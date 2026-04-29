/// Direct access signer in the same process
pub mod direct;

use crate::tx_util::create_spending_transaction;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Address, Network, ScriptBuf, Transaction, Witness};
use bitcoind_client::esplora_client::EsploraClient;
use bitcoind_client::{explorer_from_url, BlockExplorerType, Explorer};
use lightning::chain::transaction::OutPoint;
use lightning::sign::DelayedPaymentOutputDescriptor;
use lightning_signer::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use lightning_signer::bitcoin::bip32::{ChildNumber, DerivationPath};
use lightning_signer::bitcoin::consensus::encode::serialize_hex;
use lightning_signer::bitcoin::{Amount, Sequence, TxOut, Txid};
use lightning_signer::channel::{CommitmentType, InputUtxo};
use lightning_signer::lightning::ln::chan_utils::CommitmentTransaction;
use lightning_signer::lightning::ln::channel_keys::RevocationKey;
use lightning_signer::node::{Allowable, ToStringForNetwork};
use lightning_signer::util::status::Status;
use lightning_signer::util::transaction_utils::maybe_add_change_output;
use lightning_signer::{bitcoin, lightning};
use log::*;
use std::collections::BTreeMap;
use url::Url;

/// Iterator
pub struct Iter<T: RecoverySign> {
    signers: Vec<T>,
}

impl<T: RecoverySign> Iterator for Iter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.signers.pop()
    }
}

#[derive(serde::Deserialize, Debug, Clone)]
struct UtxoResponse {
    txid: Txid,
    vout: u32,
    value: u64,
}

/// Provide enough signer functionality to force-close all channels in a node
pub trait RecoveryKeys {
    type Signer: RecoverySign;
    fn iter(&self) -> Iter<Self::Signer>;
    fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        segwit_flags: &[bool],
        ipaths: &Vec<DerivationPath>,
        prev_outs: &Vec<TxOut>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<DerivationPath>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status>;
    fn wallet_address_native(&self, index: ChildNumber) -> Result<Address, Status>;
    fn wallet_address_taproot(&self, index: ChildNumber) -> Result<Address, Status>;
    fn wallet_script_pubkey_native(&self, path: &DerivationPath) -> Result<ScriptBuf, Status>;
    fn sign_wallet_input_unchecked(
        &self,
        tx: &Transaction,
        input_index: usize,
        input_utxo: &InputUtxo,
    ) -> Result<Vec<Vec<u8>>, Status>;
}

/// Provide enough signer functionality to force-close a channel
pub trait RecoverySign {
    fn sign_holder_commitment_tx_for_recovery(
        &self,
        spent_htlc_indices: &[bool],
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    >;
    fn funding_outpoint(&self) -> OutPoint;
    fn counterparty_selected_contest_delay(&self) -> u16;
    fn get_per_commitment_point(&self) -> Result<PublicKey, Status>;
    fn get_current_holder_commitment_transaction(&self) -> Result<CommitmentTransaction, Status>;
    fn commitment_type(&self) -> CommitmentType;
}

pub async fn recover_l1<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
    max_index: u32,
) {
    match block_explorer_type {
        BlockExplorerType::Esplora => {}
        _ => {
            panic!("only esplora supported for l1 recovery");
        }
    };

    let url = block_explorer_rpc.expect("must have block explorer rpc");
    let esplora = EsploraClient::new(url).await;

    let mut utxos = Vec::new();
    for index in 0..max_index {
        // TODO(king-11): add support for LDK L1 recovery by allowing random paths
        let index = ChildNumber::from(index);
        let address = keys.wallet_address_native(index).expect("address");
        let script_pubkey = address.script_pubkey();
        utxos.append(
            &mut get_utxos(&esplora, address)
                .await
                .expect("get utxos")
                .into_iter()
                .map(|u| (index, u, script_pubkey.clone()))
                .collect::<Vec<_>>(),
        );

        let taproot_address = keys.wallet_address_taproot(index).expect("address");
        let taproot_script_pubkey = taproot_address.script_pubkey();
        utxos.append(
            &mut get_utxos(&esplora, taproot_address)
                .await
                .expect("get utxos")
                .into_iter()
                .map(|u| (index, u, taproot_script_pubkey.clone()))
                .collect::<Vec<_>>(),
        );
    }

    if destination == "none" {
        info!("no destination specified, only printing txs");
    }

    let destination_address: Address<NetworkUnchecked> =
        destination.parse().expect("destination address must be valid");
    assert!(
        destination_address.is_valid_for_network(network),
        "destination address must be valid for network"
    );

    let destination_address = destination_address.assume_checked();
    let feerate_per_kw = get_feerate(&esplora).await.expect("get feerate");

    for chunk in utxos.chunks(10) {
        let tx = match make_l1_sweep(&keys, &destination_address, chunk, feerate_per_kw) {
            Some(value) => value,
            None => continue,
        };

        esplora.broadcast_transaction(&tx).await.expect("broadcast tx");
    }
}

// chunk is a list of (derivation-index, utxo)
fn make_l1_sweep<R: RecoveryKeys>(
    keys: &R,
    destination_address: &Address<NetworkChecked>,
    chunk: &[(ChildNumber, UtxoResponse, ScriptBuf)],
    feerate_per_kw: u64,
) -> Option<Transaction> {
    let value = chunk.iter().map(|(_, u, _)| u.value).sum::<u64>();

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: chunk
            .iter()
            .map(|(_, u, _)| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint { txid: u.txid, vout: u.vout },
                sequence: Sequence::ZERO,
                witness: Witness::default(),
                script_sig: ScriptBuf::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: destination_address.script_pubkey(),
        }],
    };
    let total_fee = feerate_per_kw * tx.weight().to_wu() / 1000;
    if total_fee > value - 1000 {
        warn!("not enough value to pay fee {:?}", tx);
        return None;
    }
    tx.output[0].value -= Amount::from_sat(total_fee);
    info!("sending tx {} - {}", tx.compute_txid().to_string(), serialize_hex(&tx));

    let ipaths = chunk.iter().map(|(i, _, _)| vec![*i].into()).collect::<Vec<_>>();
    let prev_outs = chunk
        .iter()
        .map(|(_, u, script_pubkey)| TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: script_pubkey.clone(),
        })
        .collect::<Vec<_>>();
    let unicosekeys = chunk.iter().map(|_| None).collect::<Vec<_>>();

    // sign transaction
    let witnesses = keys
        .sign_onchain_tx(&tx, &vec![], &ipaths, &prev_outs, unicosekeys, &vec![vec![].into()])
        .expect("sign tx");

    for (i, witness) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = Witness::from_slice(&witness);
    }
    Some(tx)
}

// get the utxos for an address
async fn get_utxos(esplora: &EsploraClient, address: Address) -> Result<Vec<UtxoResponse>, ()> {
    let utxos: Vec<UtxoResponse> =
        esplora.get(&format!("address/{}/utxo", address)).await.map_err(|e| {
            error!("{}", e);
        })?;
    Ok(utxos)
}

// get the 24-block (4 hour) feerate
async fn get_feerate(esplora: &EsploraClient) -> Result<u64, ()> {
    let fees: BTreeMap<String, f64> = esplora.get("fee-estimates").await.map_err(|e| {
        error!("{}", e);
    })?;
    let feerate = (fees.get("24").expect("feerate") * 1000f64).ceil() as u64;
    Ok(feerate)
}

/// Checks which HTLC outputs from the commitment transaction have been spent on-chain.
/// Returns a vector of booleans where `true` means the output is already spent.
async fn get_spent_htlc_indices(
    explorer_client: &Option<Box<dyn Explorer>>,
    commitment_tx: &CommitmentTransaction,
) -> Result<Vec<bool>, Status> {
    let htlcs = commitment_tx.htlcs();
    let htlc_count = htlcs.len();

    if htlc_count == 0 {
        return Ok(Vec::new());
    }

    let mut spent_indices = vec![false; htlc_count];

    let Some(client) = explorer_client else {
        warn!("No block explorer available. Assuming all HTLCs are unspent.");
        return Ok(spent_indices);
    };

    let commitment_txid = commitment_tx.trust().built_transaction().transaction.compute_txid();

    for (htlc_idx, htlc_output) in htlcs.iter().enumerate() {
        let Some(vout) = htlc_output.transaction_output_index else {
            continue;
        };

        let outpoint = bitcoin::OutPoint { txid: commitment_txid, vout };

        match client.get_utxo_confirmations(&outpoint).await {
            Ok(confirmations) => {
                if confirmations.is_none() {
                    // We only probe HTLC outputs after the funding outpoint is no longer live,
                    // so a missing HTLC UTXO here is treated as already spent/missing on-chain.
                    spent_indices[htlc_idx] = true;
                    info!("HTLC index {} (vout {}) is already spent/missing", htlc_idx, vout);
                }
            }
            Err(e) => {
                warn!("Failed to check HTLC at vout {}: {}. Assuming unspent.", vout, e);
            }
        }
    }

    Ok(spent_indices)
}

/// Constant for the combined size of a witness component in bytes.
/// Per BIP141/BIP144, a P2WPKH witness field is serialized as:
/// - 1 byte  : var_int item count (0x02, two items: sig + pubkey)
/// - 1 byte  : var_int signature length (0x49 = 73)
/// - 73 bytes: DER-encoded signature (max size)
/// - 1 byte  : var_int pubkey length (0x21 = 33)
/// - 33 bytes: compressed public key
/// Total: 1 + 1 + 73 + 1 + 33 = 109 bytes per input witness.
const P2WPKH_INPUT_WITNESS_SIZE: u64 = 1 + 1 + 73 + 1 + 33;

fn add_fee_to_htlc_txs<R: RecoveryKeys>(
    keys: &R,
    htlc_txs: Vec<Transaction>,
    fee_rate: u32,
    input_utxos: &[InputUtxo],
    funding_outpoint: &OutPoint,
) -> Result<Vec<Transaction>, Status> {
    if htlc_txs.is_empty() {
        return Ok(htlc_txs);
    }

    let mut result = Vec::with_capacity(htlc_txs.len());
    let mut provided_utxos = input_utxos.iter().cloned();
    let mut current_fee_utxo = provided_utxos.next();

    for (idx, htlc_tx) in htlc_txs.into_iter().enumerate() {
        let mut next_fee_utxo = current_fee_utxo.take().or_else(|| provided_utxos.next());
        let mut last_error = None;

        loop {
            let Some(fee_utxo) = next_fee_utxo else {
                let last_error =
                    last_error.map(|e| format!("; last fee UTXO error: {}", e)).unwrap_or_default();
                return Err(Status::invalid_argument(format!(
                    "cannot add fees to HTLC recovery transaction {} for channel {:?}: no usable fee UTXO available{}",
                    idx, funding_outpoint, last_error
                )));
            };

            let fee_outpoint = fee_utxo.outpoint;
            match add_fee_to_htlc_tx(
                keys,
                htlc_tx.clone(),
                &fee_utxo,
                fee_rate,
                funding_outpoint,
                idx,
            ) {
                Ok((funded_tx, change_utxo)) => {
                    info!(
                        "added fee input {}:{} to HTLC recovery transaction {} for channel {:?}",
                        fee_outpoint.txid, fee_outpoint.vout, idx, funding_outpoint
                    );
                    current_fee_utxo = change_utxo;
                    result.push(funded_tx);
                    break;
                }
                Err(e) => {
                    warn!(
                        "skipping fee UTXO {}:{} for HTLC recovery transaction {} on channel {:?}: {}",
                        fee_outpoint.txid, fee_outpoint.vout, idx, funding_outpoint, e
                    );
                    last_error = Some(e.to_string());
                    next_fee_utxo = provided_utxos.next();
                }
            }
        }
    }

    Ok(result)
}

fn add_fee_to_htlc_tx<R: RecoveryKeys>(
    keys: &R,
    mut tx: Transaction,
    fee_utxo: &InputUtxo,
    fee_rate: u32,
    funding_outpoint: &OutPoint,
    htlc_tx_index: usize,
) -> Result<(Transaction, Option<InputUtxo>), Status> {
    let fee_input_index = tx.input.len();
    tx.input.push(bitcoin::TxIn {
        previous_output: fee_utxo.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    });

    let htlc_output_value = tx.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat()).ok_or_else(|| {
            Status::internal(format!(
                "HTLC recovery transaction {} for channel {:?} output value overflow",
                htlc_tx_index, funding_outpoint
            ))
        })
    })?;
    let input_value = htlc_output_value.checked_add(fee_utxo.value.to_sat()).ok_or_else(|| {
        Status::internal(format!(
            "HTLC recovery transaction {} for channel {:?} input value overflow",
            htlc_tx_index, funding_outpoint
        ))
    })?;

    let change_script = keys.wallet_script_pubkey_native(&fee_utxo.derivation_path)?;
    let outputs_before_change = tx.output.len();
    maybe_add_change_output(
        &mut tx,
        input_value,
        P2WPKH_INPUT_WITNESS_SIZE,
        fee_rate,
        change_script,
    )
    .map_err(|_| {
        Status::invalid_argument(format!(
            "fee UTXO {}:{} value {} sat cannot pay fee rate {} sat/kw for HTLC recovery transaction {} on channel {:?}",
            fee_utxo.outpoint.txid,
            fee_utxo.outpoint.vout,
            fee_utxo.value.to_sat(),
            fee_rate,
            htlc_tx_index,
            funding_outpoint
        ))
    })?;

    let change_utxo = if tx.output.len() > outputs_before_change {
        let change_vout = (tx.output.len() - 1) as u32;
        Some(InputUtxo {
            outpoint: bitcoin::OutPoint { txid: tx.compute_txid(), vout: change_vout },
            value: tx.output[change_vout as usize].value,
            derivation_path: fee_utxo.derivation_path.clone(),
        })
    } else {
        None
    };

    let fee_witness = keys.sign_wallet_input_unchecked(&tx, fee_input_index, fee_utxo)?;
    if fee_witness.is_empty() {
        return Err(Status::internal(format!(
            "signer returned empty wallet witness for fee input {} on HTLC recovery transaction {} for channel {:?}",
            fee_input_index, htlc_tx_index, funding_outpoint
        )));
    }
    tx.input[fee_input_index].witness = Witness::from_slice(&fee_witness);

    Ok((tx, change_utxo))
}

pub async fn recover_close<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
    fee_rate: u32,
    input_utxos: &[InputUtxo],
) {
    let explorer_client = match block_explorer_rpc {
        Some(url) => Some(explorer_from_url(network, block_explorer_type, url).await),
        None => None,
    };

    recover_close_inner(network, destination, keys, fee_rate, input_utxos, explorer_client).await;
}

pub(crate) async fn recover_close_inner<R: RecoveryKeys>(
    network: Network,
    destination: &str,
    keys: R,
    _fee_rate: u32,
    _input_utxos: &[InputUtxo],
    explorer_client: Option<Box<dyn Explorer>>,
) {
    let mut sweeps = Vec::new();

    for signer in keys.iter() {
        info!("# funding {:?}", signer.funding_outpoint());

        let current_commitment_tx = signer
            .get_current_holder_commitment_transaction()
            .expect("signer must have a current commitment tx before recovery can proceed");

        let funding_confirms = if let Some(bitcoind_client) = &explorer_client {
            bitcoind_client
                .get_utxo_confirmations(&signer.funding_outpoint().into_bitcoin_outpoint())
                .await
                .expect("block explorer must be reachable to verify funding outpoint status")
        } else {
            None
        };

        let spent_htlc_indices = if explorer_client.is_none() || funding_confirms.is_some() {
            vec![false; current_commitment_tx.htlcs().len()]
        } else {
            get_spent_htlc_indices(&explorer_client, &current_commitment_tx)
                .await
                .expect("block explorer must be reachable to check HTLC spend status")
        };

        let (tx, htlc_txs, revocable_script, uck, revocation_pubkey) =
            signer.sign_holder_commitment_tx_for_recovery(&spent_htlc_indices).expect("sign");
        let txid = tx.compute_txid();
        debug!("closing tx {:?}", &tx);
        info!("closing txid {}", txid);
        if let Some(bitcoind_client) = &explorer_client {
            if let Some(confirms) = funding_confirms {
                info!("channel is open ({} confirms), broadcasting force-close {}", confirms, txid);
                bitcoind_client.broadcast_transaction(&tx).await.expect("failed to broadcast");
            } else {
                let required_confirms = signer.counterparty_selected_contest_delay();
                info!(
                    "channel is already closed, check outputs, waiting until {} confirms",
                    required_confirms
                );

                for (idx, out) in tx.output.iter().enumerate() {
                    let script = out.script_pubkey.clone();
                    if script == revocable_script {
                        info!("our revocable output {} @ {}", out.value, idx);
                        let out_point = OutPoint { txid, index: idx as u16 };
                        let confirms = bitcoind_client
                            .get_utxo_confirmations(&out_point.into_bitcoin_outpoint())
                            .await
                            .expect("get_txout for our output");
                        if let Some(confirms) = confirms {
                            info!("revocable output is unspent ({} confirms)", confirms);
                            if confirms >= required_confirms as u64 {
                                info!("revocable output is mature, broadcasting sweep");
                                let to_self_delay = signer.counterparty_selected_contest_delay();
                                let descriptor = DelayedPaymentOutputDescriptor {
                                    outpoint: out_point,
                                    per_commitment_point: signer
                                        .get_per_commitment_point()
                                        .expect("commitment point"),
                                    to_self_delay,
                                    output: tx.output[idx].clone(),
                                    revocation_pubkey: RevocationKey(revocation_pubkey),
                                    channel_keys_id: [0; 32], // unused
                                    channel_value_satoshis: 0,
                                    channel_transaction_parameters: None,
                                };
                                sweeps.push((descriptor, uck.clone()));
                            } else {
                                warn!(
                                    "revocable output is immature ({} < {})",
                                    confirms, required_confirms
                                );
                            }
                        } else {
                            info!("revocable output is spent, skipping");
                        }
                    }
                }
            }
        } else {
            info!("tx: {}", serialize_hex(&tx));
            for htlc_tx in htlc_txs {
                info!("HTLC tx: {}", htlc_tx.compute_txid());
            }
        }
    }

    if destination == "none" {
        info!("no address specified, not sweeping");
        return;
    }

    let wallet_path: DerivationPath = DerivationPath::master();
    let destination_allowable = Allowable::from_str(destination, network).expect("address");
    info!("sweeping to {}", destination_allowable.to_string(network));
    let output_script = destination_allowable.to_script().expect("script");
    for (descriptor, uck) in sweeps {
        let feerate = 1000;
        let sweep_tx = spend_delayed_outputs(
            &keys,
            &[descriptor],
            uck,
            output_script.clone(),
            wallet_path.clone(),
            feerate,
        );
        debug!("sweep tx {:?}", &sweep_tx);
        info!("sweep txid {}", sweep_tx.compute_txid());
        if let Some(bitcoind_client) = &explorer_client {
            bitcoind_client.broadcast_transaction(&sweep_tx).await.expect("failed to broadcast");
        }
    }
}

fn spend_delayed_outputs<R: RecoveryKeys>(
    keys: &R,
    descriptors: &[DelayedPaymentOutputDescriptor],
    unilateral_close_key: (SecretKey, Vec<Vec<u8>>),
    output_script: ScriptBuf,
    opath: DerivationPath,
    feerate_sat_per_1000_weight: u32,
) -> Transaction {
    let mut tx =
        create_spending_transaction(descriptors, output_script, feerate_sat_per_1000_weight)
            .expect("create_spending_transaction");
    let values_sat = descriptors.iter().map(|d| d.output.clone()).collect();
    let ipaths = descriptors.iter().map(|_| vec![].into()).collect();
    let uniclosekeys = descriptors.iter().map(|_| Some(unilateral_close_key.clone())).collect();
    let input_txs = vec![]; // only need input txs for funding tx
    let witnesses = keys
        .sign_onchain_tx(&tx, &input_txs, &ipaths, &values_sat, uniclosekeys, &vec![opath])
        .expect("sign");
    assert_eq!(witnesses.len(), tx.input.len());
    for (idx, w) in witnesses.into_iter().enumerate() {
        tx.input[idx].witness = Witness::from_slice(&w);
    }
    tx
}

#[cfg(test)]
mod tests {
    use super::direct::DirectRecoveryKeys;
    use super::*;
    use async_trait::async_trait;
    use bitcoind_client::Error;
    use lightning_signer::bitcoin::hashes::Hash;
    use lightning_signer::channel::Channel;
    use lightning_signer::lightning::ln::chan_utils::{
        ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
        HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning_signer::lightning::ln::channel_keys::{DelayedPaymentKey, HtlcKey};
    use lightning_signer::lightning::types::payment::PaymentHash;
    use lightning_signer::node::SpendType;
    use lightning_signer::tx::tx::HTLCInfo2;
    use lightning_signer::util::test_utils::key::{
        make_test_bitcoin_pubkey, make_test_counterparty_points, make_test_privkey,
        make_test_pubkey,
    };
    use lightning_signer::util::test_utils::{
        init_node, make_test_channel_setup_with_points, make_test_previous_tx, TEST_NODE_CONFIG,
        TEST_SEED,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};
    use vls_protocol::serde_bolt::bitcoin::CompressedPublicKey;

    #[derive(Default)]
    struct TestRecoveryState {
        spent_htlc_indices: Vec<Vec<bool>>,
        wallet_signs: Vec<WalletSignCall>,
    }

    struct WalletSignCall {
        tx: Transaction,
        input_index: usize,
        input_utxo: InputUtxo,
    }

    #[derive(Clone, Default)]
    struct MockExplorer {
        confirms: Arc<Mutex<HashMap<bitcoin::OutPoint, Option<u64>>>>,
        broadcasts: Arc<Mutex<Vec<Transaction>>>,
        spending_txs: Arc<Mutex<HashMap<bitcoin::OutPoint, Option<Transaction>>>>,
        spending_tx_errors: Arc<Mutex<HashMap<bitcoin::OutPoint, String>>>,
    }

    impl MockExplorer {
        fn set_confirms(&self, outpoint: bitcoin::OutPoint, confirms: Option<u64>) {
            self.confirms.lock().unwrap().insert(outpoint, confirms);
        }

        fn set_spending_tx(&self, outpoint: bitcoin::OutPoint, tx: Option<Transaction>) {
            self.spending_txs.lock().unwrap().insert(outpoint, tx);
        }

        fn broadcasts(&self) -> Vec<Transaction> {
            self.broadcasts.lock().unwrap().clone()
        }

        fn set_spending_tx_error(&self, outpoint: bitcoin::OutPoint, error: &str) {
            self.spending_tx_errors.lock().unwrap().insert(outpoint, error.to_string());
        }
    }

    #[async_trait]
    impl Explorer for MockExplorer {
        async fn get_utxo_confirmations(
            &self,
            outpoint: &bitcoin::OutPoint,
        ) -> Result<Option<u64>, Error> {
            Ok(self.confirms.lock().unwrap().get(outpoint).cloned().unwrap_or(None))
        }

        async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), Error> {
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(())
        }

        async fn get_utxo_spending_tx(
            &self,
            outpoint: &bitcoin::OutPoint,
        ) -> Result<Option<Transaction>, Error> {
            if let Some(error) = self.spending_tx_errors.lock().unwrap().get(outpoint).cloned() {
                return Err(Error::Esplora(error));
            }
            Ok(self.spending_txs.lock().unwrap().get(outpoint).cloned().unwrap_or(None))
        }
    }

    #[derive(Clone)]
    struct TestRecoveryKeys {
        signers: Vec<TestRecoverySigner>,
        state: Arc<Mutex<TestRecoveryState>>,
        wallet_script: ScriptBuf,
        wallet_witness: Vec<Vec<u8>>,
    }

    impl TestRecoveryKeys {
        fn new(signers: Vec<TestRecoverySigner>, state: Arc<Mutex<TestRecoveryState>>) -> Self {
            Self {
                signers,
                state,
                wallet_script: make_p2wpkh_script(21),
                wallet_witness: vec![vec![0x30, 0x01], vec![0x02, 0x03]],
            }
        }
    }

    impl RecoveryKeys for TestRecoveryKeys {
        type Signer = TestRecoverySigner;

        fn iter(&self) -> Iter<Self::Signer> {
            Iter { signers: self.signers.clone() }
        }

        fn sign_onchain_tx(
            &self,
            _tx: &Transaction,
            _segwit_flags: &[bool],
            _ipaths: &Vec<DerivationPath>,
            _prev_outs: &Vec<TxOut>,
            _uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
            _opaths: &Vec<DerivationPath>,
        ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
            panic!("not used by recover_close dry-run tests")
        }

        fn wallet_address_native(&self, _index: ChildNumber) -> Result<Address, Status> {
            panic!("not used by recover_close tests")
        }

        fn wallet_address_taproot(&self, _index: ChildNumber) -> Result<Address, Status> {
            panic!("not used by recover_close tests")
        }

        fn wallet_script_pubkey_native(&self, _path: &DerivationPath) -> Result<ScriptBuf, Status> {
            Ok(self.wallet_script.clone())
        }

        fn sign_wallet_input_unchecked(
            &self,
            tx: &Transaction,
            input_index: usize,
            input_utxo: &InputUtxo,
        ) -> Result<Vec<Vec<u8>>, Status> {
            self.state.lock().unwrap().wallet_signs.push(WalletSignCall {
                tx: tx.clone(),
                input_index,
                input_utxo: input_utxo.clone(),
            });
            Ok(self.wallet_witness.clone())
        }
    }

    #[derive(Clone)]
    struct TestRecoverySigner {
        funding_outpoint: OutPoint,
        commitment_type: CommitmentType,
        current_commitment_tx: CommitmentTransaction,
        closing_tx: Transaction,
        htlc_txs: Vec<Transaction>,
        state: Arc<Mutex<TestRecoveryState>>,
    }

    impl TestRecoverySigner {
        fn new(
            commitment_type: CommitmentType,
            htlc_txs: Vec<Transaction>,
            state: Arc<Mutex<TestRecoveryState>>,
        ) -> Self {
            Self {
                funding_outpoint: funding_outpoint(),
                commitment_type,
                current_commitment_tx: make_empty_commitment_tx(),
                closing_tx: make_recovery_tx(),
                htlc_txs,
                state,
            }
        }
    }

    impl RecoverySign for TestRecoverySigner {
        fn sign_holder_commitment_tx_for_recovery(
            &self,
            spent_htlc_indices: &[bool],
        ) -> Result<
            (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
            Status,
        > {
            self.state.lock().unwrap().spent_htlc_indices.push(spent_htlc_indices.to_vec());
            Ok((
                self.closing_tx.clone(),
                self.htlc_txs.clone(),
                ScriptBuf::new(),
                (make_test_privkey(1), Vec::new()),
                make_test_pubkey(2),
            ))
        }

        fn funding_outpoint(&self) -> OutPoint {
            self.funding_outpoint
        }

        fn counterparty_selected_contest_delay(&self) -> u16 {
            6
        }

        fn get_per_commitment_point(&self) -> Result<PublicKey, Status> {
            Ok(make_test_pubkey(3))
        }

        fn get_current_holder_commitment_transaction(
            &self,
        ) -> Result<CommitmentTransaction, Status> {
            Ok(self.current_commitment_tx.clone())
        }

        fn commitment_type(&self) -> CommitmentType {
            self.commitment_type
        }
    }

    fn txid(byte: u8) -> Txid {
        Txid::from_slice(&[byte; 32]).unwrap()
    }

    fn funding_outpoint() -> OutPoint {
        OutPoint { txid: txid(42), index: 0 }
    }

    fn funding_bitcoin_outpoint() -> bitcoin::OutPoint {
        funding_outpoint().into_bitcoin_outpoint()
    }

    fn bitcoin_outpoint(byte: u8, vout: u32) -> bitcoin::OutPoint {
        bitcoin::OutPoint { txid: txid(byte), vout }
    }

    fn make_p2wpkh_script(byte: u8) -> ScriptBuf {
        Address::p2wpkh(&make_test_bitcoin_pubkey(byte), Network::Regtest).script_pubkey()
    }

    fn make_recovery_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin_outpoint(42, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: make_p2wpkh_script(1),
            }],
        }
    }

    fn make_htlc_tx(value_sat: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin_outpoint(43, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: make_p2wpkh_script(2),
            }],
        }
    }

    fn make_fee_utxo(value_sat: u64) -> InputUtxo {
        InputUtxo {
            outpoint: bitcoin_outpoint(44, 1),
            value: Amount::from_sat(value_sat),
            derivation_path: vec![ChildNumber::from_normal_idx(7).unwrap()].into(),
        }
    }

    fn make_htlc_output(byte: u8) -> HTLCOutputInCommitment {
        let htlc = HTLCInfo2 {
            value_sat: 700 + u64::from(byte) * 100,
            cltv_expiry: 100 + u32::from(byte),
            payment_hash: PaymentHash([byte; 32]),
        };

        let (offered, received) =
            if byte % 2 == 0 { (vec![htlc], Vec::new()) } else { (Vec::new(), vec![htlc]) };
        Channel::htlcs_info2_to_oic(&offered, &received).remove(0)
    }

    fn make_empty_commitment_tx() -> CommitmentTransaction {
        make_commitment_tx(Vec::new())
    }

    fn make_commitment_tx(htlcs: Vec<HTLCOutputInCommitment>) -> CommitmentTransaction {
        let holder_pubkeys = make_test_counterparty_points();
        let mut setup = make_test_channel_setup_with_points(true, make_test_counterparty_points());
        setup.funding_outpoint = funding_bitcoin_outpoint();

        let channel_parameters = ChannelTransactionParameters {
            holder_pubkeys: holder_pubkeys.clone(),
            holder_selected_contest_delay: setup.holder_selected_contest_delay,
            is_outbound_from_holder: setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: setup.counterparty_points.clone(),
                selected_contest_delay: setup.counterparty_selected_contest_delay,
            }),
            funding_outpoint: Some(funding_outpoint()),
            channel_type_features: setup.features(),
        };
        let mut htlcs = htlcs.into_iter().map(|h| (h, ())).collect();
        let keys = TxCreationKeys {
            per_commitment_point: make_test_pubkey(10),
            revocation_key: RevocationKey(make_test_pubkey(11)),
            broadcaster_htlc_key: HtlcKey(make_test_pubkey(12)),
            countersignatory_htlc_key: HtlcKey(make_test_pubkey(13)),
            broadcaster_delayed_payment_key: DelayedPaymentKey(make_test_pubkey(14)),
        };

        CommitmentTransaction::new_with_auxiliary_htlc_data(
            0,
            20_000,
            0,
            holder_pubkeys.funding_pubkey,
            setup.counterparty_points.funding_pubkey,
            keys,
            0,
            &mut htlcs,
            &channel_parameters.as_holder_broadcastable(),
        )
        .with_non_zero_fee_anchors()
    }

    #[ignore]
    #[tokio::test]
    async fn esplora_utxo_test() {
        fern::Dispatch::new().level(LevelFilter::Info).chain(std::io::stdout()).apply().unwrap();
        let address: Address<NetworkUnchecked> =
            "19XBuBAa78zccvfFrNWKB6PhnA1mMRASeT".parse().unwrap();
        let address = address.assume_checked();
        let esplora = EsploraClient::new("https://blockstream.info/api".parse().unwrap()).await;

        let fees: BTreeMap<String, f64> =
            esplora.get("fee-estimates").await.expect("fee_estimates");
        info!("fees: {:?}", fees);

        let utxos = get_utxos(&esplora, address.clone()).await.expect("get_utxos");
        info!("address {} has {:?}", address, utxos);
    }

    #[test]
    fn l1_sweep_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let pubkey = CompressedPublicKey(make_test_pubkey(2));
        let address = Address::p2wpkh(&pubkey, Network::Testnet);

        node.add_allowlist(&[address.to_string()]).expect("add_allowlist");

        let values = vec![(123, 12345u64, SpendType::P2wpkh)];
        let (input_tx, input_txid) = make_test_previous_tx(&node, &values);
        let utxo = UtxoResponse { txid: input_txid, vout: 0, value: 12345 };

        let keys = DirectRecoveryKeys { node };
        let tx = make_l1_sweep(
            &keys,
            &address,
            &[(
                ChildNumber::from_normal_idx(123).unwrap(),
                utxo,
                input_tx.output[0].script_pubkey.clone(),
            )],
            1000,
        )
        .expect("make_l1_sweep");
        tx.verify(|txo| {
            if txo.txid == input_txid && txo.vout == 0 {
                Some(input_tx.output[0].clone())
            } else {
                None
            }
        })
        .expect("verify");

        // won't verify if we change the input amount
        let utxo = UtxoResponse { txid: input_txid, vout: 0, value: 12346 };
        let tx = make_l1_sweep(
            &keys,
            &address,
            &[(
                ChildNumber::from_normal_idx(123).unwrap(),
                utxo,
                input_tx.output[0].script_pubkey.clone(),
            )],
            1000,
        )
        .expect("make_l1_sweep");
        tx.verify(|txo| {
            if txo.txid == input_txid && txo.vout == 0 {
                Some(input_tx.output[0].clone())
            } else {
                None
            }
        })
        .expect_err("verify");
    }

    #[test]
    fn add_fee_to_htlc_txs_adds_fee_input_change_and_witness() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let keys = TestRecoveryKeys::new(Vec::new(), state.clone());
        let input_utxo = make_fee_utxo(60_000);

        let txs = add_fee_to_htlc_txs(
            &keys,
            vec![make_htlc_tx(10_000)],
            1000,
            &[input_utxo.clone()],
            &funding_outpoint(),
        )
        .expect("funded htlc tx");

        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].input.len(), 2);
        assert_eq!(txs[0].input[1].previous_output, input_utxo.outpoint);
        assert_eq!(txs[0].input[1].witness.len(), 2);
        assert_eq!(txs[0].output.len(), 2);
        assert_eq!(txs[0].output[1].script_pubkey, keys.wallet_script);

        let state = state.lock().unwrap();
        assert_eq!(state.wallet_signs.len(), 1);
        assert_eq!(state.wallet_signs[0].input_index, 1);
        assert_eq!(state.wallet_signs[0].input_utxo, input_utxo);
        assert_eq!(state.wallet_signs[0].tx.input[1].previous_output, input_utxo.outpoint);
    }

    #[test]
    fn add_fee_to_htlc_txs_errors_when_fee_utxo_cannot_pay_fee() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let keys = TestRecoveryKeys::new(Vec::new(), state.clone());

        let err = add_fee_to_htlc_txs(
            &keys,
            vec![make_htlc_tx(10_000)],
            1000,
            &[make_fee_utxo(100)],
            &funding_outpoint(),
        )
        .expect_err("fee utxo is too small");

        assert!(err.message().contains("no usable fee UTXO available"));
        assert!(err.message().contains("cannot pay fee rate 1000"));
        assert!(state.lock().unwrap().wallet_signs.is_empty());
    }
}
