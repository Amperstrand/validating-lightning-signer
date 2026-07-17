/// Direct access signer in the same process
pub mod direct;

use crate::tx_util::create_spending_transaction;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Address, Network, ScriptBuf, Transaction, Witness};
use bitcoind_client::esplora_client::EsploraClient;
use bitcoind_client::{bitcoind_client_from_url, explorer_from_url, BlockExplorerType, Explorer};
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
use std::collections::{BTreeMap, BTreeSet};
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
        dry_run: bool,
        chain_height_override: Option<u32>,
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

fn recovery_mode(dry_run: bool) -> &'static str {
    if dry_run {
        "dry-run"
    } else {
        "broadcast"
    }
}

pub async fn recover_l1<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
    max_index: u32,
    dry_run: bool,
) {
    match block_explorer_type {
        BlockExplorerType::Esplora => {}
        _ => {
            panic!("only esplora supported for l1 recovery");
        }
    };

    let url = block_explorer_rpc.expect("must have block explorer rpc");
    let esplora = EsploraClient::new(url).await;

    info!("starting l1 recovery scan: max_index={} mode={}", max_index, recovery_mode(dry_run));

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
    info!(
        "l1 recovery scan complete: scanned {} derivation indexes, found {} spendable outputs",
        max_index,
        utxos.len()
    );

    let destination_address: Address<NetworkUnchecked> =
        destination.parse().expect("destination address must be valid");
    assert!(
        destination_address.is_valid_for_network(network),
        "destination address must be valid for network"
    );

    let destination_address = destination_address.assume_checked();
    let feerate_per_kw = get_feerate(&esplora).await.expect("get feerate");

    let total_sweep_txs = (utxos.len() + 9) / 10;
    let mut prepared_sweep_txs = 0;
    for (chunk_index, chunk) in utxos.chunks(10).enumerate() {
        let tx = match make_l1_sweep(&keys, &destination_address, chunk, feerate_per_kw) {
            Some(value) => value,
            None => continue,
        };

        let txid = tx.compute_txid();
        prepared_sweep_txs += 1;
        info!(
            "l1 recovery progress: sweep tx {}/{} prepared with {} inputs: {}",
            chunk_index + 1,
            total_sweep_txs,
            chunk.len(),
            txid
        );
        if dry_run {
            info!("dry-run: would broadcast l1 sweep tx {}: {}", txid, serialize_hex(&tx));
        } else {
            esplora.broadcast_transaction(&tx).await.expect("broadcast tx");
            info!("broadcast l1 sweep tx {}", txid);
        }
    }
    info!(
        "l1 recovery complete: prepared {} sweep transactions from {} spendable outputs",
        prepared_sweep_txs,
        utxos.len()
    );
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

struct HtlcSpendStatus {
    spent_indices: Vec<bool>,
    spender_txs: Vec<Transaction>,
}

/// Checks which HTLC outputs from the commitment transaction have been spent on-chain.
/// `spent_indices` contains `true` for already-spent outputs.  When supported,
/// `spender_txs` contains the actual on-chain spending transactions for those
/// spent outputs so their delayed HTLC outputs can be swept once mature.
async fn get_htlc_spend_status(
    explorer_client: &Option<Box<dyn Explorer>>,
    commitment_tx: &CommitmentTransaction,
    lookup_spending_txs: bool,
) -> Result<HtlcSpendStatus, Status> {
    let htlcs = commitment_tx.htlcs();
    let htlc_count = htlcs.len();

    if htlc_count == 0 {
        return Ok(HtlcSpendStatus { spent_indices: Vec::new(), spender_txs: Vec::new() });
    }

    let mut spent_indices = vec![false; htlc_count];
    let mut spender_txs = Vec::new();
    let mut seen_spender_txids = BTreeSet::new();

    let Some(client) = explorer_client else {
        warn!("No block explorer available. Assuming all HTLCs are unspent.");
        return Ok(HtlcSpendStatus { spent_indices, spender_txs });
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
                    if lookup_spending_txs {
                        match client.get_utxo_spending_tx(&outpoint).await {
                            Ok(Some(spender_tx)) => {
                                let spender_txid = spender_tx.compute_txid();
                                if seen_spender_txids.insert(spender_txid) {
                                    info!(
                                        "found HTLC index {} spending transaction {}",
                                        htlc_idx, spender_txid
                                    );
                                    spender_txs.push(spender_tx);
                                }
                            }
                            Ok(None) => {
                                warn!(
                                    "HTLC index {} is spent, but no spending transaction was found",
                                    htlc_idx
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to look up spending transaction for HTLC index {}: {}",
                                    htlc_idx, e
                                );
                            }
                        }
                    } else {
                        warn!(
                            "HTLC index {} is spent, but this recovery backend cannot look up spending transactions; already-spent HTLC delayed outputs cannot be swept",
                            htlc_idx
                        );
                    }
                }
            }
            Err(e) => {
                warn!("Failed to check HTLC at vout {}: {}. Assuming unspent.", vout, e);
            }
        }
    }

    Ok(HtlcSpendStatus { spent_indices, spender_txs })
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

async fn broadcast_htlc_txs<E: Explorer + ?Sized>(
    explorer: &E,
    htlc_txs: &[Transaction],
    funding_outpoint: &OutPoint,
    dry_run: bool,
) {
    for (idx, htlc_tx) in htlc_txs.iter().enumerate() {
        let txid = htlc_tx.compute_txid();
        if dry_run {
            info!(
                "dry-run: would broadcast HTLC recovery transaction {} for channel {:?}: {}: {}",
                idx,
                funding_outpoint,
                txid,
                serialize_hex(htlc_tx)
            );
            continue;
        }
        match explorer.broadcast_transaction(htlc_tx).await {
            Ok(()) => {
                info!(
                    "broadcast HTLC recovery transaction {} for channel {:?}: {}",
                    idx, funding_outpoint, txid
                );
            }
            Err(e) => {
                error!(
                    "failed to broadcast HTLC recovery transaction {} for channel {:?} (txid {}): {}",
                    idx, funding_outpoint, txid, e
                );
            }
        }
    }
}

async fn collect_delayed_sweep_outputs<E: Explorer + ?Sized>(
    explorer: &E,
    source: &str,
    tx: &Transaction,
    delayed_script_pubkey: &ScriptBuf,
    required_confirms: u16,
    per_commitment_point: PublicKey,
    revocation_pubkey: PublicKey,
) -> Vec<DelayedPaymentOutputDescriptor> {
    let txid = tx.compute_txid();
    let mut outputs = Vec::new();

    for (idx, output) in tx.output.iter().enumerate() {
        if &output.script_pubkey != delayed_script_pubkey {
            continue;
        }

        let Ok(index) = u16::try_from(idx) else {
            warn!("{} output index {} does not fit in a recovery outpoint; skipping", source, idx);
            continue;
        };
        let outpoint = OutPoint { txid, index };
        info!("our delayed output {} @ {} in {}", output.value, idx, source);

        let confirms =
            match explorer.get_utxo_confirmations(&outpoint.into_bitcoin_outpoint()).await {
                Ok(confirms) => confirms,
                Err(e) => {
                    warn!(
                        "failed to check delayed output {} from {}: {}; skipping",
                        outpoint, source, e
                    );
                    continue;
                }
            };
        if let Some(confirms) = confirms {
            info!("delayed output from {} is unspent ({} confirms)", source, confirms);
            if confirms >= u64::from(required_confirms) {
                info!("delayed output from {} is mature, queueing sweep", source);
                outputs.push(DelayedPaymentOutputDescriptor {
                    outpoint,
                    per_commitment_point,
                    to_self_delay: required_confirms,
                    output: output.clone(),
                    revocation_pubkey: RevocationKey(revocation_pubkey),
                    channel_keys_id: [0; 32], // unused
                    channel_value_satoshis: 0,
                    channel_transaction_parameters: None,
                });
            } else {
                warn!(
                    "delayed output from {} is immature ({} < {})",
                    source, confirms, required_confirms
                );
            }
        } else {
            info!("delayed output from {} is spent, skipping", source);
        }
    }

    outputs
}

#[derive(Default)]
struct CloseRecoveryProgress {
    total_channels: usize,
    prepared_channels: usize,
    skipped_channels: usize,
    holder_close_txs: usize,
    htlc_txs: usize,
    delayed_outputs_ready: usize,
    delayed_sweep_txs: usize,
}

impl CloseRecoveryProgress {
    fn new(total_channels: usize) -> Self {
        Self { total_channels, ..Self::default() }
    }

    fn log_start(&self, dry_run: bool) {
        info!(
            "starting close recovery: channels={} mode={}",
            self.total_channels,
            recovery_mode(dry_run)
        );
    }

    fn log_channel_start(
        &self,
        channel_number: usize,
        funding_outpoint: &OutPoint,
        commitment_type: CommitmentType,
    ) {
        info!(
            "recovery progress: channel {}/{} funding {:?} commitment_type={:?}",
            channel_number, self.total_channels, funding_outpoint, commitment_type
        );
    }

    fn record_channel(
        &mut self,
        channel_number: usize,
        holder_close_txs: usize,
        htlc_txs: usize,
        delayed_outputs_ready: usize,
    ) {
        self.prepared_channels += 1;
        self.holder_close_txs += holder_close_txs;
        self.htlc_txs += htlc_txs;
        self.delayed_outputs_ready += delayed_outputs_ready;
        info!(
            "recovery progress: channel {}/{} prepared close_txs={} htlc_txs={} delayed_outputs_ready={} prepared={} skipped={}",
            channel_number,
            self.total_channels,
            holder_close_txs,
            htlc_txs,
            delayed_outputs_ready,
            self.prepared_channels,
            self.skipped_channels
        );
    }

    fn record_skip(&mut self, channel_number: usize) {
        self.skipped_channels += 1;
        info!(
            "recovery progress: channel {}/{} skipped prepared={} skipped={}",
            channel_number, self.total_channels, self.prepared_channels, self.skipped_channels
        );
    }

    fn record_delayed_sweep_tx(&mut self) {
        self.delayed_sweep_txs += 1;
    }

    fn log_complete(&self, dry_run: bool) {
        info!(
            "close recovery complete: mode={} channels={} prepared={} skipped={} close_txs={} htlc_txs={} delayed_outputs_ready={} delayed_sweep_txs={}",
            recovery_mode(dry_run),
            self.total_channels,
            self.prepared_channels,
            self.skipped_channels,
            self.holder_close_txs,
            self.htlc_txs,
            self.delayed_outputs_ready,
            self.delayed_sweep_txs
        );
    }
}

pub async fn recover_close<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
    fee_rate: Option<u32>,
    input_utxos: &[InputUtxo],
    dry_run: bool,
) {
    let can_lookup_spending_tx = matches!(block_explorer_type, BlockExplorerType::Esplora);
    let chain_height_override = if matches!(block_explorer_type, BlockExplorerType::Bitcoind) {
        if let Some(ref url) = block_explorer_rpc {
            let btc = bitcoind_client_from_url(url.clone(), network).await;
            match btc.get_blockchain_info().await {
                Ok(info) => {
                    let height = info.latest_height as u32;
                    info!("recovery chain height override: queried bitcoind tip height={}", height);
                    Some(height)
                }
                Err(e) => {
                    warn!("failed to query bitcoind chain height for recovery override: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let explorer_client = match block_explorer_rpc {
        Some(url) => Some(explorer_from_url(network, block_explorer_type, url).await),
        None => None,
    };

    recover_close_inner(
        network,
        destination,
        keys,
        fee_rate,
        input_utxos,
        explorer_client,
        can_lookup_spending_tx,
        dry_run,
        chain_height_override,
    )
    .await;
}

pub(crate) async fn recover_close_inner<R: RecoveryKeys>(
    network: Network,
    destination: &str,
    keys: R,
    fee_rate: Option<u32>,
    input_utxos: &[InputUtxo],
    explorer_client: Option<Box<dyn Explorer>>,
    can_lookup_spending_tx: bool,
    dry_run: bool,
    chain_height_override: Option<u32>,
) {
    let mut sweeps = Vec::new();
    let signers: Vec<_> = keys.iter().collect();
    let mut progress = CloseRecoveryProgress::new(signers.len());
    progress.log_start(dry_run);

    for (channel_index, signer) in signers.into_iter().enumerate() {
        let channel_number = channel_index + 1;
        let funding_outpoint = signer.funding_outpoint();
        let commitment_type = signer.commitment_type();
        progress.log_channel_start(channel_number, &funding_outpoint, commitment_type);
        let anchor_fee_rate = match commitment_type {
            CommitmentType::AnchorsZeroFeeHtlc => {
                let fee_rate = match fee_rate {
                    Some(fee_rate) => fee_rate,
                    None => {
                        error!(
                            "cannot recover AnchorsZeroFeeHtlc channel {:?}: missing --fee-rate; provide a fee rate in satoshis per kw so recovery transactions can pay fees",
                            funding_outpoint
                        );
                        progress.record_skip(channel_number);
                        continue;
                    }
                };
                if fee_rate == 0 {
                    error!(
                        "cannot recover AnchorsZeroFeeHtlc channel {:?}: --fee-rate must be greater than zero sat/kw",
                        funding_outpoint
                    );
                    progress.record_skip(channel_number);
                    continue;
                }

                if input_utxos.is_empty() {
                    error!(
                        "cannot recover AnchorsZeroFeeHtlc channel {:?}: missing --input-utxo; provide at least one wallet UTXO as txid:vout:value:derivation_path to pay recovery fees",
                        funding_outpoint
                    );
                    progress.record_skip(channel_number);
                    continue;
                }
                debug!(
                    "AnchorsZeroFeeHtlc recovery fee inputs for {:?}: fee_rate={} sat/kw input_utxos={}",
                    funding_outpoint,
                    fee_rate,
                    input_utxos.len()
                );
                Some(fee_rate)
            }
            CommitmentType::StaticRemoteKey => {
                info!(
                    "StaticRemoteKey HTLC recovery enabled for channel {:?}; second-level HTLC transactions carry their own fees",
                    funding_outpoint
                );
                None
            }
            unsupported => {
                warn!(
                    "skipping channel {:?}: recovery supports StaticRemoteKey and AnchorsZeroFeeHtlc holder force-close recovery; found unsupported commitment type {:?}",
                    funding_outpoint, unsupported
                );
                progress.record_skip(channel_number);
                continue;
            }
        };

        let current_commitment_tx = signer
            .get_current_holder_commitment_transaction()
            .expect("signer must have a current commitment tx before recovery can proceed");

        let funding_confirms = if let Some(bitcoind_client) = &explorer_client {
            bitcoind_client
                .get_utxo_confirmations(&funding_outpoint.into_bitcoin_outpoint())
                .await
                .expect("block explorer must be reachable to verify funding outpoint status")
        } else {
            None
        };

        let reconstruct_holder_htlcs = funding_confirms.is_none() && !can_lookup_spending_tx;

        let htlc_spend_status = if explorer_client.is_none()
            || funding_confirms.is_some()
            || reconstruct_holder_htlcs
        {
            if reconstruct_holder_htlcs {
                warn!(
                    "best-effort holder HTLC recovery for already-closed channel {:?}: backend cannot look up spending transactions, so reconstructing holder HTLC transactions from local signer state",
                    funding_outpoint
                );
            }
            HtlcSpendStatus {
                spent_indices: vec![false; current_commitment_tx.htlcs().len()],
                spender_txs: Vec::new(),
            }
        } else {
            get_htlc_spend_status(&explorer_client, &current_commitment_tx, can_lookup_spending_tx)
                .await
                .expect("block explorer must be reachable to check HTLC spend status")
        };

        let (tx, htlc_txs, revocable_script, uck, revocation_pubkey) = signer
            .sign_holder_commitment_tx_for_recovery(
                &htlc_spend_status.spent_indices,
                dry_run,
                chain_height_override,
            )
            .expect("sign");
        let htlc_txs = if let Some(fee_rate) = anchor_fee_rate {
            match add_fee_to_htlc_txs(&keys, htlc_txs, fee_rate, input_utxos, &funding_outpoint) {
                Ok(htlc_txs) => htlc_txs,
                Err(e) => {
                    error!(
                        "failed to add fees to HTLC recovery transactions for channel {:?}: {}",
                        funding_outpoint, e
                    );
                    Vec::new()
                }
            }
        } else {
            htlc_txs
        };
        let current_holder_commitment_htlcs = current_commitment_tx.htlcs().len();
        let htlc_txids: Vec<_> = htlc_txs.iter().map(|tx| tx.compute_txid()).collect();
        info!(
            "prepared {} HTLC recovery transaction(s) for channel {:?}; current_holder_commitment_htlcs={}; txids={:?}",
            htlc_txs.len(),
            funding_outpoint,
            current_holder_commitment_htlcs,
            htlc_txids
        );
        let txid = tx.compute_txid();
        debug!("closing tx {:?}", &tx);
        info!("closing txid {}", txid);
        if let Some(bitcoind_client) = &explorer_client {
            if let Some(confirms) = funding_confirms {
                if dry_run {
                    info!(
                        "dry-run: channel is open ({} confirms), would broadcast force-close {}: {}",
                        confirms,
                        txid,
                        serialize_hex(&tx)
                    );
                } else {
                    info!(
                        "channel is open ({} confirms), broadcasting force-close {}",
                        confirms, txid
                    );
                    bitcoind_client.broadcast_transaction(&tx).await.expect("failed to broadcast");
                }
                broadcast_htlc_txs(bitcoind_client.as_ref(), &htlc_txs, &funding_outpoint, dry_run)
                    .await;
                progress.record_channel(channel_number, 1, htlc_txs.len(), 0);
            } else {
                if anchor_fee_rate.is_some() && can_lookup_spending_tx {
                    let spending_tx = match bitcoind_client
                        .get_utxo_spending_tx(&funding_outpoint.into_bitcoin_outpoint())
                        .await
                    {
                        Ok(spending_tx) => spending_tx,
                        Err(e) => {
                            warn!(
                                "skipping channel {:?}: failed to determine who closed channel (expected closing tx {}): {}",
                                funding_outpoint, txid, e
                            );
                            progress.record_skip(channel_number);
                            continue;
                        }
                    };

                    match spending_tx {
                        Some(ref stx) => {
                            let spending_txid = stx.compute_txid();
                            if spending_txid != txid {
                                warn!(
                                    "skipping channel {:?}: closing tx was spent by counterparty (expected {}, found {}); counterparty-initiated close recovery is not supported",
                                    funding_outpoint, txid, spending_txid
                                );
                                progress.record_skip(channel_number);
                                continue;
                            }
                        }
                        None => {
                            warn!(
                                "skipping channel {:?}: funding outpoint is unavailable, but no spending transaction was found (expected closing tx {}); cannot confirm holder-initiated close recovery",
                                funding_outpoint, txid
                            );
                            progress.record_skip(channel_number);
                            continue;
                        }
                    }
                } else if reconstruct_holder_htlcs {
                    warn!(
                        "cannot determine funding outpoint spender for channel {:?}; best-effort holder recovery will only use the expected holder commitment and reconstructed holder HTLC transactions, and may miss already-broadcast anchor HTLC transactions if a later run uses different fee inputs",
                        funding_outpoint
                    );
                }
                broadcast_htlc_txs(bitcoind_client.as_ref(), &htlc_txs, &funding_outpoint, dry_run)
                    .await;
                let required_confirms = signer.counterparty_selected_contest_delay();
                info!(
                    "channel is already closed, check outputs, waiting until {} confirms",
                    required_confirms
                );

                let per_commitment_point =
                    signer.get_per_commitment_point().expect("commitment point");
                let mut sweep_outputs = collect_delayed_sweep_outputs(
                    bitcoind_client.as_ref(),
                    "commitment transaction",
                    &tx,
                    &revocable_script,
                    required_confirms,
                    per_commitment_point,
                    revocation_pubkey,
                )
                .await;

                if reconstruct_holder_htlcs {
                    for (idx, htlc_tx) in htlc_txs.iter().enumerate() {
                        let source = format!("reconstructed holder HTLC transaction {}", idx);
                        sweep_outputs.extend(
                            collect_delayed_sweep_outputs(
                                bitcoind_client.as_ref(),
                                &source,
                                htlc_tx,
                                &revocable_script,
                                required_confirms,
                                per_commitment_point,
                                revocation_pubkey,
                            )
                            .await,
                        );
                    }
                }

                for (idx, htlc_tx) in htlc_spend_status.spender_txs.iter().enumerate() {
                    let source = format!("spent HTLC transaction {}", idx);
                    sweep_outputs.extend(
                        collect_delayed_sweep_outputs(
                            bitcoind_client.as_ref(),
                            &source,
                            htlc_tx,
                            &revocable_script,
                            required_confirms,
                            per_commitment_point,
                            revocation_pubkey,
                        )
                        .await,
                    );
                }
                let delayed_outputs_ready = sweep_outputs.len();
                sweeps
                    .extend(sweep_outputs.into_iter().map(|descriptor| (descriptor, uck.clone())));
                progress.record_channel(channel_number, 0, htlc_txs.len(), delayed_outputs_ready);
            }
        } else {
            info!("tx: {}", serialize_hex(&tx));
            let htlc_tx_count = htlc_txs.len();
            for htlc_tx in htlc_txs {
                info!("HTLC tx: {}", htlc_tx.compute_txid());
            }
            progress.record_channel(channel_number, 1, htlc_tx_count, 0);
        }
    }

    if sweeps.is_empty() {
        info!("no delayed outputs ready to sweep");
        progress.log_complete(dry_run);
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
        progress.record_delayed_sweep_tx();
        if dry_run {
            info!(
                "dry-run: would broadcast delayed-output sweep tx {}: {}",
                sweep_tx.compute_txid(),
                serialize_hex(&sweep_tx)
            );
        } else if let Some(bitcoind_client) = &explorer_client {
            bitcoind_client.broadcast_transaction(&sweep_tx).await.expect("failed to broadcast");
        }
    }
    progress.log_complete(dry_run);
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
        confirmation_errors: Arc<Mutex<HashMap<bitcoin::OutPoint, String>>>,
        broadcasts: Arc<Mutex<Vec<Transaction>>>,
        spending_txs: Arc<Mutex<HashMap<bitcoin::OutPoint, Option<Transaction>>>>,
        spending_tx_errors: Arc<Mutex<HashMap<bitcoin::OutPoint, String>>>,
    }

    impl MockExplorer {
        fn set_confirms(&self, outpoint: bitcoin::OutPoint, confirms: Option<u64>) {
            self.confirms.lock().unwrap().insert(outpoint, confirms);
        }

        fn set_confirmation_error(&self, outpoint: bitcoin::OutPoint, error: &str) {
            self.confirmation_errors.lock().unwrap().insert(outpoint, error.to_string());
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
            if let Some(error) = self.confirmation_errors.lock().unwrap().get(outpoint).cloned() {
                return Err(Error::Esplora(error));
            }
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
            tx: &Transaction,
            _segwit_flags: &[bool],
            _ipaths: &Vec<DerivationPath>,
            _prev_outs: &Vec<TxOut>,
            _uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
            _opaths: &Vec<DerivationPath>,
        ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
            Ok(tx.input.iter().map(|_| Vec::new()).collect())
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

        fn with_current_commitment_tx(
            mut self,
            current_commitment_tx: CommitmentTransaction,
        ) -> Self {
            self.current_commitment_tx = current_commitment_tx;
            self
        }
    }

    impl RecoverySign for TestRecoverySigner {
        fn sign_holder_commitment_tx_for_recovery(
            &self,
            spent_htlc_indices: &[bool],
            _dry_run: bool,
            _chain_height_override: Option<u32>,
        ) -> Result<
            (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
            Status,
        > {
            self.state.lock().unwrap().spent_htlc_indices.push(spent_htlc_indices.to_vec());
            let htlc_txs = if !spent_htlc_indices.is_empty()
                && spent_htlc_indices.iter().all(|spent| *spent)
            {
                Vec::new()
            } else {
                self.htlc_txs.clone()
            };
            Ok((
                self.closing_tx.clone(),
                htlc_txs,
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

    fn destination_address() -> String {
        Address::p2wpkh(&make_test_bitcoin_pubkey(99), Network::Regtest).to_string()
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

    #[tokio::test]
    async fn get_htlc_spend_status_without_explorer_assumes_unspent() {
        let commitment_tx = make_commitment_tx(vec![make_htlc_output(1), make_htlc_output(2)]);
        let explorer_client: Option<Box<dyn Explorer>> = None;

        let status = get_htlc_spend_status(&explorer_client, &commitment_tx, false).await.unwrap();

        assert_eq!(status.spent_indices, vec![false, false]);
        assert!(status.spender_txs.is_empty());
    }

    #[tokio::test]
    async fn get_htlc_spend_status_marks_missing_outputs_spent() {
        let commitment_tx =
            make_commitment_tx(vec![make_htlc_output(1), make_htlc_output(2), make_htlc_output(3)]);
        let commitment_txid = commitment_tx.trust().built_transaction().transaction.compute_txid();
        let mock = MockExplorer::default();

        for (idx, htlc) in commitment_tx.htlcs().iter().enumerate() {
            let outpoint = bitcoin::OutPoint {
                txid: commitment_txid,
                vout: htlc.transaction_output_index.unwrap(),
            };
            mock.set_confirms(outpoint, if idx == 0 || idx == 2 { None } else { Some(1) });
        }

        let explorer_client: Option<Box<dyn Explorer>> = Some(Box::new(mock));
        let status = get_htlc_spend_status(&explorer_client, &commitment_tx, false).await.unwrap();

        assert_eq!(status.spent_indices, vec![true, false, true]);
        assert!(status.spender_txs.is_empty());
    }

    #[tokio::test]
    async fn get_htlc_spend_status_collects_and_deduplicates_spenders() {
        let commitment_tx =
            make_commitment_tx(vec![make_htlc_output(1), make_htlc_output(2), make_htlc_output(3)]);
        let commitment_txid = commitment_tx.trust().built_transaction().transaction.compute_txid();
        let mock = MockExplorer::default();
        let spender_tx = make_htlc_tx(10_000);

        for htlc in commitment_tx.htlcs() {
            let outpoint = bitcoin::OutPoint {
                txid: commitment_txid,
                vout: htlc.transaction_output_index.unwrap(),
            };
            mock.set_confirms(outpoint, None);
            mock.set_spending_tx(outpoint, Some(spender_tx.clone()));
        }

        let explorer_client: Option<Box<dyn Explorer>> = Some(Box::new(mock));
        let status = get_htlc_spend_status(&explorer_client, &commitment_tx, true).await.unwrap();

        assert_eq!(status.spent_indices, vec![true, true, true]);
        assert_eq!(status.spender_txs.len(), 1);
        assert_eq!(status.spender_txs[0].compute_txid(), spender_tx.compute_txid());
    }

    #[tokio::test]
    async fn collect_delayed_sweep_outputs_finds_htlc_tx_outputs() {
        let delayed_script = make_p2wpkh_script(9);
        let mut htlc_tx = make_htlc_tx(10_000);
        htlc_tx.output[0].script_pubkey = delayed_script.clone();

        let mock = MockExplorer::default();
        mock.set_confirms(bitcoin::OutPoint { txid: htlc_tx.compute_txid(), vout: 0 }, Some(6));

        let outputs = collect_delayed_sweep_outputs(
            &mock,
            "HTLC transaction 0",
            &htlc_tx,
            &delayed_script,
            6,
            make_test_pubkey(3),
            make_test_pubkey(2),
        )
        .await;

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].outpoint, OutPoint { txid: htlc_tx.compute_txid(), index: 0 });
        assert_eq!(outputs[0].output, htlc_tx.output[0]);
    }

    #[tokio::test]
    async fn collect_delayed_sweep_outputs_skips_failed_explorer_lookup() {
        let delayed_script = make_p2wpkh_script(9);
        let mut htlc_tx = make_htlc_tx(10_000);
        htlc_tx.output = vec![
            TxOut { value: Amount::from_sat(4_000), script_pubkey: delayed_script.clone() },
            TxOut { value: Amount::from_sat(6_000), script_pubkey: delayed_script.clone() },
        ];

        let mock = MockExplorer::default();
        let txid = htlc_tx.compute_txid();
        mock.set_confirmation_error(bitcoin::OutPoint { txid, vout: 0 }, "lookup failed");
        mock.set_confirms(bitcoin::OutPoint { txid, vout: 1 }, Some(6));

        let outputs = collect_delayed_sweep_outputs(
            &mock,
            "HTLC transaction 0",
            &htlc_tx,
            &delayed_script,
            6,
            make_test_pubkey(3),
            make_test_pubkey(2),
        )
        .await;

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].outpoint, OutPoint { txid, index: 1 });
        assert_eq!(outputs[0].output, htlc_tx.output[1]);
    }

    #[tokio::test]
    async fn recover_close_inner_open_anchor_channel_broadcasts_close_and_htlc_txs() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        );
        let keys = TestRecoveryKeys::new(vec![signer], state);
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), Some(3));

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            false,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 2);
        assert!(broadcasts[0]
            .input
            .iter()
            .any(|input| { input.previous_output == funding_bitcoin_outpoint() }));
        assert!(broadcasts[1]
            .input
            .iter()
            .any(|input| input.previous_output == input_utxos[0].outpoint));
    }

    #[tokio::test]
    async fn recover_close_inner_open_static_channel_broadcasts_close_and_htlc_txs() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::StaticRemoteKey,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        )
        .with_current_commitment_tx(make_commitment_tx(vec![
            make_htlc_output(1),
            make_htlc_output(2),
        ]));
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), Some(3));

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            None,
            &[],
            Some(Box::new(mock.clone())),
            false,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 2);
        assert!(broadcasts[0]
            .input
            .iter()
            .any(|input| { input.previous_output == funding_bitcoin_outpoint() }));
        assert_eq!(broadcasts[1].input[0].previous_output, bitcoin_outpoint(43, 0));

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![vec![false, false]]);
        assert!(state.wallet_signs.is_empty());
    }

    #[tokio::test]
    async fn recover_close_inner_closed_static_channel_reconstructs_htlc_txs_without_spender_lookup(
    ) {
        // When the channel is already closed and the recovery backend cannot look up
        // spending transactions (bitcoind mode), static channels now also reconstruct
        // HTLC-timeout transactions from signer state so their second-level delayed
        // outputs can be swept once the CSV matures.
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::StaticRemoteKey,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        )
        .with_current_commitment_tx(make_commitment_tx(vec![
            make_htlc_output(1),
            make_htlc_output(2),
        ]));
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            None,
            &[],
            Some(Box::new(mock.clone())),
            false,
            false,
            None,
        )
        .await;

        // The reconstructed HTLC-timeout transaction is broadcast (it may already be
        // confirmed from an earlier run, but we try again so we can sweep its outputs).
        assert_eq!(mock.broadcasts().len(), 1);

        let state = state.lock().unwrap();
        // HTLCs are treated as unspent for reconstruction so they get signed.
        assert_eq!(state.spent_htlc_indices, vec![vec![false, false]]);
        assert!(state.wallet_signs.is_empty());
    }

    #[tokio::test]
    async fn recover_close_inner_closed_static_sweeps_spent_htlc_spender_outputs() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let commitment_tx = make_commitment_tx(vec![make_htlc_output(1)]);
        let commitment_txid = commitment_tx.trust().built_transaction().transaction.compute_txid();
        let htlc_outpoint = bitcoin::OutPoint {
            txid: commitment_txid,
            vout: commitment_tx.htlcs()[0].transaction_output_index.unwrap(),
        };
        let mut htlc_spender_tx = make_htlc_tx(10_000);
        htlc_spender_tx.output[0].script_pubkey = ScriptBuf::new();
        let delayed_outpoint = bitcoin::OutPoint { txid: htlc_spender_tx.compute_txid(), vout: 0 };
        let signer =
            TestRecoverySigner::new(CommitmentType::StaticRemoteKey, Vec::new(), state.clone())
                .with_current_commitment_tx(commitment_tx);
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);
        mock.set_confirms(htlc_outpoint, None);
        mock.set_spending_tx(htlc_outpoint, Some(htlc_spender_tx));
        mock.set_confirms(delayed_outpoint, Some(6));

        recover_close_inner(
            Network::Regtest,
            &destination_address(),
            keys,
            None,
            &[],
            Some(Box::new(mock.clone())),
            true,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(broadcasts[0].input[0].previous_output, delayed_outpoint);

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![vec![true]]);
        assert!(state.wallet_signs.is_empty());
    }

    #[tokio::test]
    async fn recover_close_inner_closed_static_does_not_collect_new_htlc_txs() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let commitment_tx = make_commitment_tx(vec![make_htlc_output(1)]);
        let commitment_txid = commitment_tx.trust().built_transaction().transaction.compute_txid();
        let htlc_outpoint = bitcoin::OutPoint {
            txid: commitment_txid,
            vout: commitment_tx.htlcs()[0].transaction_output_index.unwrap(),
        };
        let mut new_htlc_tx = make_htlc_tx(10_000);
        new_htlc_tx.output[0].script_pubkey = ScriptBuf::new();
        let new_delayed_outpoint = bitcoin::OutPoint { txid: new_htlc_tx.compute_txid(), vout: 0 };
        let signer = TestRecoverySigner::new(
            CommitmentType::StaticRemoteKey,
            vec![new_htlc_tx.clone()],
            state.clone(),
        )
        .with_current_commitment_tx(commitment_tx);
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);
        mock.set_confirms(htlc_outpoint, Some(1));
        mock.set_confirms(new_delayed_outpoint, Some(6));

        recover_close_inner(
            Network::Regtest,
            &destination_address(),
            keys,
            None,
            &[],
            Some(Box::new(mock.clone())),
            true,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(broadcasts[0].compute_txid(), new_htlc_tx.compute_txid());

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![vec![false]]);
        assert!(state.wallet_signs.is_empty());
    }

    #[tokio::test]
    async fn recover_close_inner_already_closed_rebroadcasts_anchor_htlc_txs_for_holder_close() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        );
        let keys = TestRecoveryKeys::new(vec![signer], state);
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);
        mock.set_spending_tx(funding_bitcoin_outpoint(), Some(make_recovery_tx()));

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            true,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert!(broadcasts[0]
            .input
            .iter()
            .any(|input| input.previous_output == input_utxos[0].outpoint));
        assert!(!broadcasts[0]
            .input
            .iter()
            .any(|input| input.previous_output == funding_bitcoin_outpoint()));
    }

    #[tokio::test]
    async fn recover_close_inner_closed_anchor_best_effort_holder_htlc_fallback() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        )
        .with_current_commitment_tx(make_commitment_tx(vec![make_htlc_output(1)]));
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);

        // bitcoind-style recovery cannot identify funding/HTLC spenders, so this
        // verifies the explicit best-effort holder reconstruction fallback.
        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            false,
            false,
            None,
        )
        .await;

        let broadcasts = mock.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert!(broadcasts[0]
            .input
            .iter()
            .any(|input| input.previous_output == input_utxos[0].outpoint));

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![vec![false]]);
    }

    #[tokio::test]
    async fn recover_close_inner_closed_anchor_skips_when_spender_lookup_fails() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        );
        let keys = TestRecoveryKeys::new(vec![signer], state);
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);
        mock.set_spending_tx_error(funding_bitcoin_outpoint(), "lookup failed");

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            true,
            false,
            None,
        )
        .await;

        assert!(mock.broadcasts().is_empty());
    }

    #[tokio::test]
    async fn recover_close_inner_closed_anchor_skips_without_spending_tx() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        );
        let keys = TestRecoveryKeys::new(vec![signer], state);
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), None);

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            true,
            false,
            None,
        )
        .await;

        assert!(mock.broadcasts().is_empty());
    }

    #[tokio::test]
    async fn recover_close_skips_unsupported_or_anchor_channels_without_required_fee_inputs() {
        let cases = vec![
            (
                "unsupported commitment type",
                CommitmentType::Anchors,
                Some(1000),
                vec![make_fee_utxo(60_000)],
            ),
            (
                "missing fee rate",
                CommitmentType::AnchorsZeroFeeHtlc,
                None,
                vec![make_fee_utxo(60_000)],
            ),
            (
                "zero fee rate",
                CommitmentType::AnchorsZeroFeeHtlc,
                Some(0),
                vec![make_fee_utxo(60_000)],
            ),
            ("missing fee input", CommitmentType::AnchorsZeroFeeHtlc, Some(1000), Vec::new()),
        ];

        for (case, commitment_type, fee_rate, input_utxos) in cases {
            let state = Arc::new(Mutex::new(TestRecoveryState::default()));
            let signer = TestRecoverySigner::new(commitment_type, Vec::new(), state.clone());
            let keys = TestRecoveryKeys::new(vec![signer], state.clone());

            recover_close(
                Network::Regtest,
                BlockExplorerType::Bitcoind,
                None,
                "none",
                keys,
                fee_rate,
                &input_utxos,
                false,
            )
            .await;

            let state = state.lock().unwrap();
            assert!(state.spent_htlc_indices.is_empty(), "case: {}", case);
            assert!(state.wallet_signs.is_empty(), "case: {}", case);
        }
    }

    #[tokio::test]
    async fn recover_close_dry_run_signs_and_funds_anchor_htlc_txs_without_broadcasting() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::AnchorsZeroFeeHtlc,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        );
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());
        let input_utxos = vec![make_fee_utxo(60_000)];
        let mock = MockExplorer::default();
        mock.set_confirms(funding_bitcoin_outpoint(), Some(3));

        recover_close_inner(
            Network::Regtest,
            "none",
            keys,
            Some(1000),
            &input_utxos,
            Some(Box::new(mock.clone())),
            false,
            true,
            None,
        )
        .await;

        assert!(mock.broadcasts().is_empty());

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![Vec::<bool>::new()]);
        assert_eq!(state.wallet_signs.len(), 1);
        assert_eq!(state.wallet_signs[0].input_index, 1);
        assert_eq!(state.wallet_signs[0].input_utxo, input_utxos[0]);
        assert_eq!(state.wallet_signs[0].tx.input.len(), 2);
        assert_eq!(state.wallet_signs[0].tx.input[1].previous_output, input_utxos[0].outpoint);
    }

    #[tokio::test]
    async fn recover_close_dry_run_static_signs_without_fee_inputs() {
        let state = Arc::new(Mutex::new(TestRecoveryState::default()));
        let signer = TestRecoverySigner::new(
            CommitmentType::StaticRemoteKey,
            vec![make_htlc_tx(10_000)],
            state.clone(),
        )
        .with_current_commitment_tx(make_commitment_tx(vec![
            make_htlc_output(1),
            make_htlc_output(2),
        ]));
        let keys = TestRecoveryKeys::new(vec![signer], state.clone());

        recover_close(
            Network::Regtest,
            BlockExplorerType::Bitcoind,
            None,
            "none",
            keys,
            None,
            &[],
            true,
        )
        .await;

        let state = state.lock().unwrap();
        assert_eq!(state.spent_htlc_indices, vec![vec![false, false]]);
        assert!(state.wallet_signs.is_empty());
    }
}
