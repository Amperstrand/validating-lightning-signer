use super::{Iter, RecoveryKeys, RecoverySign};
use lightning::chain::transaction::OutPoint;
use lightning_signer::bitcoin::bip32::{ChildNumber, DerivationPath};
use lightning_signer::bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning_signer::bitcoin::{Address, Amount, ScriptBuf, Transaction, TxOut};
use lightning_signer::channel::{Channel, ChannelBase, ChannelSlot, CommitmentType, InputUtxo};
use lightning_signer::lightning;
use lightning_signer::lightning::ln::chan_utils::CommitmentTransaction;
use lightning_signer::node::Node;
use lightning_signer::prelude::{Arc, Mutex, MutexGuard};
use lightning_signer::util::status::Status;
use lightning_signer::wallet::Wallet;

/// Recovery keys for an in-process Node
pub struct DirectRecoveryKeys {
    pub node: Arc<Node>,
}

impl RecoveryKeys for DirectRecoveryKeys {
    type Signer = DirectRecoverySigner;

    fn iter(&self) -> Iter<Self::Signer> {
        let signers: Vec<_> = self
            .node
            .get_channels()
            .iter()
            .map(|(_id, channel)| Arc::clone(channel))
            .filter_map(|channel| {
                let channel1 = Arc::clone(&channel);
                let lock = channel1.lock().unwrap();
                match *lock {
                    ChannelSlot::Stub(ref c) => {
                        println!("# channel {} is a stub", c.id0);
                        None
                    }
                    ChannelSlot::Ready(_) => Some(DirectRecoverySigner { channel }),
                }
            })
            .collect();
        Iter { signers }
    }

    fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        segwit_flags: &[bool],
        ipaths: &Vec<DerivationPath>,
        prev_outs: &Vec<TxOut>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<DerivationPath>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        self.node.check_onchain_tx(tx, segwit_flags, prev_outs, &uniclosekeys, opaths)?;
        self.node.unchecked_sign_onchain_tx(tx, ipaths, prev_outs, uniclosekeys)
    }

    fn wallet_address_native(&self, index: ChildNumber) -> Result<Address, Status> {
        self.node.get_native_address(&vec![index].into())
    }

    fn wallet_address_taproot(&self, index: ChildNumber) -> Result<Address, Status> {
        self.node.get_taproot_address(&vec![index].into())
    }

    fn wallet_script_pubkey_native(&self, path: &DerivationPath) -> Result<ScriptBuf, Status> {
        Ok(self.node.get_native_address(path)?.script_pubkey())
    }

    fn sign_wallet_input_unchecked(
        &self,
        tx: &Transaction,
        input_index: usize,
        input_utxo: &InputUtxo,
    ) -> Result<Vec<Vec<u8>>, Status> {
        if input_index >= tx.input.len() {
            return Err(Status::invalid_argument(format!(
                "fee input index {} out of bounds for tx with {} inputs",
                input_index,
                tx.input.len()
            )));
        }
        if input_utxo.derivation_path.is_empty() {
            return Err(Status::invalid_argument(format!(
                "fee input {}:{} must include the native wallet child derivation path",
                input_utxo.outpoint.txid, input_utxo.outpoint.vout
            )));
        }

        let mut ipaths = vec![DerivationPath::master(); tx.input.len()];
        let mut prev_outs =
            vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() }; tx.input.len()];
        ipaths[input_index] = input_utxo.derivation_path.clone();
        prev_outs[input_index] = TxOut {
            value: input_utxo.value,
            script_pubkey: self.wallet_script_pubkey_native(&input_utxo.derivation_path)?,
        };

        let witnesses = self.node.unchecked_sign_onchain_tx(
            tx,
            &ipaths,
            &prev_outs,
            vec![None; tx.input.len()],
        )?;

        witnesses.get(input_index).cloned().ok_or_else(|| {
            Status::internal(format!(
                "missing wallet witness for fee input {} in tx with {} inputs",
                input_index,
                tx.input.len()
            ))
        })
    }
}

/// Recovery signer for an in-process Channel
pub struct DirectRecoverySigner {
    channel: Arc<Mutex<ChannelSlot>>,
}

impl RecoverySign for DirectRecoverySigner {
    fn sign_holder_commitment_tx_for_recovery(
        &self,
        spent_htlc_indices: &[bool],
        dry_run: bool,
        chain_height_override: Option<u32>,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        let mut lock = self.lock();
        if dry_run {
            Self::channel(&mut lock).sign_holder_commitment_tx_for_recovery_dry_run(
                spent_htlc_indices,
                chain_height_override,
            )
        } else {
            Self::channel(&mut lock)
                .sign_holder_commitment_tx_for_recovery(spent_htlc_indices, chain_height_override)
        }
    }

    fn funding_outpoint(&self) -> OutPoint {
        let mut lock = self.lock();
        Self::channel(&mut lock).keys.funding_outpoint().unwrap().clone()
    }

    fn counterparty_selected_contest_delay(&self) -> u16 {
        let mut lock = self.lock();
        Self::channel(&mut lock).setup.counterparty_selected_contest_delay
    }

    fn get_per_commitment_point(&self) -> Result<PublicKey, Status> {
        let mut lock = self.lock();
        let channel = Self::channel(&mut lock);
        channel.get_per_commitment_point(channel.enforcement_state.next_holder_commit_num - 1)
    }

    fn get_current_holder_commitment_transaction(&self) -> Result<CommitmentTransaction, Status> {
        let mut lock = self.lock();
        Self::channel(&mut lock).get_current_holder_commitment_transaction()
    }

    fn commitment_type(&self) -> CommitmentType {
        let mut lock = self.lock();
        Self::channel(&mut lock).setup.commitment_type
    }
}

impl DirectRecoverySigner {
    fn channel(lock: &mut ChannelSlot) -> &mut Channel {
        match *lock {
            ChannelSlot::Stub(_) => {
                panic!("already checked");
            }
            ChannelSlot::Ready(ref mut c) => c,
        }
    }

    fn lock(&self) -> MutexGuard<'_, ChannelSlot> {
        self.channel.lock().unwrap()
    }
}
