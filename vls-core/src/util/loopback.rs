#![allow(missing_docs)]

use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::Hash;
use bitcoin::io::Error as IOError;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{ScriptBuf, Transaction, TxOut, Txid, WPubkeyHash};
use lightning::ln::chan_utils;
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::channel_keys::{DelayedPaymentKey, RevocationKey};
use lightning::ln::msgs::{UnsignedChannelAnnouncement, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::types::features::ChannelTypeFeatures;
use lightning::types::payment::PaymentPreimage;

use super::crypto_utils;
use crate::channel::{ChannelBase, ChannelId, ChannelSetup, CommitmentType};
use crate::invoice::Invoice;
use crate::node::Node;
use crate::prelude::*;
use crate::signer::multi_signer::MultiSigner;
use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
use crate::util::crypto_utils::derive_public_key;
use crate::util::status::Status;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::Arc;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::HTLCDescriptor;
use lightning::sign::{
    ChannelSigner, EntropySource, NodeSigner, PeerStorageKey, ReceiveAuthKey, Recipient,
    SignerProvider, SpendableOutputDescriptor,
};
use lightning::util::ser::{Writeable, Writer};
use lightning_invoice::RawBolt11Invoice;
use log::{debug, error, info};
use vls_common::to_derivation_path;

/// Adapt MySigner to NodeSigner
pub struct LoopbackSignerKeysInterface {
    pub node_id: PublicKey,
    pub signer: Arc<MultiSigner>,
}

impl LoopbackSignerKeysInterface {
    pub fn get_node(&self) -> Arc<Node> {
        self.signer.get_node(&self.node_id).expect("our node is missing")
    }

    pub fn add_invoice(&self, invoice: Invoice) {
        self.get_node().add_invoice(invoice).expect("could not add invoice");
    }

    pub fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
    ) -> Result<Transaction, ()> {
        self.get_node().spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
        )
    }

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        match recipient {
            Recipient::Node => Ok(self.get_node().get_node_secret()),
            Recipient::PhantomNode => Err(()),
        }
    }
}

/// Tracks lazy channel setup. LDK 0.2 removed `ChannelSigner::provide_channel_parameters`
/// (which used to call `Node::setup_channel`), so we set the channel up lazily on the first
/// signing op instead — mirroring `SignerClient` on the wire path. On the inbound side LDK
/// calls `validate_holder_commitment` before any signing op, so we defer it and replay after
/// setup completes.
struct LoopbackSetupState {
    done: bool,
    deferred_validate: Option<(HolderCommitmentTransaction, Vec<PaymentPreimage>)>,
}

#[derive(Clone)]
pub struct LoopbackChannelSigner {
    pub node_id: PublicKey,
    pub channel_id: ChannelId,
    pub signer: Arc<MultiSigner>,
    pub pubkeys: ChannelPublicKeys,
    pub channel_value_sat: u64,
    setup_state: Arc<Mutex<LoopbackSetupState>>,
}

impl LoopbackChannelSigner {
    fn new(
        node_id: &PublicKey,
        channel_id: &ChannelId,
        signer: Arc<MultiSigner>,
        channel_value_sat: u64,
    ) -> LoopbackChannelSigner {
        info!("new channel {:?} {:?}", node_id, channel_id);
        let pubkeys = signer
            .with_channel_base(&node_id, &channel_id, |base| Ok(base.get_channel_basepoints()))
            .map_err(|s| {
                error!("bad status {:?} on channel {}", s, channel_id);
                ()
            })
            .expect("must be able to get basepoints");
        LoopbackChannelSigner {
            node_id: *node_id,
            channel_id: channel_id.clone(),
            signer: signer.clone(),
            pubkeys,
            channel_value_sat,
            setup_state: Arc::new(Mutex::new(LoopbackSetupState {
                done: false,
                deferred_validate: None,
            })),
        }
    }

    /// Set the channel up on the signer from LDK's channel parameters, lazily and once.
    /// Replaces the removed `provide_channel_parameters` hook. Replays a deferred
    /// `validate_holder_commitment` (inbound side) once setup completes.
    fn ensure_setup(&self, parameters: &ChannelTransactionParameters) -> Result<(), ()> {
        let mut state = self.setup_state.lock().unwrap();
        if state.done {
            return Ok(());
        }

        // Skip if already set up (e.g. by a test harness); `with_channel_base` works on a stub.
        let already_setup = self
            .signer
            .with_channel_base(&self.node_id, &self.channel_id, |base| Ok(base.is_ready()))
            .unwrap_or(false);
        if !already_setup {
            let funding_outpoint = parameters.funding_outpoint.ok_or(())?.into_bitcoin_outpoint();
            let counterparty_parameters = parameters.counterparty_parameters.as_ref().ok_or(())?;
            // Match the negotiated channel type, like `SignerClient::do_setup_channel`.
            let features = &parameters.channel_type_features;
            let commitment_type = if features.supports_anchors_zero_fee_htlc_tx() {
                CommitmentType::AnchorsZeroFeeHtlc
            } else if features.supports_anchors_nonzero_fee_htlc_tx() {
                CommitmentType::Anchors
            } else {
                CommitmentType::StaticRemoteKey
            };
            let setup = ChannelSetup {
                is_outbound: parameters.is_outbound_from_holder,
                // LDK 0.2 dropped the channel value from `derive_channel_signer`, so take it
                // from the parameters (like `SignerClient`).
                channel_value_sat: parameters.channel_value_satoshis,
                push_value_msat: 0, // TODO
                funding_outpoint,
                holder_selected_contest_delay: parameters.holder_selected_contest_delay,
                holder_shutdown_script: None, // use the signer's shutdown script
                counterparty_points: counterparty_parameters.pubkeys.clone(),
                counterparty_selected_contest_delay: counterparty_parameters.selected_contest_delay,
                counterparty_shutdown_script: None, // TODO
                commitment_type,
            };
            let node = self.signer.get_node(&self.node_id).map_err(|_| ())?;
            node.setup_channel(self.channel_id.clone(), None, setup, &DerivationPath::master())
                .map_err(|s| self.bad_status(s))?;
        }
        // Clone rather than `take` so a failed replay leaves the message in place: `done` stays
        // false and a later signing op retries it, instead of dropping it on the floor. Same
        // ordering as `SignerClient::ensure_channel_setup`.
        if let Some((holder_tx, preimages)) = state.deferred_validate.clone() {
            self.do_validate_holder_commitment(&holder_tx, preimages)?;
            state.deferred_validate = None;
        }
        state.done = true;
        Ok(())
    }

    fn do_validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        let commitment_number = INITIAL_COMMITMENT_NUMBER - holder_tx.commitment_number();
        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                chan.htlcs_fulfilled(outbound_htlc_preimages);
                let (offered_htlcs, received_htlcs) =
                    LoopbackChannelSigner::convert_to_htlc_info2(holder_tx.nondust_htlcs());
                chan.validate_holder_commitment_tx_phase2(
                    commitment_number,
                    holder_tx.negotiated_feerate_per_kw(),
                    holder_tx.to_broadcaster_value_sat(),
                    holder_tx.to_countersignatory_value_sat(),
                    offered_htlcs,
                    received_htlcs,
                    &holder_tx.counterparty_sig,
                    &holder_tx.counterparty_htlc_sigs,
                )?;
                chan.revoke_previous_holder_commitment(commitment_number)?;
                Ok(())
            })
            .map_err(|s| self.bad_status(s))?;
        Ok(())
    }

    fn get_channel_setup(&self) -> Result<ChannelSetup, ()> {
        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| Ok(chan.setup.clone()))
            .map_err(|s| self.bad_status(s))
    }

    fn bad_status(&self, s: Status) {
        error!("bad status {:?} on channel {}", s, self.channel_id);
    }

    fn convert_to_htlc_info2(htlcs: &[HTLCOutputInCommitment]) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
        let mut offered_htlcs = Vec::new();
        let mut received_htlcs = Vec::new();
        for htlc in htlcs {
            let htlc_info = HTLCInfo2 {
                value_sat: htlc.amount_msat / 1000,
                payment_hash: htlc.payment_hash,
                cltv_expiry: htlc.cltv_expiry,
            };
            if htlc.offered {
                offered_htlcs.push(htlc_info);
            } else {
                received_htlcs.push(htlc_info);
            }
        }
        (offered_htlcs, received_htlcs)
    }

    fn dest_wallet_path() -> DerivationPath {
        to_derivation_path(&[1u32])
    }

    fn features(&self) -> ChannelTypeFeatures {
        let setup = self.get_channel_setup().expect("not ready");
        setup.features()
    }
}

impl Writeable for LoopbackChannelSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), IOError> {
        self.channel_id.inner().write(writer)?;
        self.channel_value_sat.write(writer)?;
        Ok(())
    }
}

impl ChannelSigner for LoopbackChannelSigner {
    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        let forward_idx = INITIAL_COMMITMENT_NUMBER - idx;
        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                chan.validate_counterparty_revocation(forward_idx, secret)
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(())
    }

    fn get_per_commitment_point(
        &self,
        idx: u64,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<PublicKey, ()> {
        // signer layer expect forward counting commitment number, but
        // we are passed a backwards counting one
        self.signer
            .with_channel_base(&self.node_id, &self.channel_id, |base| {
                Ok(base.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - idx).unwrap())
            })
            .map_err(|s| self.bad_status(s))
    }

    fn release_commitment_secret(&self, commitment_number: u64) -> Result<[u8; 32], ()> {
        // signer layer expect forward counting commitment number, but
        // we are passed a backwards counting one
        let secret = self.signer.with_channel(&self.node_id, &self.channel_id, |chan| {
            let secret = chan
                .get_per_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
                .unwrap();
            Ok(*secret.as_ref())
        });
        Ok(secret.expect("missing channel"))
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        // On the inbound side this is called before the channel is set up (setup happens
        // lazily on the first signing op); defer and replay after `ensure_setup` completes.
        {
            let mut state = self.setup_state.lock().unwrap();
            if !state.done {
                // Only one validation can be deferred: overwriting would silently drop a holder
                // commitment the signer never saw. Unreachable in practice (the first signing op
                // completes setup before a second `commitment_signed`), so fail the call rather
                // than lose it — LDK closes the channel instead of proceeding unvalidated.
                if state.deferred_validate.is_some() {
                    debug_assert!(false, "validate_holder_commitment called twice before setup");
                    error!("validate_holder_commitment called twice before setup");
                    return Err(());
                }
                state.deferred_validate = Some((holder_tx.clone(), outbound_htlc_preimages));
                return Ok(());
            }
        }
        self.do_validate_holder_commitment(holder_tx, outbound_htlc_preimages)
    }

    fn pubkeys(&self, _secp_ctx: &Secp256k1<All>) -> ChannelPublicKeys {
        self.pubkeys.clone()
    }

    fn new_funding_pubkey(
        &self,
        _splice_parent_funding_txid: Txid,
        _secp_ctx: &Secp256k1<All>,
    ) -> PublicKey {
        todo!("new_funding_pubkey for splicing - #538")
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        // Called before the (lazy) setup, so use `with_channel_base`, which works on a stub. Must
        // be the signer's derived keys id, which `spend_spendable_outputs` re-derives keys from.
        self.signer
            .with_channel_base(&self.node_id, &self.channel_id, |base| {
                Ok(base.get_channel_keys_id())
            })
            .expect("missing channel")
    }
}

impl EcdsaChannelSigner for LoopbackChannelSigner {
    // TODO - Couldn't this return a declared error signature?
    fn sign_counterparty_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &CommitmentTransaction,
        inbound_htlc_preimages: Vec<PaymentPreimage>,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.ensure_setup(channel_parameters)?;
        let trusted_tx = commitment_tx.trust();
        info!(
            "sign_counterparty_commitment {:?} {:?} txid {}",
            self.node_id,
            self.channel_id,
            trusted_tx.built_transaction().txid,
        );

        let (offered_htlcs, received_htlcs) =
            LoopbackChannelSigner::convert_to_htlc_info2(commitment_tx.nondust_htlcs());

        // This doesn't actually require trust
        let per_commitment_point = trusted_tx.keys().per_commitment_point;

        let commitment_number = INITIAL_COMMITMENT_NUMBER - commitment_tx.commitment_number();
        let to_holder_value_sat = commitment_tx.to_countersignatory_value_sat();
        let to_counterparty_value_sat = commitment_tx.to_broadcaster_value_sat();
        let feerate_per_kw = commitment_tx.negotiated_feerate_per_kw();

        let (commitment_sig, htlc_sigs) = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                chan.htlcs_fulfilled(inbound_htlc_preimages);
                chan.htlcs_fulfilled(outbound_htlc_preimages);
                chan.sign_counterparty_commitment_tx_phase2(
                    &per_commitment_point,
                    commitment_number,
                    feerate_per_kw,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    offered_htlcs,
                    received_htlcs,
                )
            })
            .map_err(|s| self.bad_status(s))?;
        Ok((commitment_sig, htlc_sigs))
    }

    fn sign_holder_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        hct: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.ensure_setup(channel_parameters)?;
        let commitment_tx = hct.trust();

        debug!("loopback: sign local txid {}", commitment_tx.built_transaction().txid);

        let commitment_number = INITIAL_COMMITMENT_NUMBER - hct.commitment_number();
        let to_holder_value_sat = hct.to_broadcaster_value_sat();
        let to_counterparty_value_sat = hct.to_countersignatory_value_sat();
        let feerate_per_kw = hct.negotiated_feerate_per_kw();
        let (offered_htlcs, received_htlcs) =
            LoopbackChannelSigner::convert_to_htlc_info2(hct.nondust_htlcs());

        let sig = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                let info2 = chan.validator().get_current_holder_commitment_info(
                    &mut chan.enforcement_state,
                    commitment_number,
                )?;

                let expected = CommitmentInfo2::new(
                    false,
                    to_counterparty_value_sat,
                    to_holder_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                    feerate_per_kw,
                );

                // Ensure that LDK-provided data matches previously validated state
                if info2 != expected {
                    return Err(Status::invalid_argument(
                        "holder commitment tx does not match previously validated state",
                    ));
                }
                chan.sign_holder_commitment_tx_phase2(commitment_number)
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    fn unsafe_sign_holder_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        // Intentionally bypass VLS policy enforcement — callers like
        // force-close recovery need to be able to sign older commitments
        // that the policy layer would otherwise reject.
        let node = self.signer.get_node(&self.node_id).map_err(|_| ())?;
        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                chan.keys
                    .unsafe_sign_holder_commitment(
                        channel_parameters,
                        commitment_tx,
                        node.get_entropy_source(),
                        secp_ctx,
                    )
                    .map_err(|_| Status::internal("could not unsafe-sign"))
            })
            .map_err(|_s| ())
    }

    fn sign_justice_revoked_output(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let setup = self.get_channel_setup()?;
        let counterparty_pubkeys = setup.counterparty_points;

        let (revocation_key, delayed_payment_key) = get_delayed_payment_keys(
            secp_ctx,
            &per_commitment_point,
            &counterparty_pubkeys,
            &self.pubkeys,
        )?;
        let redeem_script = chan_utils::get_revokeable_redeemscript(
            &RevocationKey(revocation_key),
            setup.holder_selected_contest_delay,
            &DelayedPaymentKey(delayed_payment_key),
        );

        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                chan.sign_justice_sweep(
                    justice_tx,
                    input,
                    per_commitment_key,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    fn sign_justice_revoked_htlc(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                let tx_keys = chan.make_counterparty_tx_keys(&per_commitment_point);
                let redeem_script =
                    chan_utils::get_htlc_redeemscript(&htlc, &self.features(), &tx_keys);
                chan.sign_justice_sweep(
                    justice_tx,
                    input,
                    per_commitment_key,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        _input: usize,
        htlc_descriptor: &HTLCDescriptor,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let signature = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |channel| {
                let per_commitment_point = &htlc_descriptor.per_commitment_point;
                let chan_keys = channel.make_holder_tx_keys(per_commitment_point);
                let witness_script = htlc_descriptor.witness_script(secp_ctx);
                let redeem_script = chan_utils::get_htlc_redeemscript(
                    &htlc_descriptor.htlc,
                    &self.features(),
                    &chan_keys,
                );
                // FIXME the redmee script is not the witness script
                channel.sign_htlc_tx(
                    htlc_tx,
                    per_commitment_point,
                    &redeem_script,
                    htlc_descriptor.htlc.amount_msat / 1000,
                    &witness_script,
                    false,
                    chan_keys.clone(),
                )
            })
            .expect("sign_htlc_tx");
        Ok(signature.sig)
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                let chan_keys = chan.make_counterparty_tx_keys(per_commitment_point);
                let redeem_script =
                    chan_utils::get_htlc_redeemscript(htlc, &self.features(), &chan_keys);
                chan.sign_counterparty_htlc_sweep(
                    htlc_tx,
                    input,
                    per_commitment_point,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_closing_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        closing_tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.ensure_setup(channel_parameters)?;
        info!("sign_closing_transaction {:?} {:?}", self.node_id, self.channel_id);

        // TODO error handling is awkward
        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                // matches ldk_shutdown_pubkey derivation in [`MyKeysManager::new`]
                let holder_wallet_path_hint = to_derivation_path(&[2u32]);

                chan.sign_mutual_close_tx_phase2(
                    closing_tx.to_holder_value_sat(),
                    closing_tx.to_counterparty_value_sat(),
                    &Some(closing_tx.to_holder_script().into()),
                    &Some(closing_tx.to_counterparty_script().into()),
                    &holder_wallet_path_hint,
                )
            })
            .map_err(|_| ())
    }

    fn sign_holder_keyed_anchor_input(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        _anchor_tx: &Transaction,
        _input: usize,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        todo!("LDK 0.2 - keyed anchor spending for EcdsaChannelSigner")
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.ensure_setup(channel_parameters)?;
        info!("sign_channel_announcement {:?} {:?}", self.node_id, self.channel_id);

        self.signer
            .with_channel(&self.node_id, &self.channel_id, |chan| {
                Ok(chan.sign_channel_announcement_with_funding_key(&msg.encode()))
            })
            .map_err(|s| self.bad_status(s))
    }

    fn sign_splice_shared_input(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        _tx: &Transaction,
        _input_index: usize,
        _secp_ctx: &Secp256k1<All>,
    ) -> Signature {
        todo!("sign_splice_shared_input - #538")
    }
}

impl SignerProvider for LoopbackSignerKeysInterface {
    type EcdsaSigner = LoopbackChannelSigner;

    // FIXME: see how to use the channel_keys_id
    fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();
        let pubkey = self.get_node().get_wallet_pubkey(&wallet_path).expect("pubkey");
        Ok(ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&pubkey.0.serialize())))
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        // FIXME - this method is deprecated
        Ok(self.get_node().get_ldk_shutdown_scriptpubkey())
    }

    fn generate_channel_keys_id(&self, _inbound: bool, _user_channel_id: u128) -> [u8; 32] {
        let node = self.signer.get_node(&self.node_id).unwrap();
        let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();
        channel_id.ldk_channel_keys_id()
    }

    fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
        let channel_id = ChannelId::new(&channel_keys_id);
        LoopbackChannelSigner::new(
            &self.node_id,
            &channel_id,
            Arc::clone(&self.signer),
            0, // channel_value_sat - unused
        )
    }
}

impl EntropySource for LoopbackSignerKeysInterface {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.get_node().get_secure_random_bytes()
    }
}

impl NodeSigner for LoopbackSignerKeysInterface {
    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        let node_secret = self.get_node_secret(recipient)?;

        Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), &node_secret))
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        let node = self.get_node();
        let sig = node.sign_gossip_message(&msg).expect("sign_gossip_message");
        Ok(sig)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        let mut node_secret = self.get_node_secret(recipient)?;
        if let Some(tweak) = tweak {
            node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
        }
        Ok(SharedSecret::new(other_key, &node_secret))
    }

    fn sign_invoice(
        &self,
        invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => return Err(()),
        };
        self.get_node().sign_bolt11_invoice(invoice.clone()).map_err(|_| ())
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &lightning::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.get_node().sign_bolt12_invoice(invoice).map_err(|_| ())
    }

    fn get_expanded_key(&self) -> ExpandedKey {
        self.get_node().get_inbound_payment_key_material()
    }

    fn get_peer_storage_key(&self) -> PeerStorageKey {
        self.get_node().keys_manager.get_peer_storage_key()
    }

    fn get_receive_auth_key(&self) -> ReceiveAuthKey {
        self.get_node().keys_manager.get_receive_auth_key()
    }

    fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
        self.get_node().keys_manager.sign_message(msg)
    }
}

fn get_delayed_payment_keys(
    secp_ctx: &Secp256k1<All>,
    per_commitment_point: &PublicKey,
    a_pubkeys: &ChannelPublicKeys,
    b_pubkeys: &ChannelPublicKeys,
) -> Result<(PublicKey, PublicKey), ()> {
    let revocation_key = crypto_utils::derive_public_revocation_key(
        secp_ctx,
        &per_commitment_point,
        &b_pubkeys.revocation_basepoint,
    )?;
    let delayed_payment_key =
        derive_public_key(secp_ctx, &per_commitment_point, &a_pubkeys.delayed_payment_basepoint.0)
            .map_err(|_| ())?;
    Ok((revocation_key.0, delayed_payment_key))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::{hex::FromHex, key::Secp256k1};
    use lightning::ln::chan_utils::ChannelTransactionParameters;
    use lightning::sign::{ecdsa::EcdsaChannelSigner, SignerProvider};

    use crate::channel::{Channel, ChannelBase};
    use crate::persist::DummySeedPersister;
    use crate::signer::multi_signer::MultiSigner;
    use crate::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
    use crate::util::test_utils::key::make_test_pubkey;
    use crate::util::test_utils::{
        init_channel, make_services, make_test_channel_setup, make_test_counterparty_keys,
        setup_validated_holder_commitment,
    };
    use crate::util::test_utils::{
        make_holder_commitment_tx, TestChannelContext, TestNodeContext, TEST_NODE_CONFIG, TEST_SEED,
    };

    fn setup_loopback_signer() -> (
        LoopbackChannelSigner,
        TestNodeContext,
        TestChannelContext,
        crate::util::test_utils::TestCommitmentTxContext,
        ChannelTransactionParameters,
    ) {
        let setup = make_test_channel_setup();
        let signer = Arc::new(MultiSigner::new(make_services()));
        let seed = Vec::from_hex(TEST_SEED[1]).expect("test seed");
        let node_id = signer
            .new_node_with_seed(TEST_NODE_CONFIG, &seed, Arc::new(DummySeedPersister {}))
            .expect("new node");

        let node = signer.get_node(&node_id).expect("get node");
        let channel_id = init_channel(setup.clone(), node.clone());
        let secp_ctx = Secp256k1::signing_only();
        let counterparty_keys = make_test_counterparty_keys(
            &TestNodeContext { node: node.clone(), secp_ctx: secp_ctx.clone() },
            &channel_id,
        );

        node.with_channel(&channel_id, |chan| {
            let commit_num = 23;
            let point = make_test_pubkey(25);
            chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num + 1, point);
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num);
            Ok(())
        })
        .expect("set commitment state");

        let node_ctx = TestNodeContext { node: node.clone(), secp_ctx };
        let chan_ctx =
            TestChannelContext { channel_id: channel_id.clone(), setup, counterparty_keys };

        let commit_tx_ctx =
            setup_validated_holder_commitment(&node_ctx, &chan_ctx, 23, |_ctx| {}, |_keys| {})
                .expect("validated commitment");

        let lsp = LoopbackSignerKeysInterface { node_id, signer };
        let loopback_signer = lsp.derive_channel_signer(channel_id.ldk_channel_keys_id());

        let channel_parameters = node
            .with_channel(&channel_id, |chan| Ok(chan.make_channel_parameters()))
            .expect("channel parameters");

        (loopback_signer, node_ctx, chan_ctx, commit_tx_ctx, channel_parameters)
    }

    #[test]
    fn sign_holder_commitment_success() {
        let (loopback_signer, node_ctx, chan_ctx, mut commit_tx_ctx, channel_parameters) =
            setup_loopback_signer();
        let hct = make_holder_commitment_tx(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        let secp_ctx = Secp256k1::new();

        let result = loopback_signer.sign_holder_commitment(&channel_parameters, &hct, &secp_ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn sign_holder_commitment_rejects_mismatch() {
        let (loopback_signer, node_ctx, chan_ctx, mut commit_tx_ctx, channel_parameters) =
            setup_loopback_signer();

        let mismatched_commitment_tx = node_ctx
            .node
            .with_channel(&chan_ctx.channel_id, |chan| {
                let per_commitment_point =
                    chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
                let htlcs = Channel::htlcs_info2_to_oic(
                    &commit_tx_ctx.offered_htlcs,
                    &commit_tx_ctx.received_htlcs,
                );

                Ok(chan.make_holder_commitment_tx(
                    commit_tx_ctx.commit_num,
                    &per_commitment_point,
                    commit_tx_ctx.feerate_per_kw + 1,
                    commit_tx_ctx.to_broadcaster,
                    commit_tx_ctx.to_countersignatory,
                    htlcs,
                ))
            })
            .expect("mismatched commitment tx");

        commit_tx_ctx.tx = Some(mismatched_commitment_tx);
        let hct = make_holder_commitment_tx(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        let secp_ctx = Secp256k1::new();

        let result = loopback_signer.sign_holder_commitment(&channel_parameters, &hct, &secp_ctx);
        assert!(result.is_err());
    }
}
