//! A VLS-owned channel signer.
//!
//! This replaces LDK's `InMemorySigner` as the per-channel signing engine inside the signer
//! process. It holds the per-channel secret keys (which VLS derives itself, see
//! [`MyKeysManager`](super::my_keys_manager::MyKeysManager)) and delegates the actual signature
//! math to LDK's public, stable `chan_utils` / `CommitmentTransaction` helpers — the same helpers
//! `InMemorySigner` uses internally. This lets VLS stop depending on LDK's `_test_utils`-gated
//! `InMemorySigner::new` constructor (which pulls in `bitcoin/bitcoinconsensus` and breaks
//! `no-std`) and on `InMemorySigner`'s `pub` key fields.
//!
//! The signer is purely internal to vls-core (it is never handed to LDK as a trait object), so it
//! exposes inherent methods rather than implementing LDK's `EcdsaChannelSigner`/`ChannelSigner`
//! traits.
//!
//! Only v1 `remote_key` derivation is supported (matching prior VLS behaviour). LDK's v2
//! static-remote-key scheme and the splice funding-key tweak are out of scope; the
//! `funding_key(Option<Txid>)` accessor keeps its shape for a future tweak but currently ignores
//! the argument.

use crate::prelude::*;
use crate::util::crypto_utils::{sign, sign_with_aux_rand};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, Signing};
use bitcoin::sighash::{self, EcdsaSighashType};
use bitcoin::{Network, ScriptBuf, Transaction, Txid, Witness};

use crate::tx::script::ANCHOR_OUTPUT_VALUE_SATOSHI;
use lightning::ln::chan_utils::{
    self, build_htlc_transaction, get_countersigner_payment_script, get_htlc_redeemscript,
    get_keyed_anchor_redeemscript, get_revokeable_redeemscript,
    get_to_countersigner_keyed_anchor_redeemscript, make_funding_redeemscript, ChannelPublicKeys,
    ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HolderCommitmentTransaction,
};
use lightning::ln::channel_keys::{
    DelayedPaymentBasepoint, DelayedPaymentKey, HtlcBasepoint, RevocationBasepoint,
};
use lightning::sign::{
    DelayedPaymentOutputDescriptor, EntropySource, HTLCDescriptor, StaticPaymentOutputDescriptor,
};
use lightning::types::features::ChannelTypeFeatures;

/// A per-channel signer owned by VLS.
///
/// See the [module docs](self) for rationale.
#[derive(Clone)]
pub struct VlsChannelSigner {
    /// Holder funding secret key (2-of-2 multisig). Private; access via [`Self::funding_key`].
    funding_key: SecretKey,
    /// Holder revocation basepoint secret key.
    pub(crate) revocation_base_key: SecretKey,
    /// Holder payment secret key (v1 derivation only).
    payment_key: SecretKey,
    /// Holder delayed-payment basepoint secret key.
    pub(crate) delayed_payment_base_key: SecretKey,
    /// Holder HTLC basepoint secret key.
    pub(crate) htlc_base_key: SecretKey,
    /// Commitment seed, used to derive per-commitment secrets/points.
    pub(crate) commitment_seed: [u8; 32],
    /// The LDK channel-keys id for this channel.
    channel_keys_id: [u8; 32],
    /// Cached holder channel public keys (derived once at construction).
    holder_pubkeys: ChannelPublicKeys,
}

impl VlsChannelSigner {
    /// Construct a signer from individually-derived per-channel secret keys.
    ///
    /// Argument order mirrors the former `make_in_memory_signer` shim for an easy swap.
    pub fn new<C: Signing>(
        funding_key: SecretKey,
        revocation_base_key: SecretKey,
        payment_key: SecretKey,
        delayed_payment_base_key: SecretKey,
        htlc_base_key: SecretKey,
        commitment_seed: [u8; 32],
        channel_keys_id: [u8; 32],
        secp_ctx: &Secp256k1<C>,
    ) -> Self {
        let from_secret = |s: &SecretKey| PublicKey::from_secret_key(secp_ctx, s);
        let holder_pubkeys = ChannelPublicKeys {
            funding_pubkey: from_secret(&funding_key),
            revocation_basepoint: RevocationBasepoint::from(from_secret(&revocation_base_key)),
            payment_point: from_secret(&payment_key),
            delayed_payment_basepoint: DelayedPaymentBasepoint::from(from_secret(
                &delayed_payment_base_key,
            )),
            htlc_basepoint: HtlcBasepoint::from(from_secret(&htlc_base_key)),
        };
        VlsChannelSigner {
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_keys_id,
            holder_pubkeys,
        }
    }

    // --- Accessors (drop-in replacements for the InMemorySigner methods VLS called) ---

    /// Holder channel public keys (basepoints). The `secp_ctx` argument is unused (the pubkeys are
    /// cached at construction); it is kept for signature compatibility with the prior call sites.
    pub fn pubkeys<C: Signing>(&self, _secp_ctx: &Secp256k1<C>) -> ChannelPublicKeys {
        self.holder_pubkeys.clone()
    }

    /// The per-commitment point for the given commitment index.
    pub fn get_per_commitment_point<C: Signing>(
        &self,
        idx: u64,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<PublicKey, ()> {
        let commitment_secret =
            SecretKey::from_slice(&chan_utils::build_commitment_secret(&self.commitment_seed, idx))
                .map_err(|_| ())?;
        Ok(PublicKey::from_secret_key(secp_ctx, &commitment_secret))
    }

    /// Release the per-commitment secret for the given (revoked) commitment index.
    pub fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        Ok(chan_utils::build_commitment_secret(&self.commitment_seed, idx))
    }

    /// Holder funding secret key. The splice-parent argument is reserved for a future funding-key
    /// tweak and is currently ignored (v1 behaviour); guard against a caller silently expecting a
    /// tweaked key before splice support lands.
    pub fn funding_key(&self, splice_parent_funding_txid: Option<Txid>) -> SecretKey {
        debug_assert!(
            splice_parent_funding_txid.is_none(),
            "funding-key tweak for splicing is not yet implemented (#538)"
        );
        self.funding_key
    }

    /// The LDK channel-keys id for this channel.
    pub fn channel_keys_id(&self) -> [u8; 32] {
        self.channel_keys_id
    }

    // --- Signing operations (ported from LDK's `EcdsaChannelSigner for InMemorySigner`) ---

    /// Sign a counterparty commitment transaction, returning the funding signature and the
    /// per-HTLC signatures. Fully deterministic (low-R) under grinding.
    pub fn sign_counterparty_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &CommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let trusted_tx = commitment_tx.trust();
        let keys = trusted_tx.keys();

        let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
        let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &funding_key);
        let counterparty_keys = channel_parameters.counterparty_pubkeys().ok_or(())?;
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_keys.funding_pubkey);

        let built_tx = trusted_tx.built_transaction();
        let commitment_sig = built_tx.sign_counterparty_commitment(
            &funding_key,
            &channel_funding_redeemscript,
            channel_parameters.channel_value_satoshis,
            secp_ctx,
        );
        let commitment_txid = built_tx.txid;

        let mut htlc_sigs = Vec::with_capacity(commitment_tx.nondust_htlcs().len());
        for htlc in commitment_tx.nondust_htlcs() {
            let holder_selected_contest_delay = channel_parameters.holder_selected_contest_delay;
            let chan_type = &channel_parameters.channel_type_features;
            let htlc_tx = build_htlc_transaction(
                &commitment_txid,
                commitment_tx.negotiated_feerate_per_kw(),
                holder_selected_contest_delay,
                htlc,
                chan_type,
                &keys.broadcaster_delayed_payment_key,
                &keys.revocation_key,
            );
            let htlc_redeemscript = get_htlc_redeemscript(htlc, chan_type, &keys);
            let htlc_sighashtype = if chan_type.supports_anchors_zero_fee_htlc_tx()
                || chan_type.supports_anchor_zero_fee_commitments()
            {
                EcdsaSighashType::SinglePlusAnyoneCanPay
            } else {
                EcdsaSighashType::All
            };
            let htlc_sighash = Message::from_digest(
                sighash::SighashCache::new(&htlc_tx)
                    .p2wsh_signature_hash(
                        0,
                        &htlc_redeemscript,
                        htlc.to_bitcoin_amount(),
                        htlc_sighashtype,
                    )
                    .map_err(|_| ())?
                    .to_byte_array(),
            );
            let holder_htlc_key = chan_utils::derive_private_key(
                secp_ctx,
                &keys.per_commitment_point,
                &self.htlc_base_key,
            );
            htlc_sigs.push(sign(secp_ctx, &htlc_sighash, &holder_htlc_key));
        }

        Ok((commitment_sig, htlc_sigs))
    }

    /// Sign the holder's commitment transaction. Non-deterministic (aux-rand grinding).
    pub fn sign_holder_commitment<ES: EntropySource + ?Sized>(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
        let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &funding_key);
        let counterparty_keys = channel_parameters.counterparty_pubkeys().ok_or(())?;
        let funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_keys.funding_pubkey);
        let trusted_tx = commitment_tx.trust();
        Ok(trusted_tx.built_transaction().sign_holder_commitment(
            &funding_key,
            &funding_redeemscript,
            channel_parameters.channel_value_satoshis,
            &entropy_source,
            secp_ctx,
        ))
    }

    /// Sign the holder's commitment transaction, bypassing policy. Identical signing to
    /// [`Self::sign_holder_commitment`]; the "unsafe" distinction is enforced by the caller (e.g.
    /// force-close recovery), matching LDK's `unsafe_sign_holder_commitment`.
    pub fn unsafe_sign_holder_commitment<ES: EntropySource + ?Sized>(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.sign_holder_commitment(channel_parameters, commitment_tx, entropy_source, secp_ctx)
    }

    /// Sign a transaction spending the holder's keyed anchor output. Non-deterministic.
    pub fn sign_holder_keyed_anchor_input<ES: EntropySource + ?Sized>(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        anchor_tx: &Transaction,
        input: usize,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let witness_script =
            get_keyed_anchor_redeemscript(&channel_parameters.holder_pubkeys.funding_pubkey);
        let amt = ANCHOR_OUTPUT_VALUE_SATOSHI;
        let sighash = sighash::SighashCache::new(anchor_tx)
            .p2wsh_signature_hash(input, &witness_script, amt, EcdsaSighashType::All)
            .map_err(|_| ())?;
        let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
        let sighash = Message::from_digest(sighash.to_byte_array());
        Ok(sign_with_aux_rand(secp_ctx, &sighash, &funding_key, entropy_source))
    }

    /// Sign a holder second-level HTLC transaction. Non-deterministic (aux-rand grinding).
    pub fn sign_holder_htlc_transaction<ES: EntropySource + ?Sized>(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        htlc_descriptor: &HTLCDescriptor,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let witness_script = htlc_descriptor.witness_script(secp_ctx);
        let sighash = sighash::SighashCache::new(htlc_tx)
            .p2wsh_signature_hash(
                input,
                &witness_script,
                htlc_descriptor.htlc.to_bitcoin_amount(),
                EcdsaSighashType::All,
            )
            .map_err(|_| ())?;
        let our_htlc_private_key = chan_utils::derive_private_key(
            secp_ctx,
            &htlc_descriptor.per_commitment_point,
            &self.htlc_base_key,
        );
        let sighash = Message::from_digest(sighash.to_byte_array());
        Ok(sign_with_aux_rand(secp_ctx, &sighash, &our_htlc_private_key, entropy_source))
    }

    /// Sign a cooperative closing transaction. Deterministic (low-R) under grinding.
    pub fn sign_closing_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        closing_tx: &ClosingTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
        let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &funding_key);
        let counterparty_funding_key =
            &channel_parameters.counterparty_pubkeys().ok_or(())?.funding_pubkey;
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, counterparty_funding_key);
        Ok(closing_tx.trust().sign(
            &funding_key,
            &channel_funding_redeemscript,
            channel_parameters.channel_value_satoshis,
            secp_ctx,
        ))
    }

    // --- Spendable-output sweep (ported for `MyKeysManager::spend_spendable_outputs`) ---

    /// Sign a counterparty static-payment output (the `to_remote` output). Non-deterministic.
    pub fn sign_counterparty_payment_input<C: Signing, ES: EntropySource + ?Sized>(
        &self,
        spend_tx: &Transaction,
        input_idx: usize,
        descriptor: &StaticPaymentOutputDescriptor,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<Witness, ()> {
        if spend_tx.input.len() <= input_idx {
            return Err(());
        }
        if !spend_tx.input[input_idx].script_sig.is_empty() {
            return Err(());
        }
        if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint()
        {
            return Err(());
        }

        let legacy_default_channel_type = ChannelTypeFeatures::only_static_remote_key();
        let channel_type_features = descriptor
            .channel_transaction_parameters
            .as_ref()
            .map(|params| &params.channel_type_features)
            .unwrap_or(&legacy_default_channel_type);

        // VLS uses v1 `remote_key` derivation only, so there is a single payment key.
        let payment_point = PublicKey::from_secret_key(secp_ctx, &self.payment_key);
        let spk = get_countersigner_payment_script(channel_type_features, &payment_point);
        if spk != descriptor.output.script_pubkey {
            return Err(());
        }
        let remotepubkey = bitcoin::PublicKey::new(payment_point);

        let witness_script = if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
            get_to_countersigner_keyed_anchor_redeemscript(&remotepubkey.inner)
        } else {
            ScriptBuf::new_p2pkh(&remotepubkey.pubkey_hash())
        };
        let sighash = Message::from_digest(
            sighash::SighashCache::new(spend_tx)
                .p2wsh_signature_hash(
                    input_idx,
                    &witness_script,
                    descriptor.output.value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| ())?
                .to_byte_array(),
        );
        let remotesig = sign_with_aux_rand(secp_ctx, &sighash, &self.payment_key, entropy_source);
        let payment_script = if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
            witness_script.to_p2wsh()
        } else {
            ScriptBuf::new_p2wpkh(&remotepubkey.wpubkey_hash().map_err(|_| ())?)
        };

        if payment_script != descriptor.output.script_pubkey {
            return Err(());
        }

        let mut witness = Vec::with_capacity(2);
        witness.push(remotesig.serialize_der().to_vec());
        witness[0].push(EcdsaSighashType::All as u8);
        if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
            witness.push(witness_script.to_bytes());
        } else {
            witness.push(remotepubkey.to_bytes());
        }
        Ok(witness.into())
    }

    /// Sign a holder delayed-payment output (the `to_local` output after our contest delay).
    /// Non-deterministic.
    pub fn sign_dynamic_p2wsh_input<C: Signing, ES: EntropySource + ?Sized>(
        &self,
        spend_tx: &Transaction,
        input_idx: usize,
        descriptor: &DelayedPaymentOutputDescriptor,
        entropy_source: &ES,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<Witness, ()> {
        if spend_tx.input.len() <= input_idx {
            return Err(());
        }
        if !spend_tx.input[input_idx].script_sig.is_empty() {
            return Err(());
        }
        if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint()
        {
            return Err(());
        }
        if spend_tx.input[input_idx].sequence.0 != descriptor.to_self_delay as u32 {
            return Err(());
        }

        let delayed_payment_key = chan_utils::derive_private_key(
            secp_ctx,
            &descriptor.per_commitment_point,
            &self.delayed_payment_base_key,
        );
        let delayed_payment_pubkey =
            DelayedPaymentKey::from_secret_key(secp_ctx, &delayed_payment_key);
        let witness_script = get_revokeable_redeemscript(
            &descriptor.revocation_pubkey,
            descriptor.to_self_delay,
            &delayed_payment_pubkey,
        );
        let sighash = Message::from_digest(
            sighash::SighashCache::new(spend_tx)
                .p2wsh_signature_hash(
                    input_idx,
                    &witness_script,
                    descriptor.output.value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| ())?
                .to_byte_array(),
        );
        let local_delayedsig =
            sign_with_aux_rand(secp_ctx, &sighash, &delayed_payment_key, entropy_source);
        let payment_script =
            bitcoin::Address::p2wsh(&witness_script, Network::Bitcoin).script_pubkey();

        if descriptor.output.script_pubkey != payment_script {
            return Err(());
        }

        let mut sig_ser = local_delayedsig.serialize_der().to_vec();
        sig_ser.push(EcdsaSighashType::All as u8);
        Ok(Witness::from_slice(&[
            sig_ser,
            vec![], // MINIMALIF
            witness_script.to_bytes(),
        ]))
    }
}

impl core::fmt::Debug for VlsChannelSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // Redact secret material; only surface non-sensitive identifying data.
        f.debug_struct("VlsChannelSigner")
            .field("channel_keys_id", &self.channel_keys_id)
            .field("holder_pubkeys", &self.holder_pubkeys)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    //! Parity tests: a `VlsChannelSigner` and an LDK `InMemorySigner` built from identical keys
    //! must produce identical results. These run BEFORE the `Channel.keys` type is swapped, so they
    //! prove the new struct is a faithful replacement independent of the rest of vls-core.
    //!
    //! Deterministic ops (counterparty commitment, closing) are asserted byte-for-byte. The
    //! aux-rand ops (holder commitment/HTLC, sweeps) are non-deterministic and are covered instead
    //! by the existing end-to-end `sign_*_tests` / `validate_*_tests` after the swap.

    use super::*;
    use crate::util::test_utils::key::{
        make_test_counterparty_points, make_test_privkey, make_test_pubkey,
    };

    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{OutPoint, ScriptBuf};
    use lightning::chain::transaction::OutPoint as LdkOutPoint;
    use lightning::ln::chan_utils::{
        ChannelTransactionParameters, CommitmentTransaction,
        CounterpartyChannelTransactionParameters, HTLCOutputInCommitment,
    };
    use lightning::ln::channel_keys::RevocationKey;
    use lightning::sign::ecdsa::EcdsaChannelSigner;
    use lightning::sign::{ChannelSigner, InMemorySigner};
    use lightning::types::features::ChannelTypeFeatures;
    use lightning::types::payment::PaymentHash;
    use test_log::test;

    const CHANNEL_VALUE_SAT: u64 = 3_000_000;

    fn anchor_features() -> ChannelTypeFeatures {
        let mut f = ChannelTypeFeatures::only_static_remote_key();
        f.set_anchors_zero_fee_htlc_tx_required();
        f
    }

    /// Build both signers from the same fixed test privkeys (1..=5), matching `make_test_channel_keys`.
    fn both_signers() -> (InMemorySigner, VlsChannelSigner) {
        let secp = Secp256k1::new();
        // Construct the LDK reference signer directly (the test oracle), mirroring the keys used
        // by `make_test_channel_keys` (which now returns a `VlsChannelSigner`).
        let ldk = InMemorySigner::new(
            make_test_privkey(1), // funding_key
            make_test_privkey(2), // revocation_base_key
            make_test_privkey(3), // payment_key v1
            make_test_privkey(3), // payment_key v2
            false,                // v2_remote_key_derivation
            make_test_privkey(4), // delayed_payment_base_key
            make_test_privkey(5), // htlc_base_key
            [4u8; 32],            // commitment_seed
            // Deliberately non-zero: an all-zero id would make the accessor
            // indistinguishable from a stub returning `[0; 32]`.
            [7u8; 32], // channel_keys_id
            [0u8; 32], // rand_bytes
        );
        let vls = VlsChannelSigner::new(
            make_test_privkey(1), // funding_key
            make_test_privkey(2), // revocation_base_key
            make_test_privkey(3), // payment_key
            make_test_privkey(4), // delayed_payment_base_key
            make_test_privkey(5), // htlc_base_key
            [4u8; 32],            // commitment_seed
            // Deliberately non-zero: an all-zero id would make the accessor
            // indistinguishable from a stub returning `[0; 32]`.
            [7u8; 32], // channel_keys_id
            &secp,
        );
        (ldk, vls)
    }

    fn make_params(
        holder_pubkeys: ChannelPublicKeys,
        channel_type_features: ChannelTypeFeatures,
    ) -> ChannelTransactionParameters {
        ChannelTransactionParameters {
            holder_pubkeys,
            holder_selected_contest_delay: 6,
            is_outbound_from_holder: true,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: make_test_counterparty_points(),
                selected_contest_delay: 7,
            }),
            funding_outpoint: Some(lightning::chain::transaction::OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                index: 0,
            }),
            splice_parent_funding_txid: None,
            channel_type_features,
            channel_value_satoshis: CHANNEL_VALUE_SAT,
        }
    }

    fn make_counterparty_commitment_tx(
        params: &ChannelTransactionParameters,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        with_htlc: bool,
    ) -> CommitmentTransaction {
        let per_commitment_point = make_test_pubkey(10);
        let directed = params.as_counterparty_broadcastable();
        let htlcs = if with_htlc {
            vec![HTLCOutputInCommitment {
                offered: true,
                amount_msat: 100_000_000,
                cltv_expiry: 500,
                payment_hash: PaymentHash([7u8; 32]),
                transaction_output_index: None,
            }]
        } else {
            vec![]
        };
        let mut tx = CommitmentTransaction::new(
            42,
            &per_commitment_point,
            1_000_000,
            1_000_000,
            253,
            htlcs,
            &directed,
            secp,
        );
        if params.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
            tx = tx.with_non_zero_fee_anchors();
        }
        tx
    }

    /// The `Debug` impl must identify the type without ever leaking secret key material —
    /// these get written to logs.
    #[test]
    fn debug_identifies_type_and_redacts_secrets() {
        let (_ldk, vls) = both_signers();
        let rendered = format!("{:?}", vls);

        assert!(rendered.contains("VlsChannelSigner"), "should name the type: {}", rendered);
        assert!(rendered.contains("channel_keys_id"), "should show the channel id: {}", rendered);

        // None of the secret keys may appear, in any representation.
        for secret in [
            make_test_privkey(1), // funding_key
            make_test_privkey(2), // revocation_base_key
            make_test_privkey(3), // payment_key
            make_test_privkey(4), // delayed_payment_base_key
            make_test_privkey(5), // htlc_base_key
        ] {
            let hex = secret.display_secret().to_string();
            assert!(!rendered.contains(&hex), "Debug leaked a secret key: {}", rendered);
            assert!(!rendered.contains(&format!("{:?}", secret)), "Debug leaked a secret key");
        }
        // ... nor the commitment seed, which derives every per-commitment secret.
        assert!(!rendered.contains(&hex::encode([4u8; 32])), "Debug leaked the commitment seed");
    }

    #[test]
    fn accessor_parity() {
        let secp = Secp256k1::new();
        let (ldk, vls) = both_signers();

        assert_eq!(vls.pubkeys(&secp), ldk.pubkeys(&secp));
        assert_eq!(vls.funding_key(None), ldk.funding_key(None));
        assert_eq!(vls.channel_keys_id(), ldk.channel_keys_id());
        for idx in [0u64, 1, 42, INITIAL_IDX, u64::MAX] {
            assert_eq!(
                vls.get_per_commitment_point(idx, &secp),
                ldk.get_per_commitment_point(idx, &secp),
                "per_commitment_point mismatch at {idx}"
            );
            assert_eq!(
                vls.release_commitment_secret(idx),
                ldk.release_commitment_secret(idx),
                "commitment_secret mismatch at {idx}"
            );
        }
    }
    const INITIAL_IDX: u64 = (1u64 << 48) - 1;

    fn assert_counterparty_commitment_parity(
        channel_type_features: ChannelTypeFeatures,
        with_htlc: bool,
    ) {
        let secp = Secp256k1::new();
        let (ldk, vls) = both_signers();
        let params = make_params(ldk.pubkeys(&secp), channel_type_features);
        let commitment_tx = make_counterparty_commitment_tx(&params, &secp, with_htlc);

        let (vls_sig, vls_htlc_sigs) =
            vls.sign_counterparty_commitment(&params, &commitment_tx, &secp).expect("vls sign");
        let (ldk_sig, ldk_htlc_sigs) = ldk
            .sign_counterparty_commitment(&params, &commitment_tx, vec![], vec![], &secp)
            .expect("ldk sign");

        assert_eq!(vls_sig, ldk_sig, "funding sig mismatch");
        assert_eq!(vls_htlc_sigs, ldk_htlc_sigs, "htlc sigs mismatch");
        assert_eq!(with_htlc, !vls_htlc_sigs.is_empty(), "expected htlc sig presence");
    }

    #[test]
    fn counterparty_commitment_parity_static() {
        assert_counterparty_commitment_parity(ChannelTypeFeatures::only_static_remote_key(), false);
        assert_counterparty_commitment_parity(ChannelTypeFeatures::only_static_remote_key(), true);
    }

    #[test]
    fn counterparty_commitment_parity_anchors() {
        assert_counterparty_commitment_parity(anchor_features(), false);
        assert_counterparty_commitment_parity(anchor_features(), true);
    }

    /// Build a tx spending `outpoint` with the given sequence.
    fn make_spend_tx(outpoint: LdkOutPoint, sequence: bitcoin::Sequence) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint.into_bitcoin_outpoint(),
                script_sig: ScriptBuf::new(),
                sequence,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::CompressedPublicKey(make_test_pubkey(30)).wpubkey_hash(),
                ),
            }],
        }
    }

    /// Assert a witness signature element (DER ++ sighash byte) verifies against `pubkey`.
    fn check_witness_sig(elem: &[u8], pubkey: &PublicKey, sighash: Message) {
        let (sighash_byte, der) = elem.split_last().expect("non-empty sig element");
        assert_eq!(*sighash_byte, EcdsaSighashType::All as u8, "sighash type");
        let sig = Signature::from_der(der).expect("valid DER");
        Secp256k1::new().verify_ecdsa(&sighash, &sig, pubkey).expect("signature verifies");
    }

    /// The sweep ops sign with aux randomness, so the signature bytes differ per call. Assert the
    /// witness *layout* and every non-signature element match LDK exactly, and that both
    /// signatures verify against the same sighash — which is what catches a mis-ported witness.
    fn assert_counterparty_payment_input_parity(anchors: bool) {
        let secp = Secp256k1::new();
        let (ldk, vls) = both_signers();

        let payment_point = PublicKey::from_secret_key(&secp, &make_test_privkey(3));
        let features =
            if anchors { anchor_features() } else { ChannelTypeFeatures::only_static_remote_key() };
        let spk = get_countersigner_payment_script(&features, &payment_point);
        let value = bitcoin::Amount::from_sat(100_000);
        let outpoint = LdkOutPoint { txid: bitcoin::Txid::all_zeros(), index: 0 };

        // With `None` both signers fall back to `only_static_remote_key`; the anchor case needs
        // real parameters so the anchor branch is taken.
        let channel_transaction_parameters =
            if anchors { Some(make_params(ldk.pubkeys(&secp), features.clone())) } else { None };

        let descriptor = StaticPaymentOutputDescriptor {
            outpoint,
            output: bitcoin::TxOut { value, script_pubkey: spk },
            channel_keys_id: [0u8; 32],
            channel_value_satoshis: CHANNEL_VALUE_SAT,
            channel_transaction_parameters,
        };
        let spend_tx = make_spend_tx(outpoint, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME);

        let vls_w = vls
            .sign_counterparty_payment_input(&spend_tx, 0, &descriptor, &ldk, &secp)
            .expect("vls sign");
        let ldk_w = ldk
            .sign_counterparty_payment_input(&spend_tx, 0, &descriptor, &secp)
            .expect("ldk sign");

        let vls_v = vls_w.to_vec();
        let ldk_v = ldk_w.to_vec();
        assert_eq!(vls_v.len(), ldk_v.len(), "witness element count");
        // Element 1 is the witness script under anchors, else the pubkey.
        assert_eq!(vls_v[1], ldk_v[1], "witness trailing element");

        // Anchors spend the keyed-anchor script; non-anchor uses a p2pkh-shaped script.
        let witness_script = if anchors {
            get_to_countersigner_keyed_anchor_redeemscript(&payment_point)
        } else {
            ScriptBuf::new_p2pkh(&bitcoin::PublicKey::new(payment_point).pubkey_hash())
        };
        let sighash = Message::from_digest(
            sighash::SighashCache::new(&spend_tx)
                .p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array(),
        );
        check_witness_sig(&vls_v[0], &payment_point, sighash);
        check_witness_sig(&ldk_v[0], &payment_point, sighash);
    }

    #[test]
    fn counterparty_payment_input_parity_static() {
        assert_counterparty_payment_input_parity(false);
    }

    /// lnrod negotiates anchors, so this is the branch that actually runs in production.
    #[test]
    fn counterparty_payment_input_parity_anchors() {
        assert_counterparty_payment_input_parity(true);
    }

    #[test]
    fn dynamic_p2wsh_input_parity() {
        let secp = Secp256k1::new();
        let (ldk, vls) = both_signers();

        let per_commitment_point = make_test_pubkey(10);
        let to_self_delay: u16 = 6;
        let revocation_pubkey = RevocationKey::from_basepoint(
            &secp,
            &RevocationBasepoint::from(make_test_pubkey(11)),
            &per_commitment_point,
        );
        // delayed_payment_base_key is privkey 4 (see `both_signers`).
        let delayed_privkey =
            chan_utils::derive_private_key(&secp, &per_commitment_point, &make_test_privkey(4));
        let delayed_pubkey = DelayedPaymentKey::from_secret_key(&secp, &delayed_privkey);
        let witness_script =
            get_revokeable_redeemscript(&revocation_pubkey, to_self_delay, &delayed_pubkey);
        let value = bitcoin::Amount::from_sat(100_000);
        let outpoint = LdkOutPoint { txid: bitcoin::Txid::all_zeros(), index: 0 };

        let descriptor = DelayedPaymentOutputDescriptor {
            outpoint,
            per_commitment_point,
            to_self_delay,
            output: bitcoin::TxOut { value, script_pubkey: witness_script.to_p2wsh() },
            revocation_pubkey,
            channel_keys_id: [0u8; 32],
            channel_value_satoshis: CHANNEL_VALUE_SAT,
            channel_transaction_parameters: None,
        };
        // The signers require the input sequence to equal to_self_delay.
        let spend_tx = make_spend_tx(outpoint, bitcoin::Sequence(to_self_delay as u32));

        let vls_w =
            vls.sign_dynamic_p2wsh_input(&spend_tx, 0, &descriptor, &ldk, &secp).expect("vls sign");
        let ldk_w =
            ldk.sign_dynamic_p2wsh_input(&spend_tx, 0, &descriptor, &secp).expect("ldk sign");

        let vls_v = vls_w.to_vec();
        let ldk_v = ldk_w.to_vec();
        assert_eq!(vls_v.len(), ldk_v.len(), "witness element count");
        // Element 1 is the MINIMALIF empty push, element 2 the witness script.
        assert_eq!(vls_v[1], ldk_v[1], "MINIMALIF element");
        assert_eq!(vls_v[2], ldk_v[2], "witness script element");
        assert_eq!(vls_v[2], witness_script.to_bytes(), "witness script contents");

        let sighash = Message::from_digest(
            sighash::SighashCache::new(&spend_tx)
                .p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array(),
        );
        check_witness_sig(&vls_v[0], &delayed_pubkey.to_public_key(), sighash);
        check_witness_sig(&ldk_v[0], &delayed_pubkey.to_public_key(), sighash);
    }

    #[test]
    fn closing_transaction_parity() {
        let secp = Secp256k1::new();
        let (ldk, vls) = both_signers();
        let params = make_params(ldk.pubkeys(&secp), ChannelTypeFeatures::only_static_remote_key());

        let holder_script = ScriptBuf::new_p2wpkh(
            &bitcoin::CompressedPublicKey(make_test_pubkey(20)).wpubkey_hash(),
        );
        let counterparty_script = ScriptBuf::new_p2wpkh(
            &bitcoin::CompressedPublicKey(make_test_pubkey(21)).wpubkey_hash(),
        );
        let closing_tx = lightning::ln::chan_utils::ClosingTransaction::new(
            1_400_000,
            1_400_000,
            holder_script,
            counterparty_script,
            OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 0 },
        );

        let vls_sig = vls.sign_closing_transaction(&params, &closing_tx, &secp).expect("vls sign");
        let ldk_sig = ldk.sign_closing_transaction(&params, &closing_tx, &secp).expect("ldk sign");
        assert_eq!(vls_sig, ldk_sig, "closing sig mismatch");
    }
}
