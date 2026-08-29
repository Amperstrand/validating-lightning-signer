use core::any::Any;
use core::fmt;
use core::fmt::{Debug, Error, Formatter};

use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, ecdsa::Signature, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, Network, OutPoint, Script, ScriptBuf, Transaction, Txid};
use lightning::chain;
use lightning::ln::chan_utils::{self, build_htlc_input_witness};
use lightning::ln::chan_utils::{
    build_htlc_transaction, derive_private_key, get_htlc_redeemscript, make_funding_redeemscript,
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    CounterpartyChannelTransactionParameters, HTLCOutputInCommitment, HolderCommitmentTransaction,
    TrustedCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::channel_keys::{DelayedPaymentKey, RevocationKey};
use lightning::sign::{ChannelDerivationParameters, HTLCDescriptor, SignerProvider};
use lightning::types::features::ChannelTypeFeatures;
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use serde_derive::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as, Bytes, IfIsHumanReadable};
use tracing::*;
use vls_common::HexEncode;

use crate::monitor::ChainMonitorBase;
use crate::node::{Node, RoutedPayment, CHANNEL_STUB_PRUNE_BLOCKS};
use crate::policy::error::policy_error;
use crate::policy::validator::{ChainState, CommitmentSignatures, EnforcementState, Validator};
use crate::prelude::*;
use crate::signer::vls_channel_signer::VlsChannelSigner;
use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
use crate::util::crypto_utils::derive_public_key;
use crate::util::crypto_utils::derive_public_revocation_key;
use crate::util::debug_utils::{DebugHTLCOutputInCommitment, DebugVecVecU8};
use crate::util::ser_util::{ChannelPublicKeysDef, OutPointReversedDef, ScriptDef};
use crate::util::status::{internal_error, invalid_argument, Status};
use crate::util::transaction_utils::add_holder_sig;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::wallet::Wallet;
use crate::{catch_panic, policy_err, Arc, CommitmentPointProvider, Weak};

/// Represents a UTXO provided as input to a transaction.
///
/// This can be used for various purposes including:
/// - Paying transaction fees
/// - UTXO consolidation
/// - Providing additional input for any reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputUtxo {
    /// The outpoint identifying the UTXO (txid + vout).
    pub outpoint: OutPoint,
    /// The value of the UTXO.
    pub value: Amount,
    /// The derivation path of the UTXO.
    pub derivation_path: DerivationPath,
}

/// Channel identifier
///
/// This id is used to coordinate with the node and
/// is not related to the channel ids in the Lightning protocol.
/// The channel keys are derived from this and a base key.
///
/// A channel may have more than one id.
///
/// There are currently two ways to generate ids: one which uses
/// a peer id and is compatible with CLN, and one which doesn't
/// and is compatible with LDK. In both cases the id of the channel
/// at the node (called a `dbid` in CLN or `oid in LDK) is stored
/// in little-endian in the final 8 bytes of the id. This fact is
/// relied when retrieving the `dbid`/`oid`.
#[serde_as]
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChannelId(#[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")] Vec<u8>);

impl ChannelId {
    /// Create an id from a nonce
    pub fn new(inner: &[u8]) -> Self {
        Self(inner.to_vec())
    }

    /// Create an id from an oid (LDK-style)
    ///
    /// The nonce is a 32 byte array, where the first
    /// 24 bytes are 0 and the last 8 are the original
    /// id (little-endian)
    pub fn new_from_oid(oid: u64) -> Self {
        let mut nonce: [u8; 32] = [0u8; 32];
        let oid_slice = oid.to_le_bytes();
        nonce[24..].copy_from_slice(&oid_slice);
        Self::new(&nonce)
    }

    /// Create an id from a peer id and oid (CLN-style)
    ///
    /// The nonce is a 41 byte array, where the first 33
    /// bytes are the peer id and the final 8 are the
    /// original id (little-endian)
    pub fn new_from_peer_id_and_oid(peer_id: &[u8; 33], oid: u64) -> Self {
        let mut nonce = [0u8; 33 + 8];
        nonce[0..33].copy_from_slice(peer_id);
        nonce[33..].copy_from_slice(&oid.to_le_bytes());
        Self::new(&nonce)
    }

    /// Return a byte slice of the nonce
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return a reference to a vector of the nonce
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }

    /// Returns the original id used at creation
    pub fn oid(&self) -> u64 {
        let bytes_slice = &self.0[&self.0.len() - 8..];
        let mut bytes_array = [0u8; 8];
        bytes_array.copy_from_slice(bytes_slice);
        u64::from_le_bytes(bytes_array)
    }

    /// Return the id in a format compatible with the LDK
    /// `SignerProvider` `generate_channel_keys_id` interface
    ///
    /// This will panic if the nonce is not exactly 32 bytes
    pub fn ldk_channel_keys_id(&self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&self.0);
        nonce
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", self.0.to_hex())
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

/// Bitcoin Signature which specifies EcdsaSighashType
#[derive(Debug)]
pub struct TypedSignature {
    /// The signature
    pub sig: Signature,
    /// The sighash type
    pub typ: EcdsaSighashType,
}

impl TypedSignature {
    /// Serialize the signature and append the sighash type byte.
    pub fn serialize(&self) -> Vec<u8> {
        let mut ss = self.sig.serialize_der().to_vec();
        ss.push(self.typ as u8);
        ss
    }

    /// A TypedSignature with SIGHASH_ALL
    pub fn all(sig: Signature) -> Self {
        Self { sig, typ: EcdsaSighashType::All }
    }
}

/// The commitment type, based on the negotiated option
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommitmentType {
    /// No longer used - dynamic to-remote key
    /// DEPRECATED
    Legacy,
    /// Static to-remote key
    StaticRemoteKey,
    /// Anchors
    /// DEPRECATED
    Anchors,
    /// Anchors, zero fee htlc
    AnchorsZeroFeeHtlc,
}

/// The negotiated parameters for the [Channel]
#[serde_as]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelSetup {
    /// Whether the channel is outbound
    pub is_outbound: bool,
    /// The total the channel was funded with
    pub channel_value_sat: u64,
    // DUP keys.inner.channel_value_satoshis
    /// How much was pushed to the counterparty
    pub push_value_msat: u64,
    /// The funding outpoint
    #[serde_as(as = "IfIsHumanReadable<OutPointReversedDef>")]
    pub funding_outpoint: OutPoint,
    /// locally imposed requirement on the remote commitment transaction to_self_delay
    pub holder_selected_contest_delay: u16,
    /// The holder's optional upfront shutdown script
    #[serde_as(as = "IfIsHumanReadable<Option<ScriptDef>>")]
    pub holder_shutdown_script: Option<ScriptBuf>,
    /// The counterparty's basepoints and pubkeys
    #[serde_as(as = "ChannelPublicKeysDef")]
    pub counterparty_points: ChannelPublicKeys,
    // DUP keys.inner.remote_channel_pubkeys
    /// remotely imposed requirement on the local commitment transaction to_self_delay
    pub counterparty_selected_contest_delay: u16,
    /// The counterparty's optional upfront shutdown script
    #[serde_as(as = "IfIsHumanReadable<Option<ScriptDef>>")]
    pub counterparty_shutdown_script: Option<ScriptBuf>,
    /// The negotiated commitment type
    pub commitment_type: CommitmentType,
}

// Need to define manually because ChannelPublicKeys doesn't derive Debug.
impl fmt::Debug for ChannelSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelSetup")
            .field("is_outbound", &self.is_outbound)
            .field("channel_value_sat", &self.channel_value_sat)
            .field("push_value_msat", &self.push_value_msat)
            .field("funding_outpoint", &self.funding_outpoint)
            .field("holder_selected_contest_delay", &self.holder_selected_contest_delay)
            .field("holder_shutdown_script", &self.holder_shutdown_script)
            .field("counterparty_points", log_channel_public_keys!(&self.counterparty_points))
            .field("counterparty_selected_contest_delay", &self.counterparty_selected_contest_delay)
            .field("counterparty_shutdown_script", &self.counterparty_shutdown_script)
            .field("commitment_type", &self.commitment_type)
            .finish()
    }
}

impl ChannelSetup {
    /// True if this channel uses static to_remote key
    pub fn is_static_remotekey(&self) -> bool {
        self.commitment_type != CommitmentType::Legacy
    }

    /// True if this channel uses anchors
    pub fn is_anchors(&self) -> bool {
        self.commitment_type == CommitmentType::Anchors
            || self.commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    }

    /// True if this channel uses zero fee htlc with anchors
    pub fn is_zero_fee_htlc(&self) -> bool {
        self.commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    }

    /// Convert the channel type to a ChannelTypeFeatures
    pub fn features(&self) -> ChannelTypeFeatures {
        let mut features = ChannelTypeFeatures::empty();
        features.set_static_remote_key_required();
        if self.is_anchors() {
            if self.is_zero_fee_htlc() {
                features.set_anchors_zero_fee_htlc_tx_optional();
            } else {
                features.set_anchors_nonzero_fee_htlc_tx_optional();
            }
        }
        features
    }
}

#[derive(Debug)]
/// Channel slot information for stubs and channels.
pub enum SlotInfoVariant {
    /// Information for stubs
    StubInfo {
        /// The blockheight that the stub will be pruned
        pruneheight: u32,
    },
    /// Information for channels
    ChannelInfo {
        /// The channel's funding outpoint
        funding: Option<OutPoint>,
        /// The channel balance
        balance: ChannelBalance,
        /// Has the node has forgotten this channel?
        forget_seen: bool,
        /// Description of the state of this channel
        diagnostic: String,
    },
}

#[derive(Debug)]
/// Per-channel-slot summary information for system monitoring
pub struct SlotInfo {
    /// An ordinal identifier
    pub oid: u64,
    /// The channel id
    pub id: ChannelId,
    /// Stub and Channel specific data
    pub slot: SlotInfoVariant,
}

/// A trait implemented by both channel states.  See [ChannelSlot]
pub trait ChannelBase: Any {
    /// Get the channel basepoints and public keys
    fn get_channel_basepoints(&self) -> ChannelPublicKeys;
    /// Get the LDK channel-keys id. Available before the channel is fully set up (i.e. on a stub).
    fn get_channel_keys_id(&self) -> [u8; 32];
    /// Whether this is a fully set-up channel (`true`) rather than a stub (`false`).
    fn is_ready(&self) -> bool;
    /// Get the per-commitment point for a holder commitment transaction.
    /// Errors if the commitment number is too high given the current state.
    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status>;
    /// Get the per-commitment secret for a holder commitment transaction
    /// Errors if the commitment number is not ready to be revoked given the current state.
    fn get_per_commitment_secret(&self, commitment_number: u64) -> Result<SecretKey, Status>;
    /// Get the per-commitment secret or None if the arg is out of range
    fn get_per_commitment_secret_or_none(&self, commitment_number: u64) -> Option<SecretKey>;
    /// Check a future secret to support `option_data_loss_protect`
    fn check_future_secret(&self, commit_num: u64, suggested: &SecretKey) -> Result<bool, Status>;
    /// Returns the validator for this channel
    fn validator(&self) -> Arc<dyn Validator>;
    /// Channel information for logging
    fn chaninfo(&self) -> SlotInfo;

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    fn set_next_holder_commit_num_for_testing(&mut self, _num: u64) {
        // Do nothing for ChannelStub.  Channel will override.
    }
}

/// A channel can be in two states - before [Node::setup_channel] it's a
/// [ChannelStub], afterwards it's a [Channel].  This enum keeps track
/// of the two different states.
#[derive(Debug, Clone)]
pub enum ChannelSlot {
    /// Initial state, not ready
    Stub(ChannelStub),
    /// Ready after negotiation is complete
    Ready(Channel),
}

impl ChannelSlot {
    /// The initial channel ID
    pub fn id(&self) -> ChannelId {
        match self {
            ChannelSlot::Stub(stub) => stub.id0.clone(),
            ChannelSlot::Ready(chan) => chan.id0.clone(),
        }
    }

    /// The basepoints
    pub fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        match self {
            ChannelSlot::Stub(stub) => stub.get_channel_basepoints(),
            ChannelSlot::Ready(chan) => chan.get_channel_basepoints(),
        }
    }

    /// Assume this is a channel stub, and return it.
    /// Panics if it's not.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn unwrap_stub(&self) -> &ChannelStub {
        match self {
            ChannelSlot::Stub(stub) => stub,
            ChannelSlot::Ready(_) => panic!("unwrap_stub called on ChannelSlot::Ready"),
        }
    }

    /// Log channel information
    pub fn chaninfo(&self) -> SlotInfo {
        match self {
            ChannelSlot::Stub(stub) => stub.chaninfo(),
            ChannelSlot::Ready(chan) => chan.chaninfo(),
        }
    }
}

/// A channel takes this form after [Node::new_channel], and before [Node::setup_channel]
#[derive(Clone)]
pub struct ChannelStub {
    /// A backpointer to the node
    pub node: Weak<Node>,
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: VlsChannelSigner,
    /// The payment key for sweeping to-remote outputs.
    pub(crate) payment_key: SecretKey,
    // Incomplete, channel_value_sat is placeholder.
    /// The initial channel ID, used to find the channel in the node
    pub id0: ChannelId,
    /// Blockheight when created
    pub blockheight: u32,
}

impl fmt::Debug for ChannelStub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelStub").field("keys", &self.keys).field("id0", &self.id0).finish()
    }
}

impl ChannelBase for ChannelStub {
    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys(&self.secp_ctx).clone()
    }

    fn get_channel_keys_id(&self) -> [u8; 32] {
        self.keys.channel_keys_id()
    }

    fn is_ready(&self) -> bool {
        false
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status> {
        // LDK 0.2 eagerly fetches commitment point N+1 in `HolderCommitmentPoint::advance`,
        // which is invoked when handling funding_created/funding_signed (see
        // `Channel::accept_funding_*` in lightning/src/ln/channel.rs). That happens before
        // channel_ready, while we are still a stub here, so 2 must be reachable.
        if ![0, 1, 2].contains(&commitment_number) {
            return Err(policy_error(
                "policy-optional-fail-fast",
                format!(
                    "channel stub can only return point for commitment number zero, one, or two"
                ),
            )
            .into());
        }
        Ok(self
            .keys
            .get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - commitment_number, &self.secp_ctx)
            .unwrap())
    }

    fn get_per_commitment_secret(&self, _commitment_number: u64) -> Result<SecretKey, Status> {
        // We can't release a commitment_secret from a ChannelStub ever.
        Err(policy_error(
            "policy-revoke-new-commitment-valid",
            format!("channel stub cannot release commitment secret"),
        )
        .into())
    }

    fn get_per_commitment_secret_or_none(&self, _commitment_number: u64) -> Option<SecretKey> {
        None
    }

    fn check_future_secret(
        &self,
        commitment_number: u64,
        suggested: &SecretKey,
    ) -> Result<bool, Status> {
        let secret_data = self
            .keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
            .unwrap();
        Ok(suggested[..] == secret_data)
    }

    fn validator(&self) -> Arc<dyn Validator> {
        let node = self.get_node();
        let v = node.validator_factory().make_validator(
            node.network(),
            node.get_id(),
            Some(self.id0.clone()),
        );
        v
    }

    fn chaninfo(&self) -> SlotInfo {
        SlotInfo {
            oid: self.id0.oid(),
            id: self.id0.clone(),
            slot: SlotInfoVariant::StubInfo {
                pruneheight: self.blockheight + CHANNEL_STUB_PRUNE_BLOCKS,
            },
        }
    }
}

impl ChannelStub {
    pub(crate) fn channel_keys(&self) -> (VlsChannelSigner, SecretKey) {
        (self.keys.clone(), self.payment_key)
    }

    fn get_node(&self) -> Arc<Node> {
        // this is safe because the node holds the channel, so it can't be dropped before it
        self.node.upgrade().unwrap()
    }
}

/// After [Node::setup_channel]
#[derive(Clone)]
pub struct Channel {
    /// A backpointer to the node
    pub node: Weak<Node>,
    /// The logger
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: VlsChannelSigner,
    /// The payment key for sweeping to-remote outputs.
    pub(crate) payment_key: SecretKey,
    /// Channel state for policy enforcement purposes
    pub enforcement_state: EnforcementState,
    /// The negotiated channel setup
    pub setup: ChannelSetup,
    /// The initial channel ID
    pub id0: ChannelId,
    /// The optional permanent channel ID
    pub id: Option<ChannelId>,
    /// The chain monitor base
    pub monitor: ChainMonitorBase,
    /// The previous setup while a splice is in flight: CLN sends the
    /// post-splice SetupChannel BEFORE requesting the splice tx
    /// signature (which spends the PREVIOUS funding — the LDK "sign
    /// prev funding" case), and old-funding commitments can still
    /// arrive after the swap (R10: validate against the matched view).
    pub prev_setup: Option<ChannelSetup>,
    /// The confirmed (locked) funding outpoint — recorded by CLN's
    /// hsmd_lock_outpoint after mutual splice_locked (the funding7
    /// funding_locked analogue).
    pub funding_locked: Option<OutPoint>,
}

impl Debug for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("channel")
    }
}

#[derive(Clone)]
struct ClosableHolderCommitment {
    commitment_number: u64,
    info: CommitmentInfo2,
    counterparty_signatures: CommitmentSignatures,
}

impl ChannelBase for Channel {
    // TODO move out to impl Channel {} once LDK workaround is removed
    #[cfg(any(test, feature = "test_utils"))]
    fn set_next_holder_commit_num_for_testing(&mut self, num: u64) {
        self.enforcement_state.set_next_holder_commit_num_for_testing(num);
    }

    fn get_channel_keys_id(&self) -> [u8; 32] {
        self.keys.channel_keys_id()
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys(&self.secp_ctx).clone()
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        // The following check is relaxed by +1 because LDK fetches the next commitment point
        // before it calls validate_holder_commitment_tx.
        if commitment_number > next_holder_commit_num + 1 {
            return Err(policy_error(
                "policy-optional-fail-fast",
                format!(
                    "get_per_commitment_point: \
                 commitment_number {} invalid when next_holder_commit_num is {}",
                    commitment_number, next_holder_commit_num,
                ),
            )
            .into());
        }
        Ok(self.get_per_commitment_point_unchecked(commitment_number))
    }

    fn get_per_commitment_secret(&self, commitment_number: u64) -> Result<SecretKey, Status> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        // When we try to release commitment number n, we must have a signature
        // for commitment number `n+1`, so `next_holder_commit_num` must be at least
        // `n+2`.
        // Also, given that we previous validated the commitment tx when we
        // got the counterparty signature for it, then we must have fulfilled
        // policy-revoke-new-commitment-valid
        if commitment_number + 2 > next_holder_commit_num {
            let validator = self.validator();
            policy_err!(
                validator,
                "policy-revoke-new-commitment-signed",
                "cannot revoke commitment_number {} when next_holder_commit_num is {}",
                commitment_number,
                next_holder_commit_num,
            )
        }
        let secret = self
            .keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
            .unwrap();
        Ok(SecretKey::from_slice(&secret).unwrap())
    }

    // Like get_per_commitment_secret but just returns None instead of a
    // policy error if the request is out of range
    fn get_per_commitment_secret_or_none(&self, commitment_number: u64) -> Option<SecretKey> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        if commitment_number + 2 > next_holder_commit_num {
            warn!(
                "get_per_commitment_secret_or_none: called past current revoked holder commitment \
                 implied by next_holder_commit_num: {} + 2 > {}",
                commitment_number, next_holder_commit_num
            );
            None
        } else {
            Some(
                SecretKey::from_slice(
                    &self
                        .keys
                        .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
                        .unwrap(),
                )
                .unwrap(),
            )
        }
    }

    fn check_future_secret(
        &self,
        commitment_number: u64,
        suggested: &SecretKey,
    ) -> Result<bool, Status> {
        let secret_data = self
            .keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
            .unwrap();
        Ok(suggested[..] == secret_data)
    }

    fn validator(&self) -> Arc<dyn Validator> {
        let node = self.get_node();
        let v = node.validator_factory().make_validator(
            self.network(),
            node.get_id(),
            Some(self.id0.clone()),
        );
        v
    }

    fn chaninfo(&self) -> SlotInfo {
        SlotInfo {
            oid: self.id0.oid(),
            id: self.id(),
            slot: SlotInfoVariant::ChannelInfo {
                funding: self.monitor.funding_outpoint(),
                balance: self.balance(),
                forget_seen: self.monitor.forget_seen(),
                diagnostic: self.monitor.diagnostic(self.enforcement_state.channel_closed),
            },
        }
    }
}

impl Channel {
    /// The channel ID
    pub fn id(&self) -> ChannelId {
        self.id.clone().unwrap_or(self.id0.clone())
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_commit_num_for_testing(
        &mut self,
        num: u64,
        current_point: PublicKey,
    ) {
        self.enforcement_state.set_next_counterparty_commit_num_for_testing(num, current_point);
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_revoke_num_for_testing(&mut self, num: u64) {
        self.enforcement_state.set_next_counterparty_revoke_num_for_testing(num);
    }

    pub(crate) fn get_chain_state(&self) -> ChainState {
        self.monitor.as_chain_state()
    }

    /// Get the counterparty's public keys
    pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys {
        &self.setup.counterparty_points
    }

    fn get_per_commitment_point_unchecked(&self, commitment_number: u64) -> PublicKey {
        self.keys
            .get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - commitment_number, &self.secp_ctx)
            .unwrap()
    }

    pub(crate) fn get_counterparty_commitment_point(
        &self,
        commitment_number: u64,
    ) -> Option<PublicKey> {
        let state = &self.enforcement_state;

        let next_commit_num = state.next_counterparty_commit_num;

        // we can supply the counterparty's commitment point for the following cases:
        // - the commitment number is the current or previous one the counterparty signed (we received the point)
        // - the commitment number is older than that (the commitment was revoked and we received the secret)

        if next_commit_num < commitment_number + 1 {
            // in the future, we don't have it
            warn!("asked for counterparty commitment point {} but our next counterparty commitment number is {}",
                commitment_number, next_commit_num);
            None
        } else if next_commit_num == commitment_number + 1 {
            state.current_counterparty_point
        } else if next_commit_num == commitment_number {
            state.previous_counterparty_point
        } else if let Some(secrets) = state.counterparty_secrets.as_ref() {
            let secret = secrets.get_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
            secret.map(|s| {
                PublicKey::from_secret_key(
                    &self.secp_ctx,
                    &SecretKey::from_slice(&s).expect("secret from storage"),
                )
            })
        } else {
            warn!(
                "asked for counterparty commitment point {} but we don't have secrets storage",
                commitment_number
            );
            None
        }
    }
}

// Phase 2
impl Channel {
    // Phase 2
    /// Public for testing purposes
    pub fn make_counterparty_tx_keys(&self, per_commitment_point: &PublicKey) -> TxCreationKeys {
        let holder_points = self.keys.pubkeys(&self.secp_ctx);
        let counterparty_points = self.counterparty_pubkeys();

        self.make_tx_keys(per_commitment_point, counterparty_points, &holder_points)
    }

    pub(crate) fn make_holder_tx_keys(&self, per_commitment_point: &PublicKey) -> TxCreationKeys {
        let holder_points = self.keys.pubkeys(&self.secp_ctx);
        let counterparty_points = self.counterparty_pubkeys();

        self.make_tx_keys(per_commitment_point, &holder_points, counterparty_points)
    }

    fn make_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
        a_points: &ChannelPublicKeys,
        b_points: &ChannelPublicKeys,
    ) -> TxCreationKeys {
        TxCreationKeys::derive_new(
            &self.secp_ctx,
            &per_commitment_point,
            &a_points.delayed_payment_basepoint,
            &a_points.htlc_basepoint,
            &b_points.revocation_basepoint,
            &b_points.htlc_basepoint,
        )
    }

    /// Sign a counterparty commitment transaction after rebuilding it
    /// from the supplied arguments.
    #[instrument(skip(self))]
    pub fn sign_counterparty_commitment_tx_phase2(
        &mut self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(Signature, Vec<Signature>), Status> {
        // Since we didn't have the value at the real open, validate it now.
        let validator = self.validator();
        validator.validate_channel_value(&self.setup)?;

        let info2 = self.build_counterparty_commitment_info(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let mut state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, None, Some(&info2), &self.setup);
        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(None, Some(&info2));

        validator.validate_counterparty_commitment_tx(
            &self.enforcement_state,
            commitment_number,
            &remote_per_commitment_point,
            &self.setup,
            &self.get_chain_state(),
            &info2,
        )?;

        let htlcs = Self::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);

        #[cfg(fuzzing)]
        let htlcs_len = htlcs.len();

        // since we independently re-create the tx, this also performs the
        // policy-commitment-* controls
        let commitment_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );

        let channel_parameters = self.make_channel_parameters();
        #[cfg(not(fuzzing))]
        let (sig, htlc_sigs) = catch_panic!(
            self.keys.sign_counterparty_commitment(
                &channel_parameters,
                &commitment_tx,
                &self.secp_ctx
            ),
            "sign_counterparty_commitment panic {} chantype={:?}",
            self.setup.commitment_type,
        )
        .map_err(|_| internal_error("failed to sign"))?;

        #[cfg(fuzzing)]
        let (sig, htlc_sigs, _) = (
            Signature::from_compact(&[0; 64]).unwrap(),
            vec![Signature::from_compact(&[0; 64]).unwrap(); htlcs_len],
            commitment_tx,
        );

        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, Some(&info2));
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        // Only advance the state if nothing goes wrong.
        validator.set_next_counterparty_commit_num(
            &mut self.enforcement_state,
            commitment_number + 1,
            *remote_per_commitment_point,
            info2.clone(),
        )?;
        self.enforcement_state.counterparty_commitment_funding =
            Some(self.setup.funding_outpoint);

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
            Some(&info2),
        );

        trace_enforcement_state!(self);
        self.persist()?;
        Ok((sig, htlc_sigs))
    }

    // restore node state payments from the current commitment transactions
    pub(crate) fn restore_payments(&self) {
        let node = self.get_node();

        let incoming_payment_summary = self.enforcement_state.incoming_payments_summary(None, None);
        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, None);

        let mut hashes: UnorderedSet<&PaymentHash> = UnorderedSet::new();
        hashes.extend(incoming_payment_summary.keys());
        hashes.extend(outgoing_payment_summary.keys());

        let mut state = node.get_state();

        for hash in hashes {
            let payment = state.payments.entry(*hash).or_insert_with(|| RoutedPayment::new());
            let incoming_sat = incoming_payment_summary.get(hash).map(|a| *a).unwrap_or(0);
            let outgoing_sat = outgoing_payment_summary.get(hash).map(|a| *a).unwrap_or(0);

            let min_incoming_cltv = self
                .enforcement_state
                .current_holder_commit_info
                .as_ref()
                .and_then(|info| {
                    info.received_htlcs
                        .iter()
                        .filter(|h| &h.payment_hash == hash)
                        .map(|h| h.cltv_expiry)
                        .min()
                })
                .or_else(|| {
                    self.enforcement_state.current_counterparty_commit_info.as_ref().and_then(
                        |info| {
                            info.offered_htlcs
                                .iter()
                                .filter(|h| &h.payment_hash == hash)
                                .map(|h| h.cltv_expiry)
                                .min()
                        },
                    )
                });

            let max_outgoing_cltv = self
                .enforcement_state
                .current_holder_commit_info
                .as_ref()
                .and_then(|info| {
                    info.offered_htlcs
                        .iter()
                        .filter(|h| &h.payment_hash == hash)
                        .map(|h| h.cltv_expiry)
                        .max()
                })
                .or_else(|| {
                    self.enforcement_state.current_counterparty_commit_info.as_ref().and_then(
                        |info| {
                            info.received_htlcs
                                .iter()
                                .filter(|h| &h.payment_hash == hash)
                                .map(|h| h.cltv_expiry)
                                .max()
                        },
                    )
                });

            payment.apply(
                &self.id0,
                incoming_sat,
                outgoing_sat,
                min_incoming_cltv,
                max_outgoing_cltv,
            );
        }
    }

    // This function is needed for testing with mutated keys.
    /// Public for testing purposes
    pub fn make_counterparty_commitment_tx_with_keys(
        &self,
        per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_counterparty_broadcastable();
        CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            per_commitment_point,
            to_counterparty_value_sat,
            to_holder_value_sat,
            feerate_per_kw,
            htlcs,
            &parameters,
            &self.secp_ctx,
        )
    }

    /// Public for testing purposes
    pub fn make_counterparty_commitment_tx(
        &self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_counterparty_broadcastable();
        CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            remote_per_commitment_point,
            to_counterparty_value_sat,
            to_holder_value_sat,
            feerate_per_kw,
            htlcs,
            &parameters,
            &self.secp_ctx,
        )
    }

    #[instrument(skip(self))]
    fn check_holder_tx_signatures(
        &self,
        per_commitment_point: &PublicKey,
        txkeys: &TxCreationKeys,
        feerate_per_kw: u32,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
        recomposed_tx: CommitmentTransaction,
    ) -> Result<(), Status> {
        let redeemscript = make_funding_redeemscript(
            &self.keys.pubkeys(&self.secp_ctx).funding_pubkey,
            &self.setup.counterparty_points.funding_pubkey,
        );

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_digest(
            SighashCache::new(&recomposed_tx.trust().built_transaction().transaction)
                .p2wsh_signature_hash(
                    0,
                    &redeemscript,
                    Amount::from_sat(self.setup.channel_value_sat),
                    EcdsaSighashType::All,
                )
                .unwrap()
                .to_byte_array(),
        );

        self.secp_ctx
            .verify_ecdsa(
                &sighash,
                &counterparty_commit_sig,
                &self.setup.counterparty_points.funding_pubkey,
            )
            .map_err(|ve| {
                policy_error(
                    "policy-revoke-new-commitment-signed",
                    format!("commit sig verify failed: {}", ve),
                )
            })?;

        let commitment_txid = recomposed_tx.trust().txid();
        let to_self_delay = self.setup.counterparty_selected_contest_delay;

        let htlc_pubkey = derive_public_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.counterparty_pubkeys().htlc_basepoint.0,
        )
        .map_err(|err| internal_error(format!("derive_public_key failed: {}", err)))?;

        let sig_hash_type = if self.setup.is_anchors() {
            EcdsaSighashType::SinglePlusAnyoneCanPay
        } else {
            EcdsaSighashType::All
        };

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { feerate_per_kw };

        let features = self.setup.features();

        for ndx in 0..recomposed_tx.nondust_htlcs().len() {
            let htlc = &recomposed_tx.nondust_htlcs()[ndx];

            let htlc_redeemscript = get_htlc_redeemscript(htlc, &features, &txkeys);

            let features = self.setup.features();

            // policy-onchain-format-standard
            let recomposed_htlc_tx = catch_panic!(
                build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    to_self_delay,
                    htlc,
                    &features,
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                ),
                "build_htlc_transaction panic {} chantype={:?}",
                self.setup.commitment_type
            );

            // unwrap is safe because we just created the tx and it's well formed
            let recomposed_tx_sighash = Message::from_digest(
                SighashCache::new(&recomposed_htlc_tx)
                    .p2wsh_signature_hash(
                        0,
                        &htlc_redeemscript,
                        Amount::from_sat(htlc.amount_msat / 1000),
                        sig_hash_type,
                    )
                    .unwrap()
                    .to_byte_array(),
            );

            self.secp_ctx
                .verify_ecdsa(&recomposed_tx_sighash, &counterparty_htlc_sigs[ndx], &htlc_pubkey)
                .map_err(|err| {
                    policy_error(
                        "policy-revoke-new-commitment-signed",
                        format!("commit sig verify failed for htlc {}: {}", ndx, err),
                    )
                })?;
        }
        Ok(())
    }

    // Advance the holder commitment state so that `N + 1` is the next
    // and `N - 1` is revoked, where N is `new_current_commitment_number`.
    fn advance_holder_commitment_state(
        &mut self,
        validator: Arc<dyn Validator>,
        new_current_commitment_number: u64,
        info2: CommitmentInfo2,
        counterparty_signatures: CommitmentSignatures,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        // Advance the local commitment number state.
        validator.set_next_holder_commit_num(
            &mut self.enforcement_state,
            new_current_commitment_number + 1,
            info2,
            counterparty_signatures,
        )?;

        self.release_commitment_secret(new_current_commitment_number)
    }

    // Gets the revocation return values for a previous commitments which are
    // ready to be released (fails on future commitments)
    fn release_commitment_secret(
        &mut self,
        commitment_number: u64,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        let next_holder_commitment_point = self.get_per_commitment_point(commitment_number + 1)?;
        let maybe_old_secret = if commitment_number >= 1 {
            // this will fail if the secret is not ready to be released
            Some(self.get_per_commitment_secret(commitment_number - 1)?)
        } else {
            None
        };
        Ok((next_holder_commitment_point, maybe_old_secret))
    }

    /// Validate the counterparty's signatures on the holder's
    /// commitment and HTLCs when the commitment_signed message is
    /// received.
    pub fn validate_holder_commitment_tx_phase2(
        &mut self,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
    ) -> Result<(), Status> {
        let per_commitment_point = &self.get_per_commitment_point(commitment_number)?;
        let info2 = self.build_holder_commitment_info(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &self.setup);

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);

        let validator = self.validator();
        validator
            .validate_holder_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                warn!(
                    "VALIDATION FAILED: {} setup={:?} state={:?} info={:?}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                warn!(
                    "VALIDATION FAILED: {}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs = Self::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);

        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        // policy-commitment-*
        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &per_commitment_point,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );

        #[cfg(not(fuzzing))]
        self.check_holder_tx_signatures(
            &per_commitment_point,
            &txkeys,
            feerate_per_kw,
            counterparty_commit_sig,
            counterparty_htlc_sigs,
            recomposed_tx,
        )?;

        #[cfg(fuzzing)]
        let _ = recomposed_tx;

        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        if commitment_number == self.enforcement_state.next_holder_commit_num
            || self.enforcement_state.holder_commitment_funding
                != Some(self.setup.funding_outpoint)
        {
            let counterparty_signatures = CommitmentSignatures(
                counterparty_commit_sig.clone(),
                counterparty_htlc_sigs.to_vec(),
            );
            self.enforcement_state.next_holder_commit_info = Some((info2, counterparty_signatures));
            self.enforcement_state.holder_commitment_funding =
                Some(self.setup.funding_outpoint);
        }

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(())
    }

    /// Revoke holder commitment `N - 1` by disclosing its commitment secret.
    /// After this, `N` is the current holder commitment and `N + 1`
    /// is the next holder commitment.
    ///
    /// Returns the per_commitment_point for commitment `N + 1` and the
    /// holder's revocation secret for commitment `N - 1` if `N > 0`.
    ///
    /// [`validate_holder_commitment_tx`] (or the phase2 version) must be called
    /// before this method.
    ///
    /// The node should have persisted this state change first, because we cannot
    /// safely roll back a revocation.
    pub fn revoke_previous_holder_commitment(
        &mut self,
        new_current_commitment_number: u64,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        // If we are called on anything other than the next_holder_commit_num
        // with existing next_holder_commit_info we must not change any state
        if new_current_commitment_number != self.enforcement_state.next_holder_commit_num {
            return Ok(self.release_commitment_secret(new_current_commitment_number)?);
            // don't persist, this case doesn't change state
        }

        let validator = self.validator();

        if self.enforcement_state.next_holder_commit_info.is_none() {
            // the caller failed to call validate_holder_commitment_tx
            policy_err!(
                validator,
                "policy-revoke-new-commitment-signed",
                "new_current_commitment == next_holder_commit_num {} \
                 but next_holder_commit_info.is_none",
                new_current_commitment_number,
            );
            // `policy_err!` will not return an error in permissive mode, so we need to return
            // something plausible here.  The node will likely crash soon after, because we will
            // not return a revocation secret (`None` below).
            // That's OK, because the node should have called `validate_holder_commitment_tx` first
            // so the logic error is in the node.
            let holder_commitment_point =
                self.get_per_commitment_point(new_current_commitment_number)?;
            return Ok((holder_commitment_point, None));
        }

        // checked above
        let (info2, sigs) = self.enforcement_state.next_holder_commit_info.take().unwrap();
        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);
        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);

        let node = self.get_node();
        let mut state = node.get_state();

        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &self.setup);

        let (next_holder_commitment_point, maybe_old_secret) = self
            .advance_holder_commitment_state(
                validator.clone(),
                new_current_commitment_number,
                info2.clone(),
                sigs,
            )?;

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
            Some(&info2),
        );

        trace_enforcement_state!(self);
        self.persist()?;
        Ok((next_holder_commitment_point, maybe_old_secret))
    }

    fn get_holder_commitment_for_close(
        &mut self,
        commitment_number: u64,
    ) -> Result<ClosableHolderCommitment, Status> {
        if commitment_number == self.enforcement_state.next_holder_commit_num {
            if let Some((info, counterparty_signatures)) =
                &self.enforcement_state.next_holder_commit_info
            {
                info!("closing with pending-next holder commitment {}", commitment_number);

                return Ok(ClosableHolderCommitment {
                    commitment_number,
                    info: info.clone(),
                    counterparty_signatures: counterparty_signatures.clone(),
                });
            }
        }

        info!("closing with current holder commitment {}", commitment_number);
        let validator = self.validator();
        let info = validator
            .get_current_holder_commitment_info(&mut self.enforcement_state, commitment_number)?;
        let counterparty_signatures = self
            .enforcement_state
            .current_counterparty_signatures
            .clone()
            .ok_or_else(|| internal_error("channel not open: counterparty sigs missing"))?;

        Ok(ClosableHolderCommitment { commitment_number, info, counterparty_signatures })
    }

    fn get_latest_holder_commitment_for_close(
        &mut self,
    ) -> Result<ClosableHolderCommitment, Status> {
        let commitment_number = if self.enforcement_state.next_holder_commit_info.is_some() {
            self.enforcement_state.next_holder_commit_num
        } else {
            self.enforcement_state
                .next_holder_commit_num
                .checked_sub(1)
                .ok_or_else(|| internal_error("channel was not open: commit info missing"))?
        };

        self.get_holder_commitment_for_close(commitment_number)
    }

    fn recompose_holder_commitment_tx(
        &self,
        commitment_number: u64,
        info2: &CommitmentInfo2,
    ) -> Result<(CommitmentTransaction, PublicKey, TxCreationKeys), Status> {
        let htlcs = Self::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { info2.feerate_per_kw };
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        // policy-onchain-format-standard
        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &per_commitment_point,
            build_feerate,
            info2.to_broadcaster_value_sat,
            info2.to_countersigner_value_sat,
            htlcs,
        );

        Ok((recomposed_tx, per_commitment_point, txkeys))
    }

    /// Sign a holder commitment when force-closing
    pub fn sign_holder_commitment_tx_phase2(
        &mut self,
        commitment_number: u64,
    ) -> Result<Signature, Status> {
        // We sign the current holder commitment, or the already-validated
        // pending next holder commitment, while checking that the commitment
        // number supplied by the caller is in sync with the close selector.
        //
        // policy-commitment-holder-not-revoked is implicitly checked by
        // the fact that the current holder commitment info in the enforcement
        // state cannot have been revoked.
        let holder_commitment = self.get_holder_commitment_for_close(commitment_number)?;
        let (recomposed_tx, _per_commitment_point, _txkeys) = self.recompose_holder_commitment_tx(
            holder_commitment.commitment_number,
            &holder_commitment.info,
        )?;

        // We provide a dummy signature for the remote, since we don't require that sig
        // to be passed in to this call.  It would have been better if HolderCommitmentTransaction
        // didn't require the remote sig.
        // TODO(516) remove dummy sigs here and in phase 2 protocol
        let htlcs_len = recomposed_tx.nondust_htlcs().len();
        let mut htlc_dummy_sigs = Vec::with_capacity(htlcs_len);
        htlc_dummy_sigs.resize(htlcs_len, Self::dummy_sig());

        // Holder commitments need an extra wrapper for the LDK signature routine.
        let recomposed_holder_tx = HolderCommitmentTransaction::new(
            recomposed_tx,
            Self::dummy_sig(),
            htlc_dummy_sigs,
            &self.keys.pubkeys(&self.secp_ctx).funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );

        // Sign the recomposed commitment.
        let node = self.get_node();
        let sig = self
            .keys
            .sign_holder_commitment(
                &self.make_channel_parameters(),
                &recomposed_holder_tx,
                node.get_entropy_source(),
                &self.secp_ctx,
            )
            .map_err(|_| internal_error("failed to sign"))?;

        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok(sig)
    }

    /// Reconstruct the current holder commitment transaction without signing it.
    pub fn get_current_holder_commitment_transaction(
        &self,
    ) -> Result<CommitmentTransaction, Status> {
        let info2 = self
            .enforcement_state
            .current_holder_commit_info
            .as_ref()
            .ok_or_else(|| internal_error("channel was not open - commit info missing"))?;

        let commitment_number = self.enforcement_state.next_holder_commit_num - 1;
        let (recomposed_tx, _, _) =
            self.recompose_holder_commitment_tx(commitment_number, info2)?;

        Ok(recomposed_tx)
    }

    /// Sign a holder commitment and HTLCs when recovering from node failure.
    ///
    /// Also returns the revocable scriptPubKey so we can identify our outputs
    /// and the unilateral close key material.
    ///
    /// The `spent_htlc_indices` parameter allows skipping already-spent HTLCs
    /// to avoid building invalid transactions during repeated recovery attempts.
    pub fn sign_holder_commitment_tx_for_recovery(
        &mut self,
        spent_htlc_indices: &[bool],
        chain_height_override: Option<u32>,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        self.sign_holder_commitment_tx_for_recovery_inner(
            spent_htlc_indices,
            true,
            chain_height_override,
        )
    }

    /// Sign a holder commitment and HTLCs for a recovery dry-run.
    ///
    /// This builds and signs the same transactions as
    /// [`Self::sign_holder_commitment_tx_for_recovery`], but does not mark the
    /// channel closed or persist channel-closed state.
    pub fn sign_holder_commitment_tx_for_recovery_dry_run(
        &mut self,
        spent_htlc_indices: &[bool],
        chain_height_override: Option<u32>,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        self.sign_holder_commitment_tx_for_recovery_inner(
            spent_htlc_indices,
            false,
            chain_height_override,
        )
    }

    fn sign_holder_commitment_tx_for_recovery_inner(
        &mut self,
        spent_htlc_indices: &[bool],
        persist_close: bool,
        chain_height_override: Option<u32>,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        let holder_commitment = self.get_latest_holder_commitment_for_close()?;
        let CommitmentSignatures(counterparty_commit_sig, counterparty_htlc_sigs) =
            holder_commitment.counterparty_signatures;
        let commitment_number = holder_commitment.commitment_number;
        warn!("force-closing channel for recovery at commitment number {}", commitment_number);

        let (recomposed_tx, per_commitment_point, txkeys) =
            self.recompose_holder_commitment_tx(commitment_number, &holder_commitment.info)?;
        // Holder commitments need an extra wrapper for the LDK signature routine.
        let recomposed_holder_tx = HolderCommitmentTransaction::new(
            recomposed_tx,
            counterparty_commit_sig.clone(),
            counterparty_htlc_sigs.clone(),
            &self.keys.pubkeys(&self.secp_ctx).funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );

        // Sign the recomposed commitment.
        let node = self.get_node();
        let sig = self
            .keys
            .sign_holder_commitment(
                &self.make_channel_parameters(),
                &recomposed_holder_tx,
                node.get_entropy_source(),
                &self.secp_ctx,
            )
            .map_err(|_| internal_error("failed to sign"))?;

        let holder_tx = recomposed_holder_tx.trust();
        let mut tx = holder_tx.built_transaction().transaction.clone();
        let holder_funding_key = self.keys.pubkeys(&self.secp_ctx).funding_pubkey;
        let counterparty_funding_key = self.counterparty_pubkeys().funding_pubkey;

        let tx_keys = holder_tx.keys();
        let revocable_redeemscript = chan_utils::get_revokeable_redeemscript(
            &tx_keys.revocation_key,
            self.setup.counterparty_selected_contest_delay,
            &tx_keys.broadcaster_delayed_payment_key,
        );

        add_holder_sig(
            &mut tx,
            sig,
            counterparty_commit_sig,
            &holder_funding_key,
            &counterparty_funding_key,
        );

        let commitment_txid = tx.compute_txid();
        let htlc_txs = self.sign_holder_htlc_txs_for_recovery(
            &holder_tx,
            &commitment_txid,
            &txkeys,
            &counterparty_htlc_sigs,
            spent_htlc_indices,
            chain_height_override,
        )?;

        if persist_close {
            self.enforcement_state.channel_closed = true;
            trace_enforcement_state!(self);
        }

        let revocation_basepoint = self.counterparty_pubkeys().revocation_basepoint;
        let revocation_pubkey = derive_public_revocation_key(
            &self.secp_ctx,
            &per_commitment_point,
            &revocation_basepoint,
        )
        .map_err(|_| internal_error("failure during derive_public_revocation_key"))?;
        let ck =
            self.get_unilateral_close_key(&Some(per_commitment_point), &Some(revocation_pubkey))?;

        if persist_close {
            self.persist()?;
        }
        Ok((tx, htlc_txs, revocable_redeemscript.to_p2wsh(), ck, revocation_pubkey.0))
    }

    /// Sign HTLC transactions for recovery.
    ///
    /// For AnchorsZeroFeeHtlc channels, transactions have zero fees and use
    /// SIGHASH_SINGLE|SIGHASH_ANYONECANPAY, allowing fee inputs to be added later.
    ///
    /// For AnchorsZeroFeeHtlc channels, compatible HTLCs are batched to reduce
    /// on-chain footprint and fees:
    /// - All received HTLCs are batched into one transaction (no timelock constraint)
    /// - Offered HTLCs are batched by CLTV expiry (each group shares the same locktime)
    ///
    /// For StaticRemoteKey channels, HTLC signatures use SIGHASH_ALL, so each
    /// HTLC claim remains a separate one-input transaction.
    ///
    /// Only returns HTLCs that are currently claimable (skips unexpired or missing preimages).
    fn sign_holder_htlc_txs_for_recovery(
        &self,
        holder_tx: &TrustedCommitmentTransaction,
        commitment_txid: &Txid,
        txkeys: &TxCreationKeys,
        cp_htlc_sigs: &[Signature],
        spent_htlc_indices: &[bool],
        chain_height_override: Option<u32>,
    ) -> Result<Vec<Transaction>, Status> {
        let commitment_number = self.enforcement_state.next_holder_commit_num - 1;
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
        let features = self.setup.features();
        let node = self.get_node();
        let current_height =
            chain_height_override.unwrap_or_else(|| self.get_chain_state().current_height);
        let htlc_feerate_per_kw =
            if self.setup.is_zero_fee_htlc() { 0 } else { holder_tx.negotiated_feerate_per_kw() };

        let htlc_count = holder_tx.nondust_htlcs().len();
        if spent_htlc_indices.len() != htlc_count {
            return Err(invalid_argument(format!(
                "spent_htlc_indices length mismatch: {} != {}",
                spent_htlc_indices.len(),
                htlc_count
            )));
        }

        let mut received_htlcs = Vec::new();
        let mut offered_by_cltv: OrderedMap<u32, Vec<_>> = OrderedMap::new();
        for (htlc_idx, htlc) in holder_tx.nondust_htlcs().iter().enumerate() {
            if htlc.transaction_output_index.is_none() {
                continue;
            }

            if spent_htlc_indices[htlc_idx] {
                continue;
            }

            if htlc.offered {
                if htlc.cltv_expiry > current_height {
                    continue;
                }
                offered_by_cltv.entry(htlc.cltv_expiry).or_default().push((htlc_idx, htlc));
            } else {
                let preimage = {
                    let state = node.get_state();
                    state.payments.get(&htlc.payment_hash).and_then(|p| p.preimage)
                };

                if preimage.is_none() {
                    continue;
                }
                received_htlcs.push((htlc_idx, htlc, preimage));
            }
        }
        let mut signed_htlc_txs = Vec::new();

        if self.setup.is_zero_fee_htlc() {
            if !received_htlcs.is_empty() {
                debug!("batching {} received HTLCs into single transaction", received_htlcs.len());
                signed_htlc_txs.push(self.build_and_sign_batched_htlc_tx(
                    commitment_txid,
                    txkeys,
                    &features,
                    commitment_number,
                    per_commitment_point,
                    cp_htlc_sigs,
                    &received_htlcs,
                    0,
                    htlc_feerate_per_kw,
                )?);
            }

            for (cltv, htlcs) in offered_by_cltv {
                debug!(
                    "batching {} offered HTLCs with CLTV {} into single transaction",
                    htlcs.len(),
                    cltv
                );

                let htlcs_to_sign: Vec<_> =
                    htlcs.into_iter().map(|(idx, htlc)| (idx, htlc, None)).collect();

                signed_htlc_txs.push(self.build_and_sign_batched_htlc_tx(
                    commitment_txid,
                    txkeys,
                    &features,
                    commitment_number,
                    per_commitment_point,
                    cp_htlc_sigs,
                    &htlcs_to_sign,
                    cltv,
                    htlc_feerate_per_kw,
                )?);
            }
        } else {
            for htlc in received_htlcs {
                signed_htlc_txs.push(self.build_and_sign_batched_htlc_tx(
                    commitment_txid,
                    txkeys,
                    &features,
                    commitment_number,
                    per_commitment_point,
                    cp_htlc_sigs,
                    &[htlc],
                    0,
                    htlc_feerate_per_kw,
                )?);
            }

            for (cltv, htlcs) in offered_by_cltv {
                for (htlc_idx, htlc) in htlcs {
                    signed_htlc_txs.push(self.build_and_sign_batched_htlc_tx(
                        commitment_txid,
                        txkeys,
                        &features,
                        commitment_number,
                        per_commitment_point,
                        cp_htlc_sigs,
                        &[(htlc_idx, htlc, None)],
                        cltv,
                        htlc_feerate_per_kw,
                    )?);
                }
            }
        }

        Ok(signed_htlc_txs)
    }

    fn build_and_sign_batched_htlc_tx(
        &self,
        commitment_txid: &Txid,
        txkeys: &TxCreationKeys,
        features: &ChannelTypeFeatures,
        commitment_number: u64,
        per_commitment_point: PublicKey,
        cp_htlc_sigs: &[Signature],
        htlcs: &[(usize, &HTLCOutputInCommitment, Option<PaymentPreimage>)],
        lock_time: u32,
        feerate_per_kw: u32,
    ) -> Result<Transaction, Status> {
        let channel_derivation_parameters = ChannelDerivationParameters {
            value_satoshis: self.setup.channel_value_sat,
            keys_id: self.keys.channel_keys_id(),
            transaction_parameters: self.make_channel_parameters().clone(),
        };

        struct HTLCSigningData {
            htlc_idx: usize,
            htlc: HTLCOutputInCommitment,
            preimage: Option<PaymentPreimage>,
            cp_sig: Signature,
            redeemscript: ScriptBuf,
            input: bitcoin::TxIn,
            output: bitcoin::TxOut,
        }

        let mut signing_data: Vec<HTLCSigningData> = Vec::with_capacity(htlcs.len());

        for (htlc_idx, htlc, preimage) in htlcs {
            let htlc_tx = build_htlc_transaction(
                commitment_txid,
                feerate_per_kw,
                self.setup.counterparty_selected_contest_delay,
                htlc,
                features,
                &txkeys.broadcaster_delayed_payment_key,
                &txkeys.revocation_key,
            );

            let cp_sig = cp_htlc_sigs
                .get(*htlc_idx)
                .ok_or_else(|| {
                    internal_error(format!(
                "missing counterparty sig for htlc {} (output_index: {:?}, cp_sigs_len: {})",
                htlc_idx,
                htlc.transaction_output_index,
                cp_htlc_sigs.len()
            ))
                })?
                .clone();

            signing_data.push(HTLCSigningData {
                htlc_idx: *htlc_idx,
                htlc: (*htlc).clone(),
                preimage: *preimage,
                cp_sig,
                redeemscript: get_htlc_redeemscript(htlc, features, txkeys),
                input: htlc_tx.input[0].clone(),
                output: htlc_tx.output[0].clone(),
            });
        }

        let mut batched_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_height(lock_time).map_err(|_| {
                internal_error(format!("invalid CLTV height locktime: {}", lock_time))
            })?,
            input: signing_data.iter().map(|sd| sd.input.clone()).collect(),
            output: signing_data.iter().map(|sd| sd.output.clone()).collect(),
        };

        for (i, sd) in signing_data.iter().enumerate() {
            let htlc_descriptor = HTLCDescriptor {
                channel_derivation_parameters: channel_derivation_parameters.clone(),
                commitment_txid: *commitment_txid,
                per_commitment_number: commitment_number,
                per_commitment_point,
                feerate_per_kw,
                htlc: sd.htlc.clone(),
                preimage: sd.preimage,
                counterparty_sig: sd.cp_sig.clone(),
            };

            let node = self.get_node();
            let holder_sig = self
                .keys
                .sign_holder_htlc_transaction(
                    &batched_tx,
                    i,
                    &htlc_descriptor,
                    node.get_entropy_source(),
                    &self.secp_ctx,
                )
                .map_err(|e| {
                    internal_error(format!(
                        "HTLC recovery signing failed at idx {} (offered: {}, output: {:?}): {:?}",
                        sd.htlc_idx, sd.htlc.offered, sd.htlc.transaction_output_index, e
                    ))
                })?;

            batched_tx.input[i].witness = build_htlc_input_witness(
                &holder_sig,
                &sd.cp_sig,
                &sd.preimage,
                &sd.redeemscript,
                features,
            );
        }

        Ok(batched_tx)
    }

    pub(crate) fn make_holder_commitment_tx(
        &self,
        commitment_number: u64,
        per_commitment_point: &PublicKey,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();
        let mut commitment_tx = CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            per_commitment_point,
            to_holder_value_sat,
            to_counterparty_value_sat,
            feerate_per_kw,
            htlcs,
            &parameters,
            &self.secp_ctx,
        );
        if self.setup.is_anchors() {
            commitment_tx = commitment_tx.with_non_zero_fee_anchors();
        }
        commitment_tx
    }

    /// Public for testing purposes
    pub fn htlcs_info2_to_oic(
        offered_htlcs: &[HTLCInfo2],
        received_htlcs: &[HTLCInfo2],
    ) -> Vec<HTLCOutputInCommitment> {
        let mut htlcs = Vec::new();
        for htlc in offered_htlcs {
            htlcs.push(HTLCOutputInCommitment {
                offered: true,
                amount_msat: htlc.value_sat * 1000,
                cltv_expiry: htlc.cltv_expiry,
                payment_hash: htlc.payment_hash,
                transaction_output_index: None,
            });
        }
        for htlc in received_htlcs {
            htlcs.push(HTLCOutputInCommitment {
                offered: false,
                amount_msat: htlc.value_sat * 1000,
                cltv_expiry: htlc.cltv_expiry,
                payment_hash: htlc.payment_hash,
                transaction_output_index: None,
            });
        }
        htlcs
    }

    /// Build channel parameters, used to further build a commitment transaction
    pub fn make_channel_parameters(&self) -> ChannelTransactionParameters {
        let funding_outpoint = chain::transaction::OutPoint {
            txid: self.setup.funding_outpoint.txid,
            index: self.setup.funding_outpoint.vout as u16,
        };
        let channel_parameters = ChannelTransactionParameters {
            holder_pubkeys: self.get_channel_basepoints(),
            holder_selected_contest_delay: self.setup.holder_selected_contest_delay,
            is_outbound_from_holder: self.setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: self.setup.counterparty_points.clone(),
                selected_contest_delay: self.setup.counterparty_selected_contest_delay,
            }),
            funding_outpoint: Some(funding_outpoint),
            splice_parent_funding_txid: None,
            channel_type_features: self.setup.features(),
            channel_value_satoshis: self.setup.channel_value_sat,
        };
        channel_parameters
    }

    /// Get the shutdown script where our funds will go when we mutual-close
    // TODO(75) this method is deprecated
    pub fn get_ldk_shutdown_script(&self) -> ScriptBuf {
        self.setup.holder_shutdown_script.clone().unwrap_or_else(|| {
            self.get_node().keys_manager.get_shutdown_scriptpubkey().unwrap().into()
        })
    }

    fn get_node(&self) -> Arc<Node> {
        self.node.upgrade().unwrap()
    }

    /// Sign a mutual close transaction after rebuilding it from the supplied arguments
    /// Sign a splice transaction input with the channel funding key;
    /// CLN's channeld requests this once splice commitments are secured.
    /// Signer-side checks on top of the stock-hsmd trust model: the
    /// counterparty funding key must match the channel's, and the input
    /// must spend the channel's current or previous funding outpoint
    /// (the setup has already swapped by signing time). The psbt amount
    /// is cross-checked when present (the accepter's funding input has
    /// no witness_utxo — the funding's value stands in).
    pub fn sign_splice_tx(
        &self,
        tx: &Transaction,
        input_index: u32,
        remote_funding_key: &PublicKey,
        input_amount_sat: Option<u64>,
    ) -> Result<Signature, Status> {
        if *remote_funding_key != self.setup.counterparty_points.funding_pubkey {
            return Err(Status::invalid_argument("remote funding key mismatch"));
        }
        let input = tx
            .input
            .get(input_index as usize)
            .ok_or_else(|| Status::invalid_argument("splice input index out of range"))?;
        let channel_value_sat =
            if input.previous_output == self.setup.funding_outpoint {
                self.setup.channel_value_sat
            } else if let Some(ref prev_setup) = self.prev_setup {
                if input.previous_output == prev_setup.funding_outpoint {
                    prev_setup.channel_value_sat
                } else {
                    return Err(Status::invalid_argument(
                        "splice input is not the channel funding outpoint",
                    ));
                }
            } else {
                return Err(Status::invalid_argument(
                    "splice input is not the channel funding outpoint",
                ));
            };
        let input_amount_sat = input_amount_sat.unwrap_or(channel_value_sat);
        if input_amount_sat != channel_value_sat {
            return Err(Status::invalid_argument("splice input value is not the channel value"));
        }
        let funding_key = self.keys.funding_key(None);
        let funding_pubkey = PublicKey::from_secret_key(&self.secp_ctx, &funding_key);
        let redeemscript = make_funding_redeemscript(&funding_pubkey, remote_funding_key);
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(
                input_index as usize,
                &redeemscript,
                Amount::from_sat(input_amount_sat),
                EcdsaSighashType::All,
            )
            .map_err(|_| Status::internal("splice sighash failed"))?;
        let sig = self
            .secp_ctx
            .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &funding_key);
        Ok(sig)
    }

    /// The setup view a commitment's transaction targets — matched by
    /// its funding input outpoint: the current (post-splice) funding or
    /// the previous one while a splice is in flight. A commitment
    /// spending neither is not ours.
    pub fn setup_for_tx(&self, tx: &Transaction) -> Result<ChannelSetup, Status> {
        for input in &tx.input {
            if input.previous_output == self.setup.funding_outpoint {
                return Ok(self.setup.clone());
            }
            if let Some(ref prev) = self.prev_setup {
                if input.previous_output == prev.funding_outpoint {
                    return Ok(prev.clone());
                }
            }
        }
        Err(Status::invalid_argument(
            "commitment does not spend a known funding outpoint",
        ))
    }

    /// Splice compatibility (the funding7 `is_compatible` shape): only
    /// the funding identity and balance fields may differ; the
    /// counterparty funding key may rotate; unset shutdown scripts stay
    /// unset. Anything else changing is not a splice.
    pub fn is_splice_compatible(&self, new_setup: &ChannelSetup) -> bool {
        let mut other = new_setup.clone();
        other.counterparty_points.funding_pubkey =
            self.setup.counterparty_points.funding_pubkey.clone();
        if self.setup.holder_shutdown_script.is_none() {
            other.holder_shutdown_script = None;
        }
        if self.setup.counterparty_shutdown_script.is_none() {
            other.counterparty_shutdown_script = None;
        }
        let funding_changed = other.funding_outpoint != self.setup.funding_outpoint;
        other.funding_outpoint = self.setup.funding_outpoint;
        other.channel_value_sat = self.setup.channel_value_sat;
        other.push_value_msat = self.setup.push_value_msat;
        other == self.setup && funding_changed
    }

    /// Record the funding lock (CLN's hsmd_lock_outpoint after mutual
    /// splice_locked). Idempotent; must match the current funding.
    pub fn confirm_funding_locked(&mut self, outpoint: &OutPoint) -> Result<(), Status> {
        if self.funding_locked == Some(*outpoint) {
            return Ok(());
        }
        if *outpoint != self.setup.funding_outpoint {
            return Err(Status::invalid_argument(format!(
                "funding_locked: {} is not the current funding {}",
                outpoint, self.setup.funding_outpoint
            )));
        }
        info!("funding_locked: locking funding outpoint {}", outpoint);
        self.funding_locked = Some(*outpoint);
        // R21 F2: the lock retires the previous funding — clear the
        // splice-window view so late commitments cannot match it
        self.prev_setup = None;
        self.persist()?;
        Ok(())
    }

    pub fn sign_mutual_close_tx_phase2(
        &mut self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<ScriptBuf>,
        counterparty_script: &Option<ScriptBuf>,
        holder_wallet_path_hint: &DerivationPath,
    ) -> Result<Signature, Status> {
        self.validator().validate_mutual_close_tx(
            &*self.get_node(),
            &self.setup,
            &self.enforcement_state,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script,
            counterparty_script,
            holder_wallet_path_hint,
        )?;

        let tx = ClosingTransaction::new(
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script.clone().unwrap_or_else(|| ScriptBuf::new()),
            counterparty_script.clone().unwrap_or_else(|| ScriptBuf::new()),
            self.setup.funding_outpoint,
        );

        let sig = self
            .keys
            .sign_closing_transaction(&self.make_channel_parameters(), &tx, &self.secp_ctx)
            .map_err(|_| Status::internal("failed to sign"))?;
        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok(sig)
    }

    /// Sign a delayed output that goes to us while sweeping a transaction we broadcast
    pub fn sign_delayed_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        commitment_number: u64,
        redeemscript: &Script,
        amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_delayed_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        self.validator().validate_delayed_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            input,
            amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_digest(
            SighashCache::new(tx)
                .p2wsh_signature_hash(
                    input,
                    &redeemscript,
                    Amount::from_sat(amount_sat),
                    EcdsaSighashType::All,
                )
                .unwrap()
                .to_byte_array(),
        );

        let privkey = derive_private_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.keys.delayed_payment_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&sighash, &privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign an offered or received HTLC output from a commitment the counterparty broadcast.
    pub fn sign_counterparty_htlc_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_counterparty_htlc_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }

        self.validator().validate_counterparty_htlc_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            redeemscript,
            input,
            htlc_amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let htlc_sighash = Message::from_digest(
            SighashCache::new(tx)
                .p2wsh_signature_hash(
                    input,
                    &redeemscript,
                    Amount::from_sat(htlc_amount_sat),
                    EcdsaSighashType::All,
                )
                .unwrap()
                .to_byte_array(),
        );

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &remote_per_commitment_point,
            &self.keys.htlc_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&htlc_sighash, &htlc_privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign a justice transaction on an old state that the counterparty broadcast
    pub fn sign_justice_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        revocation_secret: &SecretKey,
        redeemscript: &Script,
        amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_justice_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }
        self.validator().validate_justice_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            input,
            amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_digest(
            SighashCache::new(tx)
                .p2wsh_signature_hash(
                    input,
                    &redeemscript,
                    Amount::from_sat(amount_sat),
                    EcdsaSighashType::All,
                )
                .unwrap()
                .to_byte_array(),
        );

        let privkey = chan_utils::derive_private_revocation_key(
            &self.secp_ctx,
            revocation_secret,
            &self.keys.revocation_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&sighash, &privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign a channel announcement with both the node key and the funding key
    pub fn sign_channel_announcement_with_funding_key(&self, announcement: &[u8]) -> Signature {
        let ann_hash = Sha256dHash::hash(announcement);
        let encmsg = secp256k1::Message::from_digest(ann_hash.to_byte_array());

        self.secp_ctx.sign_ecdsa(&encmsg, &self.keys.funding_key(None))
    }

    fn persist(&self) -> Result<(), Status> {
        let node_id = self.get_node().get_id();
        self.get_node()
            .persister
            .update_channel(&node_id, &self)
            .map_err(|_| Status::internal("persist failed"))
    }

    /// The node's network
    pub fn network(&self) -> Network {
        self.get_node().network()
    }

    /// The node has signed our funding transaction
    pub fn funding_signed(&self, tx: &Transaction, _vout: u32) {
        // Start tracking funding inputs, in case an input is double-spent.
        // The tracker was already informed of the inputs by the node.

        // Note that the fundee won't detect double-spends this way, because
        // they never see the details of the funding transaction.
        // But the fundee doesn't care about double-spends, because they don't
        // have any funds in the channel yet.

        // the lock order is backwards (monitor -> tracker), but we release
        // the monitor lock, so it's OK

        self.monitor.add_funding_inputs(tx);
    }

    /// Mark this channel as forgotten by the node allowing it to be pruned
    pub fn forget(&self) -> Result<(), Status> {
        self.monitor.forget_channel();
        self.persist()?;
        Ok(())
    }

    /// Return channel balances
    pub fn balance(&self) -> ChannelBalance {
        let node = self.get_node();
        let state = node.get_state();
        let is_ready = self.validator().is_ready(&self.get_chain_state());
        self.enforcement_state.balance(&*state, &self.setup, is_ready)
    }

    /// advance the holder commitment in an arbitrary way for testing
    #[cfg(feature = "test_utils")]
    pub fn advance_holder_commitment(
        &mut self,
        counterparty_key: &SecretKey,
        counterparty_htlc_key: &SecretKey,
        offered_htlcs: Vec<HTLCInfo2>,
        value_to_holder: u64,
        commit_num: u64,
    ) -> Result<(), Status> {
        let feerate = 1000;
        let funding_redeemscript = make_funding_redeemscript(
            &self.keys.pubkeys(&self.secp_ctx).funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );
        let per_commitment_point = self.get_per_commitment_point(commit_num)?;
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        let tx = self.make_holder_commitment_tx(
            commit_num,
            &per_commitment_point,
            feerate,
            value_to_holder,
            0,
            Channel::htlcs_info2_to_oic(&offered_htlcs, &vec![]),
        );

        let trusted_tx = tx.trust();
        let built_tx = trusted_tx.built_transaction();
        let counterparty_sig = built_tx.sign_counterparty_commitment(
            &counterparty_key,
            &funding_redeemscript,
            self.setup.channel_value_sat,
            &self.secp_ctx,
        );

        let counterparty_htlc_key =
            derive_private_key(&self.secp_ctx, &per_commitment_point, &counterparty_htlc_key);

        let features = self.setup.features();

        let mut htlc_sigs = Vec::with_capacity(tx.nondust_htlcs().len());
        for htlc in tx.nondust_htlcs() {
            let htlc_tx = catch_panic!(
                build_htlc_transaction(
                    &trusted_tx.txid(),
                    feerate,
                    self.setup.counterparty_selected_contest_delay,
                    htlc,
                    &features,
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                ),
                "build_htlc_transaction panic {} chantype={:?} htlc={:?}",
                self.setup.commitment_type,
                htlc
            );
            let htlc_redeemscript = get_htlc_redeemscript(&htlc, &features, &txkeys);
            let sig_hash_type = if self.setup.is_anchors() {
                EcdsaSighashType::SinglePlusAnyoneCanPay
            } else {
                EcdsaSighashType::All
            };

            // unwrap is safe because we just created the tx and it's well formed
            let htlc_sighash = Message::from(
                SighashCache::new(&htlc_tx)
                    .p2wsh_signature_hash(
                        0,
                        &htlc_redeemscript,
                        Amount::from_sat(htlc.amount_msat / 1000),
                        sig_hash_type,
                    )
                    .unwrap(),
            );
            htlc_sigs.push(self.secp_ctx.sign_ecdsa(&htlc_sighash, &counterparty_htlc_key));
        }

        // add an HTLC
        self.validate_holder_commitment_tx_phase2(
            commit_num,
            feerate,
            value_to_holder,
            0,
            offered_htlcs,
            vec![],
            &counterparty_sig,
            &htlc_sigs,
        )?;

        self.revoke_previous_holder_commitment(commit_num)?;
        Ok(())
    }

    /// Sign a transaction that spends the anchor output
    pub fn sign_holder_anchor_input(
        &self,
        anchor_tx: &Transaction,
        input: usize,
    ) -> Result<Signature, Status> {
        let node = self.get_node();
        self.keys
            .sign_holder_keyed_anchor_input(
                &self.make_channel_parameters(),
                anchor_tx,
                input,
                node.get_entropy_source(),
                &self.secp_ctx,
            )
            .map_err(|()| internal_error(format!("sign_holder_anchor_input failed")))
    }

    /// Get the anchor redeemscript
    pub fn get_keyed_anchor_redeemscript(&self) -> ScriptBuf {
        chan_utils::get_keyed_anchor_redeemscript(&self.keys.pubkeys(&self.secp_ctx).funding_pubkey)
    }
}

/// Balances associated with a channel
/// See: <https://gitlab.com/lightning-signer/docs/-/wikis/Proposed-L1-and-Channel-Balance-Reconciliation>
///
/// All channels that VLS knows about are in one of the four categories:
/// 1. channel stubs: assigned channelid and can generate points, keys, ...
/// 2. unconfirmed channels: negotiated channels prior to `channel_ready`
/// 3. channels: active channels in their normal operating mode
/// 4. closing channels: closed channels being swept or aged prior to pruning
///
#[derive(Debug, PartialEq)]
pub struct ChannelBalance {
    /// Claimable balance on open channel
    pub claimable: u64,
    /// Sum of htlcs offered to us
    pub received_htlc: u64,
    /// Sum of htlcs we offered
    pub offered_htlc: u64,
    /// Sweeping to wallet
    pub sweeping: u64,
    /// Current number of channel stubs
    pub stub_count: u32,
    /// Current number of unconfirmed channels
    pub unconfirmed_count: u32,
    /// Current number of active channels
    pub channel_count: u32,
    /// Current number of closing channels
    pub closing_count: u32,
    /// Current number of received htlcs
    pub received_htlc_count: u32,
    /// Current number of offered htlcs
    pub offered_htlc_count: u32,
}

impl ChannelBalance {
    /// Create a ChannelBalance with specific values
    pub fn new(
        claimable: u64,
        received_htlc: u64,
        offered_htlc: u64,
        sweeping: u64,
        stub_count: u32,
        unconfirmed_count: u32,
        channel_count: u32,
        closing_count: u32,
        received_htlc_count: u32,
        offered_htlc_count: u32,
    ) -> ChannelBalance {
        ChannelBalance {
            claimable,
            received_htlc,
            offered_htlc,
            sweeping,
            stub_count,
            unconfirmed_count,
            channel_count,
            closing_count,
            received_htlc_count,
            offered_htlc_count,
        }
    }

    /// Create a ChannelBalance with zero values
    pub fn zero() -> ChannelBalance {
        ChannelBalance {
            claimable: 0,
            received_htlc: 0,
            offered_htlc: 0,
            sweeping: 0,
            stub_count: 0,
            unconfirmed_count: 0,
            channel_count: 0,
            closing_count: 0,
            received_htlc_count: 0,
            offered_htlc_count: 0,
        }
    }

    /// Create a ChannelBalance for a stub
    pub fn stub() -> ChannelBalance {
        let mut bal = ChannelBalance::zero();
        bal.stub_count = 1;
        bal
    }

    /// Sum channel balances
    pub fn accumulate(&mut self, other: &ChannelBalance) {
        self.claimable += other.claimable;
        self.received_htlc += other.received_htlc;
        self.offered_htlc += other.offered_htlc;
        self.sweeping += other.sweeping;
        self.stub_count += other.stub_count;
        self.unconfirmed_count += other.unconfirmed_count;
        self.channel_count += other.channel_count;
        self.closing_count += other.closing_count;
        self.received_htlc_count += other.received_htlc_count;
        self.offered_htlc_count += other.offered_htlc_count;
    }
}

// Phase 1
impl Channel {
    pub(crate) fn build_counterparty_commitment_info(
        &self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> Result<CommitmentInfo2, Status> {
        Ok(CommitmentInfo2::new(
            true,
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        ))
    }

    fn build_holder_commitment_info(
        &self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> Result<CommitmentInfo2, Status> {
        Ok(CommitmentInfo2::new(
            false,
            to_counterparty_value_sat,
            to_holder_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        ))
    }

    /// Phase 1
    pub fn sign_counterparty_commitment_tx(
        &mut self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<Signature, Status> {
        if tx.output.len() != output_witscripts.len() {
            return Err(invalid_argument("len(tx.output) != len(witscripts)"));
        }

        // Since we didn't have the value at the real open, validate it now.
        let validator = self.validator();
        validator.validate_channel_value(&self.setup)?;

        // Derive a CommitmentInfo first, convert to CommitmentInfo2 below ...
        let is_counterparty = true;
        let info = validator.decode_commitment_tx(
            &self.keys,
            &self.setup,
            is_counterparty,
            tx,
            output_witscripts,
        )?;

        let info2 = self.build_counterparty_commitment_info(
            info.to_countersigner_value_sat,
            info.to_broadcaster_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let mut state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, None, Some(&info2), &self.setup_for_tx(tx)?);

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(None, Some(&info2));

        validator
            .validate_counterparty_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &remote_per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                debug!(
                    "VALIDATION FAILED: {} tx={:?} setup={:?} cstate={:?} info={:?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                debug!(
                    "VALIDATION FAILED: {}\ntx={:#?}\nsetup={:#?}\ncstate={:#?}\ninfo={:#?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs = Self::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);

        let recomposed_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            info2.to_countersigner_value_sat,
            info2.to_broadcaster_value_sat,
            htlcs,
        );

        if recomposed_tx.trust().built_transaction().transaction != *tx {
            #[cfg(not(feature = "log_pretty_print"))]
            {
                debug!("ORIGINAL_TX={:?}", &tx);
                debug!(
                    "RECOMPOSED_TX={:?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            #[cfg(feature = "log_pretty_print")]
            {
                debug!("ORIGINAL_TX={:#?}", &tx);
                debug!(
                    "RECOMPOSED_TX={:#?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            policy_err!(validator, "policy-commitment", "recomposed tx mismatch");
        }

        // The comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-commitment-version
        // - policy-commitment-locktime
        // - policy-commitment-sequence
        // - policy-commitment-input-single
        // - policy-commitment-input-match-funding
        // - policy-commitment-revocation-pubkey
        // - policy-commitment-broadcaster-pubkey
        // - policy-commitment-countersignatory-pubkey
        // - policy-commitment-htlc-revocation-pubkey
        // - policy-commitment-htlc-counterparty-htlc-pubkey
        // - policy-commitment-htlc-holder-htlc-pubkey
        // - policy-commitment-singular
        // - policy-commitment-to-self-delay
        // - policy-commitment-no-unrecognized-outputs

        // Convert from backwards counting.
        let commit_num = INITIAL_COMMITMENT_NUMBER - recomposed_tx.trust().commitment_number();

        let point = recomposed_tx.trust().keys().per_commitment_point;

        // we don't use keys.sign_counterparty_commitment here because it also signs HTLCs
        let trusted_tx = recomposed_tx.trust();

        let funding_pubkey = &self.keys.pubkeys(&self.secp_ctx).funding_pubkey;
        let counterparty_funding_pubkey = &self.setup.counterparty_points.funding_pubkey;
        let channel_funding_redeemscript =
            make_funding_redeemscript(funding_pubkey, counterparty_funding_pubkey);

        let built_tx = trusted_tx.built_transaction();
        let sig = catch_panic!(
            built_tx.sign_counterparty_commitment(
                &self.keys.funding_key(None),
                &channel_funding_redeemscript,
                self.setup.channel_value_sat,
                &self.secp_ctx,
            ),
            "sign_counterparty_commitment panic {} chantype={:?}",
            self.setup.commitment_type
        );

        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, Some(&info2));
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        // Only advance the state if nothing goes wrong.
        validator.set_next_counterparty_commit_num(
            &mut self.enforcement_state,
            commit_num + 1,
            point,
            info2.clone(),
        )?;
        self.enforcement_state.counterparty_commitment_funding =
            Some(self.setup.funding_outpoint);

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
            Some(&info2),
        );

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(sig)
    }

    fn make_validated_recomposed_holder_commitment_tx(
        &self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        commitment_number: u64,
        per_commitment_point: PublicKey,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(CommitmentTransaction, CommitmentInfo2, Map<PaymentHash, u64>), Status> {
        if tx.output.len() != output_witscripts.len() {
            return Err(invalid_argument(format!(
                "len(tx.output):{} != len(witscripts):{}",
                tx.output.len(),
                output_witscripts.len()
            )));
        }

        let validator = self.validator();

        // Since we didn't have the value at the real open, validate it now.
        validator.validate_channel_value(&self.setup)?;

        // Derive a CommitmentInfo first, convert to CommitmentInfo2 below ...
        let is_counterparty = false;
        let info = validator.decode_commitment_tx(
            &self.keys,
            &self.setup,
            is_counterparty,
            tx,
            output_witscripts,
        )?;

        let info2 = self.build_holder_commitment_info(
            info.to_broadcaster_value_sat,
            info.to_countersigner_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);

        validator
            .validate_holder_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                warn!(
                    "VALIDATION FAILED: {} tx={:?} setup={:?} state={:?} info={:?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                warn!(
                    "VALIDATION FAILED: {}\ntx={:#?}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs = Self::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);

        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &per_commitment_point,
            feerate_per_kw,
            info.to_broadcaster_value_sat,
            info.to_countersigner_value_sat,
            htlcs,
        );

        if recomposed_tx.trust().built_transaction().transaction != *tx {
            dbgvals!(
                &self.setup,
                &self.enforcement_state,
                tx,
                DebugVecVecU8(output_witscripts),
                commitment_number,
                feerate_per_kw,
                &info2.offered_htlcs,
                &info2.received_htlcs
            );
            #[cfg(not(feature = "log_pretty_print"))]
            {
                warn!("RECOMPOSITION FAILED");
                warn!("ORIGINAL_TX={:?}", &tx);
                warn!("RECOMPOSED_TX={:?}", &recomposed_tx.trust().built_transaction().transaction);
            }
            #[cfg(feature = "log_pretty_print")]
            {
                warn!("RECOMPOSITION FAILED");
                warn!("ORIGINAL_TX={:#?}", &tx);
                warn!(
                    "RECOMPOSED_TX={:#?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            policy_err!(validator, "policy-commitment", "recomposed tx mismatch");
        }

        // The comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-commitment-version
        // - policy-commitment-locktime
        // - policy-commitment-sequence
        // - policy-commitment-input-single
        // - policy-commitment-input-match-funding
        // - policy-commitment-revocation-pubkey
        // - policy-commitment-broadcaster-pubkey
        // - policy-commitment-htlc-revocation-pubkey
        // - policy-commitment-htlc-counterparty-htlc-pubkey
        // - policy-commitment-htlc-holder-htlc-pubkey
        // - policy-revoke-new-commitment-valid

        Ok((recomposed_tx, info2, incoming_payment_summary))
    }

    /// Validate the counterparty's signatures on the holder's
    /// commitment and HTLCs when the commitment_signed message is
    /// received.  Returns the next per_commitment_point and the
    /// holder's revocation secret for the prior commitment.  This
    /// method advances the expected next holder commitment number in
    /// the signer's state.
    pub fn validate_holder_commitment_tx(
        &mut self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        commitment_number: u64,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
    ) -> Result<(), Status> {
        let validator = self.validator();
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        // policy-onchain-format-standard
        let (recomposed_tx, info2, incoming_payment_summary) = self
            .make_validated_recomposed_holder_commitment_tx(
                tx,
                output_witscripts,
                commitment_number,
                per_commitment_point,
                feerate_per_kw,
                offered_htlcs,
                received_htlcs,
            )?;

        let node = self.get_node();
        let state = node.get_state();
        // R10: compute against the funding this commitment's tx actually
        // spends — an old-funding commitment arriving post-swap must not
        // be valued against the new (possibly reduced) channel_value
        let view = self.setup_for_tx(tx)?;
        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &view);

        #[cfg(not(fuzzing))]
        self.check_holder_tx_signatures(
            &per_commitment_point,
            &txkeys,
            feerate_per_kw,
            counterparty_commit_sig,
            counterparty_htlc_sigs,
            recomposed_tx,
        )?;

        #[cfg(fuzzing)]
        let _ = recomposed_tx;

        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        if commitment_number == self.enforcement_state.next_holder_commit_num
            || self.enforcement_state.holder_commitment_funding
                != Some(self.setup.funding_outpoint)
        {
            let counterparty_signatures = CommitmentSignatures(
                counterparty_commit_sig.clone(),
                counterparty_htlc_sigs.to_vec(),
            );
            self.enforcement_state.next_holder_commit_info = Some((info2, counterparty_signatures));
            self.enforcement_state.holder_commitment_funding =
                Some(self.setup.funding_outpoint);
        }

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(())
    }

    /// Activate commitment 0 explicitly
    ///
    /// Commitment 0 is special because it doesn't have a predecessor
    /// commitment.  Since the revocation of the prior commitment normally makes
    /// a new commitment "current" this final step must be invoked explicitly.
    ///
    /// Returns the next per_commitment_point.
    pub fn activate_initial_commitment(&mut self) -> Result<PublicKey, Status> {
        debug!("activate_initial_commitment");

        if self.enforcement_state.next_holder_commit_num > 1 {
            return Err(invalid_argument(format!(
                "activate_initial_commitment called with next_holder_commit_num {}",
                self.enforcement_state.next_holder_commit_num
            )));
        }

        // Remove the info and sigs from next holder and make current
        if let Some((info2, sigs)) = self.enforcement_state.next_holder_commit_info.take() {
            if self.enforcement_state.next_holder_commit_num == 0 {
                self.enforcement_state.set_next_holder_commit_num(1, info2, sigs);
            } else {
                // same-number splice re-activation: replace the current
                // holder commitment in place (the number does not advance)
                self.enforcement_state.current_holder_commit_info = Some(info2);
                self.enforcement_state.current_counterparty_signatures = Some(sigs);
            }
        } else {
            return Err(invalid_argument(format!(
                "activate_initial_commitment called before validation of the initial commitment"
            )));
        }

        trace_enforcement_state!(self);
        self.persist()?;
        Ok(self.get_per_commitment_point_unchecked(1))
    }

    /// Process the counterparty's revocation
    ///
    /// When this is provided, we know that the counterparty has committed to
    /// the next state.
    pub fn validate_counterparty_revocation(
        &mut self,
        revoke_num: u64,
        old_secret: &SecretKey,
    ) -> Result<(), Status> {
        let validator = self.validator();
        validator.validate_counterparty_revocation(
            &self.enforcement_state,
            revoke_num,
            old_secret,
        )?;

        if let Some(secrets) = self.enforcement_state.counterparty_secrets.as_mut() {
            let backwards_num = INITIAL_COMMITMENT_NUMBER - revoke_num;
            if secrets.provide_secret(backwards_num, old_secret.secret_bytes()).is_err() {
                error!(
                    "secret does not chain: {} ({}) {} into {:?}",
                    revoke_num,
                    backwards_num,
                    old_secret.display_secret(),
                    secrets
                );
                policy_err!(
                    validator,
                    "policy-commitment-previous-revoked",
                    "counterparty secret does not chain"
                )
            }
        }

        validator.set_next_counterparty_revoke_num(&mut self.enforcement_state, revoke_num + 1)?;

        trace_enforcement_state!(self);
        self.persist()?;
        Ok(())
    }

    /// Phase 1
    pub fn sign_mutual_close_tx(
        &mut self,
        tx: &Transaction,
        opaths: &[DerivationPath],
    ) -> Result<Signature, Status> {
        dbgvals!(tx.compute_txid(), self.get_node().allowlist());
        if opaths.len() != tx.output.len() {
            return Err(invalid_argument(format!(
                "{}: bad opath len {} with tx.output len {}",
                short_function!(),
                opaths.len(),
                tx.output.len()
            )));
        }

        let recomposed_tx = self.validator().decode_and_validate_mutual_close_tx(
            &*self.get_node(),
            &self.setup,
            &self.enforcement_state,
            tx,
            opaths,
        )?;

        let sig = self
            .keys
            .sign_closing_transaction(
                &self.make_channel_parameters(),
                &recomposed_tx,
                &self.secp_ctx,
            )
            .map_err(|_| Status::internal("failed to sign"))?;
        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok(sig)
    }

    /// Phase 1
    pub fn sign_holder_htlc_tx(
        &self,
        tx: &Transaction,
        commitment_number: u64,
        opt_per_commitment_point: Option<PublicKey>,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
    ) -> Result<TypedSignature, Status> {
        let per_commitment_point = if opt_per_commitment_point.is_some() {
            opt_per_commitment_point.unwrap()
        } else {
            self.get_per_commitment_point(commitment_number)?
        };

        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        self.sign_htlc_tx(
            tx,
            &per_commitment_point,
            redeemscript,
            htlc_amount_sat,
            output_witscript,
            false, // is_counterparty
            txkeys,
        )
    }

    /// Sign a HTLC transaction hanging off a commitment transaction
    pub fn sign_holder_htlc_tx_phase2(
        &self,
        tx: &Transaction,
        input: u32,
        commitment_number: u64,
        is_offered: bool,
        cltv_expiry: u32,
        htlc_amount_msat: u64,
        payment_hash: PaymentHash,
    ) -> Result<TypedSignature, Status> {
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
        let keys = self.make_holder_tx_keys(&per_commitment_point);
        let htlc = HTLCOutputInCommitment {
            offered: is_offered,
            cltv_expiry,
            payment_hash,
            transaction_output_index: None,
            amount_msat: htlc_amount_msat,
        };
        let witness_script =
            chan_utils::get_htlc_redeemscript(&htlc, &self.setup.features(), &keys);
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(
                input as usize,
                &witness_script,
                Amount::from_sat(htlc_amount_msat / 1000),
                EcdsaSighashType::All,
            )
            .unwrap();
        let our_htlc_private_key = chan_utils::derive_private_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.keys.htlc_base_key,
        );
        let sighash = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp_ctx.sign_ecdsa(&sighash, &our_htlc_private_key);
        Ok(TypedSignature { sig: signature, typ: EcdsaSighashType::All })
    }

    /// Phase 1
    pub fn sign_counterparty_htlc_tx(
        &self,
        tx: &Transaction,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
    ) -> Result<TypedSignature, Status> {
        let txkeys = self.make_counterparty_tx_keys(&remote_per_commitment_point);

        self.sign_htlc_tx(
            tx,
            remote_per_commitment_point,
            redeemscript,
            htlc_amount_sat,
            output_witscript,
            true, // is_counterparty
            txkeys,
        )
    }

    /// Sign a 2nd level HTLC transaction hanging off a commitment transaction
    pub fn sign_htlc_tx(
        &self,
        tx: &Transaction,
        per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
        is_counterparty: bool,
        txkeys: TxCreationKeys,
    ) -> Result<TypedSignature, Status> {
        let (feerate_per_kw, htlc, recomposed_tx_sighash, sighash_type) =
            self.validator().decode_and_validate_htlc_tx(
                is_counterparty,
                &self.setup,
                &txkeys,
                tx,
                &redeemscript,
                htlc_amount_sat,
                output_witscript,
            )?;

        self.validator()
            .validate_htlc_tx(
                &self.setup,
                &self.get_chain_state(),
                is_counterparty,
                &htlc,
                feerate_per_kw,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                debug!(
                    "VALIDATION FAILED: {} setup={:?} state={:?} is_counterparty={} \
                     tx={:?} htlc={:?} feerate_per_kw={}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    is_counterparty,
                    &tx,
                    DebugHTLCOutputInCommitment(&htlc),
                    feerate_per_kw,
                );
                #[cfg(feature = "log_pretty_print")]
                debug!(
                    "VALIDATION FAILED: {}\n\
                     setup={:#?}\n\
                     state={:#?}\n\
                     is_counterparty={}\n\
                     tx={:#?}\n\
                     htlc={:#?}\n\
                     feerate_per_kw={}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    is_counterparty,
                    &tx,
                    DebugHTLCOutputInCommitment(&htlc),
                    feerate_per_kw,
                );
                ve
            })?;

        let htlc_privkey =
            derive_private_key(&self.secp_ctx, &per_commitment_point, &self.keys.htlc_base_key);

        let htlc_sighash = Message::from_digest(recomposed_tx_sighash.to_byte_array());

        Ok(TypedSignature {
            sig: self.secp_ctx.sign_ecdsa(&htlc_sighash, &htlc_privkey),
            typ: sighash_type,
        })
    }

    /// Get the unilateral close key and the witness stack suffix,
    /// for sweeping our main output from a commitment transaction.
    /// If the revocation_pubkey is Some, then we are sweeping a
    /// holder commitment transaction, otherwise we are sweeping a
    /// counterparty commitment transaction.
    /// commitment_point is used to derive the key if it is Some.
    /// Since we don't support legacy channels, commitment_point must
    /// be Some iff revocation_pubkey is Some.
    pub fn get_unilateral_close_key(
        &self,
        commitment_point: &Option<PublicKey>,
        revocation_pubkey: &Option<RevocationKey>,
    ) -> Result<(SecretKey, Vec<Vec<u8>>), Status> {
        if let Some(commitment_point) = commitment_point {
            // The key is rotated via the commitment point.  Since we removed support
            // for rotating the to-remote key (legacy channel type), we enforce below that
            // this is the to-local case.
            let base_key = if revocation_pubkey.is_some() {
                &self.keys.delayed_payment_base_key
            } else {
                &self.payment_key
            };
            let key = derive_private_key(&self.secp_ctx, &commitment_point, base_key);
            let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &key);

            let witness_stack_prefix = if let Some(r) = revocation_pubkey {
                // p2wsh
                let contest_delay = self.setup.counterparty_selected_contest_delay;
                let redeemscript = chan_utils::get_revokeable_redeemscript(
                    r,
                    contest_delay,
                    &DelayedPaymentKey(pubkey),
                )
                .to_bytes();
                vec![vec![], redeemscript]
            } else {
                return Err(invalid_argument(
                    "no support for legacy rotated to-remote, commitment point is provided and revocation_pubkey is not"
                ));
            };
            Ok((key, witness_stack_prefix))
        } else {
            // The key is not rotated, so we use the base key.  This must be the to-remote case
            // because the to-local is always rotated.
            if revocation_pubkey.is_some() {
                return Err(invalid_argument(
                    "delayed to-local output must be rotated, but no commitment point provided",
                ));
            }

            let key = self.payment_key.clone();
            let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &key);
            let witness_stack_prefix = if self.setup.is_anchors() {
                // p2wsh
                let redeemscript =
                    chan_utils::get_to_countersigner_keyed_anchor_redeemscript(&pubkey).to_bytes();
                vec![redeemscript]
            } else {
                // p2wpkh
                vec![pubkey.serialize().to_vec()]
            };
            Ok((key, witness_stack_prefix))
        }
    }

    /// Mark any in-flight payments (outgoing HTLCs) on this channel with the
    /// given preimage as filled.
    /// Any such payments adjust our expected balance downwards.
    pub fn htlcs_fulfilled(&mut self, preimages: Vec<PaymentPreimage>) {
        let validator = self.validator();
        let node = self.get_node();
        node.htlcs_fulfilled(&self.id0, preimages, validator);
    }

    fn dummy_sig() -> Signature {
        Signature::from_compact(&Vec::from_hex("eb299947b140c0e902243ee839ca58c71291f4cce49ac0367fb4617c4b6e890f18bc08b9be6726c090af4c6b49b2277e134b34078f710a72a5752e39f0139149").unwrap()).unwrap()
    }

    /// Analyzes a broadcasted commitment transaction to identify spendable HTLC outputs.
    ///
    /// HTLCs are considered spendable if:
    /// - We have the preimage for HTLCs we received (counterparty offered).
    /// - For HTLCs we offered, they're always spendable after timeout.
    pub fn get_spendable_htlc_indices(
        &self,
        tx: &Transaction,
        commitment_number: u64,
    ) -> Result<Vec<u32>, Status> {
        let (is_counterparty_tx, info) = self.get_commitment_info(tx, commitment_number)?;

        let per_commitment_point = if is_counterparty_tx {
            // Safe to unwrap: get_commitment_info above already validated the commitment_number
            // so point must exist unless state is inconsistent.
            self.get_counterparty_commitment_point(commitment_number).unwrap()
        } else {
            self.get_per_commitment_point(commitment_number).unwrap()
        };

        let txkeys = if is_counterparty_tx {
            self.make_counterparty_tx_keys(&per_commitment_point)
        } else {
            self.make_holder_tx_keys(&per_commitment_point)
        };

        let htlcs = Self::htlcs_info2_to_oic(&info.offered_htlcs, &info.received_htlcs);
        let features = self.setup.features();
        let node = self.get_node();
        let payments = &node.get_state().payments;

        let mut spendable_htlcs: UnorderedSet<ScriptBuf> = UnorderedSet::new();
        for htlc in &htlcs {
            let can_spend = match (htlc.offered, is_counterparty_tx) {
                // Counterparty offered or we received: needs preimage
                (true, true) | (false, false) =>
                    payments.get(&htlc.payment_hash).and_then(|p| p.preimage.as_ref()).is_some(),
                // We offered: spendable after timeout
                (true, false) | (false, true) => true,
            };

            if can_spend {
                let redeemscript = get_htlc_redeemscript(htlc, &features, &txkeys);
                spendable_htlcs.insert(redeemscript.to_p2wsh());
            }
        }

        let spendable_indices = tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(index, output)| {
                if spendable_htlcs.contains(&output.script_pubkey) {
                    Some(index as u32)
                } else {
                    None
                }
            })
            .collect();

        Ok(spendable_indices)
    }

    fn get_commitment_info(
        &self,
        tx: &Transaction,
        commitment_number: u64,
    ) -> Result<(bool, CommitmentInfo2), Status> {
        let es = &self.enforcement_state;

        let current_holder_commit_num = es.next_holder_commit_num.saturating_sub(1);
        let next_holder_commit_num = es.next_holder_commit_num;

        if commitment_number == current_holder_commit_num {
            if let Some(info) = &es.current_holder_commit_info {
                let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
                let htlcs = Self::htlcs_info2_to_oic(&info.offered_htlcs, &info.received_htlcs);
                let expected_tx = self.make_holder_commitment_tx(
                    commitment_number,
                    &per_commitment_point,
                    info.feerate_per_kw,
                    info.to_broadcaster_value_sat,
                    info.to_countersigner_value_sat,
                    htlcs,
                );
                if expected_tx.trust().built_transaction().transaction.compute_txid()
                    == tx.compute_txid()
                {
                    return Ok((false, info.clone()));
                }
            }
        } else if commitment_number == next_holder_commit_num {
            if let Some((info, _)) = &es.next_holder_commit_info {
                let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
                let htlcs = Self::htlcs_info2_to_oic(&info.offered_htlcs, &info.received_htlcs);
                let expected_tx = self.make_holder_commitment_tx(
                    commitment_number,
                    &per_commitment_point,
                    info.feerate_per_kw,
                    info.to_broadcaster_value_sat,
                    info.to_countersigner_value_sat,
                    htlcs,
                );
                if expected_tx.trust().built_transaction().transaction.compute_txid()
                    == tx.compute_txid()
                {
                    return Ok((false, info.clone()));
                }
            }
        }

        if let Some(info) = es.get_previous_counterparty_commit_info(commitment_number) {
            return Ok((true, info));
        }

        Err(Status::invalid_argument(format!(
            "commitment info not available for commitment number {}",
            commitment_number
        )))
    }
}

#[derive(Clone)]
pub(crate) struct ChannelCommitmentPointProvider {
    chan: Arc<Mutex<ChannelSlot>>,
}

impl ChannelCommitmentPointProvider {
    /// Will panic on a channel stub
    pub(crate) fn new(chan: Arc<Mutex<ChannelSlot>>) -> Self {
        match &*chan.lock().unwrap() {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(_) => {}
        }
        Self { chan }
    }

    fn get_channel(&self) -> MutexGuard<'_, ChannelSlot> {
        self.chan.lock().unwrap()
    }
}

impl SendSync for ChannelCommitmentPointProvider {}

impl CommitmentPointProvider for ChannelCommitmentPointProvider {
    fn get_holder_commitment_point(&self, commitment_number: u64) -> PublicKey {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };
        chan.get_per_commitment_point_unchecked(commitment_number)
    }

    fn get_counterparty_commitment_point(&self, commitment_number: u64) -> Option<PublicKey> {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };

        chan.get_counterparty_commitment_point(commitment_number)
    }

    fn get_transaction_parameters(&self) -> ChannelTransactionParameters {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };

        chan.make_channel_parameters()
    }

    fn get_spendable_htlc_indices(
        &self,
        tx: &Transaction,
        commitment_number: u64,
    ) -> Result<Vec<u32>, Status> {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => return Err(invalid_argument("cannot analyze HTLCs on stub")),
            ChannelSlot::Ready(c) => c,
        };
        chan.get_spendable_htlc_indices(tx, commitment_number)
    }

    fn clone_box(&self) -> Box<dyn CommitmentPointProvider> {
        Box::new(ChannelCommitmentPointProvider { chan: self.chan.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256::Hash as Sha256Hash;
    use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
    use lightning::ln::chan_utils::HTLCOutputInCommitment;
    use lightning::types::payment::PaymentHash;
    use lightning::util::ser::Writeable;

    use crate::channel::ChannelBase;
    use crate::node::{PaymentState, PaymentType};
    use crate::util::test_utils::htlc::{
        make_commit_info_with_htlcs, make_counterparty_commit_info_with_htlcs, make_htlc,
    };
    use crate::util::test_utils::key::make_test_pubkey;
    use crate::util::test_utils::{
        hex_decode, init_node, init_node_and_channel, make_test_channel_setup,
        make_test_channel_setup_with_points, make_test_payment_hashes, make_testnet_header,
        next_state, TEST_CHANNEL_ID, TEST_NODE_CONFIG, TEST_SEED,
    };
    use bitcoin::{Network, TxOut};
    use core::time::Duration;
    use std::collections::HashSet;

    #[test]
    fn test_dummy_sig() {
        let dummy_sig = Secp256k1::new().sign_ecdsa(
            &secp256k1::Message::from_digest([42; 32]),
            &SecretKey::from_slice(&[42; 32]).unwrap(),
        );
        let ser = dummy_sig.serialize_compact();
        assert_eq!("eb299947b140c0e902243ee839ca58c71291f4cce49ac0367fb4617c4b6e890f18bc08b9be6726c090af4c6b49b2277e134b34078f710a72a5752e39f0139149", hex::encode(ser));
    }

    #[test]
    fn tx_size_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_channel(&channel_id, |chan| {
            let n = 1;
            let commitment_point = chan.get_per_commitment_point(n).unwrap();
            let htlcs = (0..583)
                .map(|i| HTLCOutputInCommitment {
                    offered: true,
                    amount_msat: 1000000,
                    cltv_expiry: 100,
                    payment_hash: PaymentHash([0; 32]),
                    transaction_output_index: Some(i),
                })
                .collect();
            let tx = chan.make_holder_commitment_tx(n, &commitment_point, 1, 1, 1, htlcs);
            let tx_size = tx.trust().built_transaction().transaction.serialized_length();
            assert_eq!(tx_size, 25196);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_ldk_oid_roundtrip() {
        let oid: u64 = 42;
        assert_eq!(oid, ChannelId::new_from_oid(oid).oid());
    }

    #[test]
    fn test_ldk_channel_keys_id_valid() {
        let oid = 42u64;
        let chan_id = ChannelId::new_from_oid(oid);
        let keys_id = chan_id.ldk_channel_keys_id();
        assert_eq!(keys_id.len(), 32);
        assert_eq!(&keys_id[0..24], &[0u8; 24]);
        assert_eq!(&keys_id[24..], &oid.to_le_bytes());
    }

    #[test]
    #[should_panic(
        expected = "source slice length (3) does not match destination slice length (32)"
    )]
    fn test_ldk_channel_keys_id_short_id() {
        let short_id = ChannelId::new(&[1, 2, 3]);
        short_id.ldk_channel_keys_id();
    }

    #[test]
    fn channel_base_readiness_and_keys_id() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        {
            let mut tracker = node.get_tracker();
            for _ in 0..3 {
                let (header, proof) = make_testnet_header(tracker.tip(), tracker.height());
                tracker.add_block(header, proof).unwrap();
            }
        }
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");

        // Stub phase: not ready, but the derived keys id is already available.
        let (ready, stub_keys_id) = node
            .with_channel_base(&channel_id, |base| {
                Ok((base.is_ready(), base.get_channel_keys_id()))
            })
            .unwrap();
        assert!(!ready);
        assert_ne!(stub_keys_id, [0u8; 32]);
        assert_ne!(stub_keys_id, [1u8; 32]);

        node.setup_channel(
            channel_id.clone(),
            None,
            make_test_channel_setup(),
            &DerivationPath::master(),
        )
        .expect("ready channel");

        // Ready phase: same keys id, now flagged ready.
        let (ready, ready_keys_id) = node
            .with_channel_base(&channel_id, |base| {
                Ok((base.is_ready(), base.get_channel_keys_id()))
            })
            .unwrap();
        assert!(ready);
        assert_eq!(ready_keys_id, stub_keys_id);
    }

    #[test]
    fn test_typed_signature_serialize() {
        let secp = Secp256k1::new();
        let msg = secp256k1::Message::from_digest([42; 32]);
        let sk = SecretKey::from_slice(&[1; 32]).unwrap();
        let sig = secp.sign_ecdsa(&msg, &sk);
        let typed_sig = TypedSignature { sig, typ: EcdsaSighashType::All };

        let serialized = typed_sig.serialize();
        let expected = {
            let mut v = sig.serialize_der().to_vec();
            v.push(EcdsaSighashType::All as u8);
            v
        };
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_channel_setup_methods() {
        let setup_legacy =
            ChannelSetup { commitment_type: CommitmentType::Legacy, ..make_test_channel_setup() };
        let setup_static = ChannelSetup {
            commitment_type: CommitmentType::StaticRemoteKey,
            ..make_test_channel_setup()
        };
        let setup_anchors =
            ChannelSetup { commitment_type: CommitmentType::Anchors, ..make_test_channel_setup() };
        let setup_zero_fee = ChannelSetup {
            commitment_type: CommitmentType::AnchorsZeroFeeHtlc,
            ..make_test_channel_setup()
        };

        assert!(!setup_legacy.is_static_remotekey());
        assert!(setup_static.is_static_remotekey());
        assert!(setup_anchors.is_static_remotekey());
        assert!(setup_zero_fee.is_static_remotekey());

        assert!(!setup_legacy.is_anchors());
        assert!(!setup_static.is_anchors());
        assert!(setup_anchors.is_anchors());
        assert!(setup_zero_fee.is_anchors());

        assert!(!setup_legacy.is_zero_fee_htlc());
        assert!(!setup_static.is_zero_fee_htlc());
        assert!(!setup_anchors.is_zero_fee_htlc());
        assert!(setup_zero_fee.is_zero_fee_htlc());

        let features_legacy = setup_legacy.features();
        assert!(features_legacy.supports_static_remote_key());
        assert!(!features_legacy.supports_anchors_zero_fee_htlc_tx());

        let features_zero_fee = setup_zero_fee.features();
        assert!(features_zero_fee.supports_static_remote_key());
        assert!(features_zero_fee.supports_anchors_zero_fee_htlc_tx());

        let feature_static = setup_static.features();
        assert!(feature_static.supports_static_remote_key());
        assert!(!feature_static.supports_anchors_zero_fee_htlc_tx());

        let feature_anchors = setup_anchors.features();
        assert!(feature_anchors.supports_static_remote_key());
        assert!(!feature_anchors.supports_anchors_zero_fee_htlc_tx());
    }

    #[test]
    fn test_channel_make_counterparty_tx_keys() {
        let (node, chan_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_channel(&chan_id, |chan| {
            let point = PublicKey::from_secret_key(
                &chan.secp_ctx,
                &SecretKey::from_slice(&[3; 32]).unwrap(),
            );
            let keys = chan.make_counterparty_tx_keys(&point);
            assert_eq!(keys.per_commitment_point, point);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_channel_network() {
        let (node, chan_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_channel(&chan_id, |chan| {
            assert_eq!(chan.network(), Network::Testnet);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_channel_balance_methods() {
        let mut bal1 = ChannelBalance::new(1000, 200, 300, 400, 1, 2, 3, 4, 5, 6);
        assert_eq!(bal1.claimable, 1000);
        assert_eq!(bal1.stub_count, 1);

        let bal2 = ChannelBalance::new(500, 100, 150, 200, 1, 1, 1, 1, 2, 3);
        bal1.accumulate(&bal2);

        assert_eq!(bal1.claimable, 1500);
        assert_eq!(bal1.received_htlc, 300);
        assert_eq!(bal1.offered_htlc, 450);
        assert_eq!(bal1.sweeping, 600);
        assert_eq!(bal1.stub_count, 2);
        assert_eq!(bal1.unconfirmed_count, 3);
        assert_eq!(bal1.channel_count, 4);
        assert_eq!(bal1.closing_count, 5);
        assert_eq!(bal1.received_htlc_count, 7);
        assert_eq!(bal1.offered_htlc_count, 9);

        let stub_bal = ChannelBalance::stub();
        assert_eq!(stub_bal.stub_count, 1);
        assert_eq!(stub_bal.claimable, 0);
    }

    #[test]
    fn test_restore_payments_rebuilds_from_holder_commit_info() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let hash1 = PaymentHash(Sha256Hash::hash(&[1u8; 32]).to_byte_array());
        let hash2 = PaymentHash(Sha256Hash::hash(&[2u8; 32]).to_byte_array());

        let holder_commit_info = make_commit_info_with_htlcs(
            vec![make_htlc(hash1, 90_000, 1000)],
            vec![
                make_htlc(hash1, 60_000, 1100),
                make_htlc(hash1, 40_000, 1050),
                make_htlc(hash2, 80_000, 1200),
            ],
        );

        let channel = node.get_channel(&channel_id).unwrap();
        let mut ch = channel.lock().unwrap();
        assert!(matches!(&*ch, ChannelSlot::Ready(_)));
        if let ChannelSlot::Ready(ref mut ready_channel) = &mut *ch {
            ready_channel.enforcement_state.current_holder_commit_info = Some(holder_commit_info);

            ready_channel.restore_payments();
        }

        let state = node.get_state();

        let payment1 = state.payments.get(&hash1).unwrap();
        assert_eq!(payment1.incoming_cltv_min, Some(1050));
        assert_eq!(payment1.outgoing_cltv_max, Some(1000));

        let payment2 = state.payments.get(&hash2).unwrap();
        assert_eq!(payment2.incoming_cltv_min, Some(1200));
        assert_eq!(payment2.outgoing_cltv_max, None);
    }

    #[test]
    fn test_restore_payments_rebuilds_from_counterparty_commit_info() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let hash1 = PaymentHash(Sha256Hash::hash(&[1u8; 32]).to_byte_array());
        let hash2 = PaymentHash(Sha256Hash::hash(&[2u8; 32]).to_byte_array());

        let counterparty_commit_info = make_counterparty_commit_info_with_htlcs(
            vec![
                make_htlc(hash1, 60_000, 1100),
                make_htlc(hash1, 40_000, 1050),
                make_htlc(hash2, 80_000, 1200),
            ],
            vec![make_htlc(hash1, 90_000, 1000)],
        );

        let channel = node.get_channel(&channel_id).unwrap();
        let mut ch = channel.lock().unwrap();
        assert!(matches!(&*ch, ChannelSlot::Ready(_)));
        if let ChannelSlot::Ready(ref mut ready_channel) = &mut *ch {
            ready_channel.enforcement_state.current_counterparty_commit_info =
                Some(counterparty_commit_info);

            ready_channel.restore_payments();
        }

        let state = node.get_state();

        let payment1 = state.payments.get(&hash1).unwrap();
        assert_eq!(payment1.incoming_cltv_min, Some(1050));
        assert_eq!(payment1.outgoing_cltv_max, Some(1000));

        let payment2 = state.payments.get(&hash2).unwrap();
        assert_eq!(payment2.incoming_cltv_min, Some(1200));
        assert_eq!(payment2.outgoing_cltv_max, None);
    }

    #[test]
    fn test_get_spendable_htlc_indices_current_holder() {
        let (node, channel_id, _, offered_htlcs, received_htlcs) = setup_test_channel_with_htlcs();
        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;

        node.with_channel(&channel_id, |chan| {
            let holder_tx = setup_holder_commitment(
                chan,
                commit_num,
                to_holder,
                to_cp,
                &offered_htlcs,
                &received_htlcs,
                feerate_per_kw,
            )?;
            let indices = chan.get_spendable_htlc_indices(&holder_tx, commit_num)?;
            assert_eq!(indices.len(), 3);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_get_spendable_htlc_indices_next_holder() {
        let (node, channel_id, _, offered_htlcs, received_htlcs) = setup_test_channel_with_htlcs();
        let commit_num = 23;
        let next_commit_num = commit_num + 1;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;

        node.with_channel(&channel_id, |chan| {
            let next_holder_info2 = chan.build_holder_commitment_info(
                to_holder + 1000,
                to_cp - 1000,
                received_htlcs.to_vec(),
                offered_htlcs.to_vec(),
                feerate_per_kw,
            )?;

            let dummy_sigs = CommitmentSignatures(Channel::dummy_sig(), vec![]);
            chan.enforcement_state.next_holder_commit_info = Some((next_holder_info2, dummy_sigs));
            chan.set_next_holder_commit_num_for_testing(next_commit_num);

            let per_commitment_point = chan.get_per_commitment_point(next_commit_num)?;
            let holder_htlcs = Channel::htlcs_info2_to_oic(&received_htlcs, &offered_htlcs);
            let next_holder_tx = chan.make_holder_commitment_tx(
                next_commit_num,
                &per_commitment_point,
                feerate_per_kw,
                to_holder + 1000,
                to_cp - 1000,
                holder_htlcs,
            );
            let next_holder_tx = next_holder_tx.trust().built_transaction().transaction.clone();

            let indices = chan.get_spendable_htlc_indices(&next_holder_tx, next_commit_num)?;
            assert_eq!(indices.len(), 3);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_get_spendable_htlc_indices_current_counterparty() {
        let (node, channel_id, _, offered_htlcs, received_htlcs) = setup_test_channel_with_htlcs();
        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;

        node.with_channel(&channel_id, |chan| {
            let cp_tx = setup_counterparty_commitment(
                chan,
                commit_num,
                to_holder,
                to_cp,
                offered_htlcs.clone(),
                received_htlcs.clone(),
                feerate_per_kw,
            )?;
            let indices = chan.get_spendable_htlc_indices(&cp_tx, commit_num)?;
            assert_eq!(indices.len(), 3);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_get_spendable_htlc_indices_no_htlcs() {
        let (node, channel_id, _, _, _) = setup_test_channel_with_htlcs();
        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;

        node.with_channel(&channel_id, |chan| {
            let cp_tx = setup_counterparty_commitment(
                chan,
                commit_num,
                to_holder,
                to_cp,
                vec![],
                vec![],
                feerate_per_kw,
            )?;
            let indices = chan.get_spendable_htlc_indices(&cp_tx, commit_num)?;
            assert_eq!(indices, Vec::<u32>::new());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_get_spendable_htlc_indices_errors() {
        let (node, channel_id, _, offered_htlcs, received_htlcs) = setup_test_channel_with_htlcs();
        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;

        node.with_channel(&channel_id, |chan| {
            let holder_tx = setup_holder_commitment(
                chan,
                commit_num,
                to_holder,
                to_cp,
                &offered_htlcs,
                &received_htlcs,
                feerate_per_kw,
            )?;

            let result = chan.get_spendable_htlc_indices(&holder_tx, commit_num + 5);
            assert!(result.is_err());
            assert!(result.unwrap_err().message().contains("commitment info not available"));

            Ok(())
        })
        .unwrap();
    }

    fn setup_test_channel_with_htlcs(
    ) -> (Arc<Node>, ChannelId, Vec<(PaymentPreimage, PaymentHash)>, Vec<HTLCInfo2>, Vec<HTLCInfo2>)
    {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let payment_hashes = make_test_payment_hashes(4);
        let (preimage_1, hash_1) = payment_hashes[0];
        let (_, hash_2) = payment_hashes[1];
        let (_, hash_3) = payment_hashes[2];
        let (_, hash_4) = payment_hashes[3];

        let offered_htlcs = vec![make_htlc(hash_1, 500, 100), make_htlc(hash_2, 600, 150)];
        let received_htlcs = vec![make_htlc(hash_3, 500, 200), make_htlc(hash_4, 600, 250)];

        {
            let mut node_state = node.get_state();
            let mut payment = RoutedPayment::new();
            payment.preimage = Some(preimage_1);
            node_state.payments.insert(hash_1, payment);
        }

        (node, channel_id, payment_hashes, offered_htlcs, received_htlcs)
    }

    fn setup_holder_commitment(
        chan: &mut Channel,
        commit_num: u64,
        to_holder: u64,
        to_cp: u64,
        offered_htlcs: &[HTLCInfo2],
        received_htlcs: &[HTLCInfo2],
        feerate_per_kw: u32,
    ) -> Result<Transaction, Status> {
        let holder_info2 = chan.build_holder_commitment_info(
            to_holder,
            to_cp,
            received_htlcs.to_vec(),
            offered_htlcs.to_vec(),
            feerate_per_kw,
        )?;

        chan.set_next_holder_commit_num_for_testing(commit_num + 1);
        let per_commitment_point = chan.get_per_commitment_point(commit_num)?;
        chan.enforcement_state.current_holder_commit_info = Some(holder_info2);

        let holder_htlcs = Channel::htlcs_info2_to_oic(&received_htlcs, &offered_htlcs);
        let holder_commitment_tx = chan.make_holder_commitment_tx(
            commit_num,
            &per_commitment_point,
            feerate_per_kw,
            to_holder,
            to_cp,
            holder_htlcs,
        );
        Ok(holder_commitment_tx.trust().built_transaction().transaction.clone())
    }

    fn setup_counterparty_commitment(
        chan: &mut Channel,
        commit_num: u64,
        to_holder: u64,
        to_cp: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> Result<Transaction, Status> {
        let per_commitment_point = make_test_pubkey(12);
        let cp_info2 = chan.build_counterparty_commitment_info(
            to_holder,
            to_cp,
            offered_htlcs.clone(),
            received_htlcs.clone(),
            feerate_per_kw,
        )?;
        chan.set_next_counterparty_commit_num_for_testing(
            commit_num + 1,
            per_commitment_point.clone(),
        );
        chan.enforcement_state.current_counterparty_commit_info = Some(cp_info2);

        let htlcs = Channel::htlcs_info2_to_oic(&offered_htlcs, &received_htlcs);
        let cp_commitment_tx = chan.make_counterparty_commitment_tx(
            &per_commitment_point,
            commit_num,
            feerate_per_kw,
            to_holder,
            to_cp,
            htlcs,
        );
        Ok(cp_commitment_tx.trust().built_transaction().transaction.clone())
    }

    #[test]
    fn test_get_current_holder_commitment_transaction() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, channel, _channel1) = setup_test_channel(&node, &node1, false, 0);
        let expected_commitment_number = channel.enforcement_state.next_holder_commit_num - 1;

        let commitment_tx = channel.get_current_holder_commitment_transaction().unwrap();

        let per_commitment_point =
            channel.get_per_commitment_point(expected_commitment_number).unwrap();

        let info2 = channel.enforcement_state.current_holder_commit_info.as_ref().unwrap();
        let fee_rate = if channel.setup.is_zero_fee_htlc() { 0 } else { info2.feerate_per_kw };
        let htlcs = Channel::htlcs_info2_to_oic(&info2.offered_htlcs, &info2.received_htlcs);

        let expected_tx = channel.make_holder_commitment_tx(
            expected_commitment_number,
            &per_commitment_point,
            fee_rate,
            info2.to_broadcaster_value_sat,
            info2.to_countersigner_value_sat,
            htlcs,
        );

        assert_eq!(commitment_tx, expected_tx);
    }

    #[test]
    fn test_get_current_holder_commitment_transaction_ignores_pending_next() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _channel1) = setup_test_channel(&node, &node1, false, 0);

        let current_tx = channel.get_current_holder_commitment_transaction().unwrap();
        let mut next_info = channel.enforcement_state.current_holder_commit_info.clone().unwrap();
        next_info.to_broadcaster_value_sat -= 1;
        next_info.to_countersigner_value_sat += 1;

        channel.enforcement_state.next_holder_commit_info =
            Some((next_info, CommitmentSignatures(Channel::dummy_sig(), Vec::new())));

        let commitment_tx = channel.get_current_holder_commitment_transaction().unwrap();

        assert_eq!(commitment_tx, current_tx);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_no_htlcs() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, false, 0);

        let (commitment_tx, htlc_txs, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&[], None).unwrap();

        assert!(htlc_txs.is_empty());

        verify_recovery_result(&channel, &commitment_tx, &htlc_txs);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_dry_run_leaves_channel_open() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, false, 0);

        assert!(!channel.enforcement_state.channel_closed);
        let (commitment_tx, htlc_txs, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery_dry_run(&[], None).unwrap();

        assert!(!channel.enforcement_state.channel_closed);
        verify_recovery_result(&channel, &commitment_tx, &htlc_txs);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_all_htlcs_spent() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 400);

        let (commitment_tx, htlc_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![true; 5], None).unwrap();

        assert!(htlc_batches.is_empty());

        verify_recovery_result(&channel, &commitment_tx, &htlc_batches);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_filters_spent_htlcs() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 400);

        let (commitment_tx, all_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();

        let mut spent = vec![false; 5];
        spent[0] = true;
        spent[2] = true;

        let (commitment_tx2, filtered_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&spent, None).unwrap();

        verify_recovery_result(&channel, &commitment_tx, &all_batches);
        verify_recovery_result(&channel, &commitment_tx2, &filtered_batches);

        let prevouts_before: HashSet<_> =
            all_batches.iter().flat_map(|tx| tx.input.iter().map(|i| i.previous_output)).collect();

        let prevouts_after: HashSet<_> = filtered_batches
            .iter()
            .flat_map(|tx| tx.input.iter().map(|i| i.previous_output))
            .collect();

        assert!(prevouts_after.is_subset(&prevouts_before));
        assert_eq!(prevouts_before.len() - prevouts_after.len(), 2);

        let total_inputs_before: usize = all_batches.iter().map(|tx| tx.input.len()).sum();
        let total_inputs_after: usize = filtered_batches.iter().map(|tx| tx.input.len()).sum();
        assert!(total_inputs_after < total_inputs_before);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_rejects_extra_spent_htlc_flags() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 400);

        let err =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 8], None).unwrap_err();
        assert!(err.message().contains("spent_htlc_indices length mismatch: 8 != 5"));
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_skips_future_offered_htlcs() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 120);

        let (commitment_tx, htlc_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();

        verify_recovery_result(&channel, &commitment_tx, &htlc_batches);

        let offered_locktimes: HashSet<_> = htlc_batches
            .iter()
            .map(|tx| tx.lock_time.to_consensus_u32())
            .filter(|locktime| *locktime > 0)
            .collect();

        assert_eq!(htlc_batches.len(), 2);
        assert_eq!(offered_locktimes, HashSet::from([100]));
        assert!(!offered_locktimes.contains(&150));
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_includes_offered_htlc_at_current_height() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 150);

        let (commitment_tx, htlc_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();

        verify_recovery_result(&channel, &commitment_tx, &htlc_batches);

        let offered_locktimes: HashSet<_> = htlc_batches
            .iter()
            .map(|tx| tx.lock_time.to_consensus_u32())
            .filter(|locktime| *locktime > 0)
            .collect();

        assert_eq!(htlc_batches.len(), 3);
        assert_eq!(offered_locktimes, HashSet::from([100, 150]));
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_batches_by_type_and_cltv() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 400);

        let (commitment_tx, htlc_batches, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();

        verify_recovery_result(&channel, &commitment_tx, &htlc_batches);

        assert_eq!(htlc_batches.len(), 3);
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_static_htlcs_are_not_batched() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let (_, mut channel, _) = setup_test_channel_with_commitment_type(
            &node,
            &node1,
            true,
            400,
            CommitmentType::StaticRemoteKey,
        );

        let (commitment_tx, htlc_txs, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();

        verify_recovery_result(&channel, &commitment_tx, &htlc_txs);

        assert_eq!(htlc_txs.len(), 4);
        assert!(htlc_txs.iter().all(|tx| tx.input.len() == 1));
        assert!(htlc_txs.iter().all(|tx| tx.output.len() == 1));
    }

    #[test]
    fn test_sign_holder_commitment_tx_for_recovery_chain_height_override() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let node1 = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        // chain_height=120: the CLTV=150 offered HTLC is in the future and should be skipped
        let (_, mut channel, _) = setup_test_channel(&node, &node1, true, 120);

        let (_, batches_without_override, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], None).unwrap();
        assert_eq!(batches_without_override.len(), 2);

        // override to height=150: the CLTV=150 HTLC is now includeable
        let (_, batches_with_override, _, _, _) =
            channel.sign_holder_commitment_tx_for_recovery(&vec![false; 5], Some(150)).unwrap();
        assert_eq!(batches_with_override.len(), 3);
    }

    fn setup_test_channel(
        node: &Arc<Node>,
        counterparty: &Arc<Node>,
        with_htlcs: bool,
        chain_height: u32,
    ) -> (ChannelId, Channel, Channel) {
        setup_test_channel_with_commitment_type(
            node,
            counterparty,
            with_htlcs,
            chain_height,
            CommitmentType::AnchorsZeroFeeHtlc,
        )
    }

    fn setup_test_channel_with_commitment_type(
        node: &Arc<Node>,
        counterparty: &Arc<Node>,
        with_htlcs: bool,
        chain_height: u32,
        commitment_type: CommitmentType,
    ) -> (ChannelId, Channel, Channel) {
        let (channel_id, _) = node.new_channel_with_random_id(node).unwrap();
        let (channel_id1, _) = counterparty.new_channel_with_random_id(counterparty).unwrap();

        let points =
            node.get_channel(&channel_id).unwrap().lock().unwrap().get_channel_basepoints();
        let points1 = counterparty
            .get_channel(&channel_id1)
            .unwrap()
            .lock()
            .unwrap()
            .get_channel_basepoints();
        let holder_shutdown_key_path = DerivationPath::from(vec![]);
        let mut setup = make_test_channel_setup_with_points(true, points1.clone());
        setup.commitment_type = commitment_type;
        let mut counterparty_setup = make_test_channel_setup_with_points(false, points.clone());
        counterparty_setup.commitment_type = commitment_type;

        let mut channel = node
            .setup_channel(channel_id.clone(), None, setup, &holder_shutdown_key_path)
            .expect("setup_channel");
        let mut channel1 = counterparty
            .setup_channel(channel_id1.clone(), None, counterparty_setup, &holder_shutdown_key_path)
            .expect("setup_channel 1");

        channel.monitor =
            ChainMonitorBase::new(channel.monitor.funding_outpoint, chain_height, &channel_id);
        assert_eq!(channel.monitor.as_chain_state().current_height, chain_height);

        if with_htlcs {
            let (preimage_2, hash_2) =
                (PaymentPreimage([2; 32]), PaymentHash::from(PaymentPreimage([2; 32])));
            let (preimage_5, hash_5) =
                (PaymentPreimage([5; 32]), PaymentHash::from(PaymentPreimage([5; 32])));

            let hash_1 = PaymentHash::from(PaymentPreimage([1; 32]));
            let hash_3 = PaymentHash::from(PaymentPreimage([3; 32]));
            let hash_4 = PaymentHash::from(PaymentPreimage([4; 32]));

            let offered_htlcs = vec![make_htlc(hash_1, 700, 100), make_htlc(hash_3, 800, 150)];
            let received_htlcs = vec![
                make_htlc(hash_2, 500, 200),
                make_htlc(hash_4, 550, 250),
                make_htlc(hash_5, 600, 300),
            ];

            {
                let mut node_state = node.get_state();
                let mut node1_state = counterparty.get_state();

                for h in &offered_htlcs {
                    node_state.invoices.insert(
                        h.payment_hash,
                        make_invoice_state(h.payment_hash, h.value_sat, counterparty.get_id()),
                    );
                    node1_state.issued_invoices.insert(
                        h.payment_hash,
                        make_invoice_state(h.payment_hash, h.value_sat, counterparty.get_id()),
                    );
                }

                for (idx, h) in received_htlcs.iter().enumerate() {
                    node1_state.invoices.insert(
                        h.payment_hash,
                        make_invoice_state(h.payment_hash, h.value_sat, node.get_id()),
                    );
                    node_state.issued_invoices.insert(
                        h.payment_hash,
                        make_invoice_state(h.payment_hash, h.value_sat, node.get_id()),
                    );

                    // only some received HTLCs have known preimages
                    match idx {
                        0 =>
                            add_payment_with_preimage(&mut node_state.payments, hash_2, preimage_2),
                        2 =>
                            add_payment_with_preimage(&mut node_state.payments, hash_5, preimage_5),
                        _ => {}
                    }
                }
            }

            next_state(&mut channel, &mut channel1, 0, 2_999_000, 0, vec![], vec![]);
            next_state(&mut channel, &mut channel1, 1, 2_899_100, 0, offered_htlcs, received_htlcs);
        } else {
            next_state(&mut channel, &mut channel1, 0, 2_999_000, 0, vec![], vec![]);
        }
        (channel_id, channel, channel1)
    }

    fn make_invoice_state(hash: PaymentHash, value_sat: u64, payee: PublicKey) -> PaymentState {
        PaymentState {
            invoice_hash: hash.0,
            amount_msat: value_sat * 1000,
            payee,
            duration_since_epoch: Duration::from_secs(0),
            expiry_duration: Duration::from_secs(3600),
            is_fulfilled: false,
            payment_type: PaymentType::Invoice,
        }
    }

    fn add_payment_with_preimage(
        payments: &mut Map<PaymentHash, RoutedPayment>,
        hash: PaymentHash,
        preimage: PaymentPreimage,
    ) {
        let mut p = RoutedPayment::new();
        p.preimage = Some(preimage);
        payments.insert(hash, p);
    }

    fn verify_recovery_result(
        channel: &Channel,
        commitment_tx: &Transaction,
        htlc_batches: &[Transaction],
    ) {
        commitment_tx
            .verify(|outpoint| {
                if outpoint == &channel.setup.funding_outpoint {
                    let funding_redeemscript = make_funding_redeemscript(
                        &channel.keys.pubkeys(&channel.secp_ctx).funding_pubkey,
                        &channel.counterparty_pubkeys().funding_pubkey,
                    );
                    Some(TxOut {
                        value: Amount::from_sat(channel.setup.channel_value_sat),
                        script_pubkey: funding_redeemscript.to_p2wsh(),
                    })
                } else {
                    None
                }
            })
            .expect("Commitment transaction verified");

        let commitment_txid = commitment_tx.compute_txid();

        for (_, tx) in htlc_batches.iter().enumerate() {
            tx.verify(|outpoint| {
                if outpoint.txid == commitment_txid {
                    commitment_tx.output.get(outpoint.vout as usize).cloned()
                } else {
                    None
                }
            })
            .expect("HTLC batch transaction verified");
        }
    }
}
