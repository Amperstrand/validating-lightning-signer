//! Fork-local spike: teach VLS how the Electrum wallet derives lightning keys.
//!
//! Mirrors `electrum/lnutil.py` (spesmilo/electrum). Wallet-level keys derive
//! from the lightning xprv at `m/67'/`; channel-level keys derive from a
//! per-channel random 32-byte `channel_seed` used as a fresh BIP32 root.
//! Anchors channels additionally derive the multisig funding key and the
//! payment basepoint from wallet-level secrets plus channel context; because
//! the `KeyDerive` trait carries no channel context, those are standalone
//! functions for the M2 setup seam, and `channel_keys()` returns the
//! channel-seed family keys (legacy semantics) instead.
//!
//! Per-commitment secrets use the BOLT-3 shachain over
//! `per_commitment_secret_seed` with index `START_INDEX - ctn`. vls-core's
//! built-in `chan_utils::build_commitment_secret` implements LDK's scheme,
//! which differs; the KAT documents the divergence and an Electrum style must
//! override the per-commitment derivation in M2.

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{self, PublicKey, SecretKey, Secp256k1, Signing};
use bitcoin::Network;

use lightning_signer::bitcoin;
use lightning_signer::signer::derive::KeyDerive;

pub const NODE_ID_PREFIX_LEN: usize = 16;
pub const NUM_BITS: u64 = 48;
pub const START_INDEX: u64 = (1u64 << NUM_BITS) - 1;

// LnKeyFamily indices from electrum/lnutil.py; every family is hardened
// except NODE_KEY.
const FAMILY_MULTISIG: u32 = 0;
const FAMILY_REVOCATION_BASE: u32 = 1;
const FAMILY_HTLC_BASE: u32 = 2;
const FAMILY_PAYMENT_BASE: u32 = 3;
const FAMILY_DELAY_BASE: u32 = 4;
const FAMILY_REVOCATION_ROOT: u32 = 5;
const FAMILY_NODE_KEY: u32 = 6;
const FAMILY_FUNDING_ROOT_KEY: u32 = 10;

/// Derive keys for nodes and channels the way Electrum does.
#[derive(Clone, Debug)]
pub struct ElectrumKeyDerive {
    network: Network,
}

impl ElectrumKeyDerive {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

impl KeyDerive for ElectrumKeyDerive {
    fn master_key(&self, seed: &[u8]) -> Xpriv {
        Xpriv::new_master(self.network, seed).expect("seed produces master key")
    }

    fn node_keys(
        &self,
        seed: &[u8],
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (PublicKey, SecretKey) {
        let master = self.master_key(seed);
        let ln_root = derive_path_priv(
            &master,
            &[ChildNumber::from_hardened_idx(67).expect("static index")],
            secp_ctx,
        );
        let (sk, pk) = family_keypair(&ln_root, FAMILY_NODE_KEY, false, secp_ctx);
        (pk, sk)
    }

    fn channel_keys(
        &self,
        _seed: &[u8],
        keys_id: &[u8; 32],
        _basepoint_index: u32,
        _master_key: &Xpriv,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        // keys_id carries Electrum's random per-channel channel_seed, which is
        // itself a fresh BIP32 root — it is not derived from the node seed.
        let channel_master = Xpriv::new_master(self.network, keys_id).expect("channel seed");
        let (multisig, _) = family_keypair(&channel_master, FAMILY_MULTISIG, true, secp_ctx);
        let (revocation_base, _) = family_keypair(&channel_master, FAMILY_REVOCATION_BASE, true, secp_ctx);
        let (htlc_base, _) = family_keypair(&channel_master, FAMILY_HTLC_BASE, true, secp_ctx);
        let (payment, _) = family_keypair(&channel_master, FAMILY_PAYMENT_BASE, true, secp_ctx);
        let (delayed, _) = family_keypair(&channel_master, FAMILY_DELAY_BASE, true, secp_ctx);
        let (revocation_root, _) = family_keypair(&channel_master, FAMILY_REVOCATION_ROOT, true, secp_ctx);
        (
            multisig,
            revocation_base,
            htlc_base,
            payment,
            delayed,
            revocation_root.secret_bytes(),
        )
    }
}

fn derive_path_priv<X: Signing>(
    node: &Xpriv,
    path: &[ChildNumber],
    secp: &Secp256k1<X>,
) -> Xpriv {
    node.derive_priv(secp, &path.to_vec()).expect("hardened derivation cannot fail")
}

pub fn family_keypair<X: Signing>(
    node: &Xpriv,
    family: u32,
    hardened: bool,
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let f = if hardened {
        ChildNumber::from_hardened_idx(family).expect("family index")
    } else {
        ChildNumber::from_normal_idx(family).expect("family index")
    };
    let path = vec![
        f,
        ChildNumber::from_normal_idx(0).expect("static index"),
        ChildNumber::from_normal_idx(0).expect("static index"),
    ];
    let child = derive_path_priv(node, &path, secp);
    let sk = child.private_key;
    let pk = PublicKey::from_secret_key(secp, &sk);
    (sk, pk)
}

pub fn ln_root_from_seed<X: Signing>(
    wallet_seed: &[u8],
    network: Network,
    secp: &Secp256k1<X>,
) -> Xpriv {
    let master = Xpriv::new_master(network, wallet_seed).expect("seed produces master key");
    derive_path_priv(
        &master,
        &[ChildNumber::from_hardened_idx(67).expect("static index")],
        secp,
    )
}

pub fn node_keypair<X: Signing>(
    wallet_seed: &[u8],
    network: Network,
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let ln_root = ln_root_from_seed(wallet_seed, network, secp);
    family_keypair(&ln_root, FAMILY_NODE_KEY, false, secp)
}

pub fn funding_root_keypair<X: Signing>(
    wallet_seed: &[u8],
    network: Network,
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let ln_root = ln_root_from_seed(wallet_seed, network, secp);
    family_keypair(&ln_root, FAMILY_FUNDING_ROOT_KEY, true, secp)
}

pub fn static_payment_keypair<X: Signing>(
    wallet_seed: &[u8],
    network: Network,
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let ln_root = ln_root_from_seed(wallet_seed, network, secp);
    family_keypair(&ln_root, FAMILY_PAYMENT_BASE, true, secp)
}

pub fn bip340_tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    // BIP-340: the tag digest appears twice.
    let tag_hash = Sha256::hash(tag);
    let mut engine = Sha256::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(msg);
    let out = Sha256::from_engine(engine);
    let bytes: [u8; 32] = out[..].try_into().expect("32 bytes");
    bytes
}

pub fn anchors_funding_key_we_opened<X: Signing>(
    funding_root_secret: &[u8; 32],
    remote_node_id_or_prefix: &[u8],
    nlocktime: u32,
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let mut msg = Vec::with_capacity(32 + NODE_ID_PREFIX_LEN + 4);
    msg.extend_from_slice(funding_root_secret);
    msg.extend_from_slice(&remote_node_id_or_prefix[..NODE_ID_PREFIX_LEN]);
    msg.extend_from_slice(&nlocktime.to_le_bytes());
    secret_from(bip340_tagged_hash(b"electrum/ln_multisig_funding_key/we_opened", &msg), secp)
}

pub fn anchors_funding_key_they_opened<X: Signing>(
    funding_root_secret: &[u8; 32],
    remote_node_id_or_prefix: &[u8],
    remote_funding_pubkey: &[u8; 33],
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let mut msg = Vec::with_capacity(32 + NODE_ID_PREFIX_LEN + 33);
    msg.extend_from_slice(funding_root_secret);
    msg.extend_from_slice(&remote_node_id_or_prefix[..NODE_ID_PREFIX_LEN]);
    msg.extend_from_slice(remote_funding_pubkey);
    secret_from(bip340_tagged_hash(b"electrum/ln_multisig_funding_key/they_opened", &msg), secp)
}

pub fn anchors_payment_basepoint<X: Signing>(
    static_payment_secret: &[u8; 32],
    funding_pubkey: &[u8; 33],
    secp: &Secp256k1<X>,
) -> (SecretKey, PublicKey) {
    let mut msg = Vec::with_capacity(32 + 33);
    msg.extend_from_slice(static_payment_secret);
    msg.extend_from_slice(funding_pubkey);
    secret_from(Sha256::hash(&msg).to_byte_array(), secp)
}

fn secret_from<X: Signing>(digest: [u8; 32], secp: &Secp256k1<X>) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_slice(&digest).expect("valid secret");
    let pk = PublicKey::from_secret_key(secp, &sk);
    (sk, pk)
}

pub fn per_commitment_secret(seed: &[u8; 32], index: u64) -> [u8; 32] {
    let mut secret: Vec<u8> = seed.to_vec();
    for bitindex in (0..NUM_BITS as usize).rev() {
        if index & (1u64 << bitindex) != 0 {
            secret[bitindex / 8] ^= 1 << (bitindex % 8);
            secret = Sha256::hash(&secret)[..].to_vec();
        }
    }
    secret.try_into().expect("32 bytes")
}

pub fn ctn_to_shachain_index(ctn: u64) -> u64 {
    START_INDEX.checked_sub(ctn).expect("ctn beyond START_INDEX")
}

pub fn keys_id_from_channel_seed(channel_seed: &[u8; 32]) -> [u8; 32] {
    *channel_seed
}
