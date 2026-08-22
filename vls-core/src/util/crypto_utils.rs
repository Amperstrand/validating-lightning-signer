use crate::prelude::*;
use bitcoin::hashes::sha256::Hash as BitcoinSha256;
use bitcoin::hashes::{sha256d, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::{
    self, ecdsa::Signature, schnorr, Message, PublicKey, Secp256k1, SecretKey,
};
use bitcoin::sighash::{EcdsaSighashType, TapSighash};
use bitcoin::taproot::TapTweakHash;
use bitcoin::PrivateKey;
use lightning::ln::channel_keys::{RevocationBasepoint, RevocationKey};
use lightning::sign::EntropySource;

fn hkdf_extract_expand(salt: &[u8], secret: &[u8], info: &[u8], output: &mut [u8]) {
    let mut hmac = HmacEngine::<BitcoinSha256>::new(salt);
    hmac.input(secret);
    let prk = Hmac::from_engine(hmac).to_byte_array();

    let mut t = [0; 32];
    let mut n: u8 = 0;

    for chunk in output.chunks_mut(32) {
        let mut hmac = HmacEngine::<BitcoinSha256>::new(&prk[..]);
        n = n.checked_add(1).expect("HKDF size limit exceeded.");
        if n != 1 {
            hmac.input(&t);
        }
        hmac.input(&info);
        hmac.input(&[n]);
        t = Hmac::from_engine(hmac).to_byte_array();
        chunk.copy_from_slice(&t);
    }
}

/// derive a secret from another secret using HKDF-SHA256
pub fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    hkdf_extract_expand(salt, secret, info, &mut result);
    result
}

pub(crate) fn hkdf_sha256_keys(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32 * 6] {
    let mut result = [0u8; 32 * 6];
    hkdf_extract_expand(salt, secret, info, &mut result);
    result
}

pub(crate) fn derive_public_key<T: secp256k1::Signing>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    base_point: &PublicKey,
) -> Result<PublicKey, secp256k1::Error> {
    let mut sha = BitcoinSha256::engine();
    sha.input(&per_commitment_point.serialize());
    sha.input(&base_point.serialize());
    let res = BitcoinSha256::from_engine(sha).to_byte_array();

    let hashkey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&res)?);
    base_point.combine(&hashkey)
}

/// Convert a [Signature] to Bitcoin signature bytes, with SIGHASH_ALL
pub fn signature_to_bitcoin_vec(sig: Signature) -> Vec<u8> {
    let mut sigvec = sig.serialize_der().to_vec();
    sigvec.push(EcdsaSighashType::All as u8);
    sigvec
}

/// Convert a [Signature] to Bitcoin signature bytes, with SIGHASH_ALL
pub fn schnorr_signature_to_bitcoin_vec(sig: schnorr::Signature) -> Vec<u8> {
    // taproot sighash type defaults to ALL
    let mut sigvec = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE);
    sigvec.extend_from_slice(&sig[..]);
    sigvec
}

/// Convert a Bitcoin signature bytes, with the specified EcdsaSighashType, to [Signature]
pub fn bitcoin_vec_to_signature(
    sigvec: &[u8],
    sighash_type: EcdsaSighashType,
) -> Result<Signature, secp256k1::Error> {
    let len = sigvec.len();
    if len == 0 {
        return Err(secp256k1::Error::InvalidSignature);
    }
    let mut sv = sigvec.to_vec();
    let mode = sv.pop().ok_or_else(|| secp256k1::Error::InvalidSignature)?;
    if mode != sighash_type as u8 {
        return Err(secp256k1::Error::InvalidSignature);
    }
    Ok(Signature::from_der(&sv[..])?)
}

/// Use the provided seed, or generate a random one
pub fn maybe_generate_seed(seed_opt: Option<[u8; 32]>) -> [u8; 32] {
    seed_opt.unwrap_or_else(generate_seed)
}

/// Generate a seed
pub fn generate_seed() -> [u8; 32] {
    #[cfg(feature = "std")]
    {
        use secp256k1::rand::RngCore;
        let mut seed = [0; 32];
        let mut rng = secp256k1::rand::rngs::OsRng;
        rng.fill_bytes(&mut seed);
        seed
    }
    #[cfg(not(feature = "std"))]
    unimplemented!("no RNG available in no_std environments yet");
}

pub(crate) fn ecdsa_sign(
    secp_ctx: &Secp256k1<secp256k1::All>,
    privkey: &PrivateKey,
    sighash: sha256d::Hash,
) -> Signature {
    let message = Message::from_digest(sighash.to_byte_array());
    secp_ctx.sign_ecdsa(&message, &privkey.inner)
}

/// Deterministically sign `msg` with `sk`, grinding for a low-R signature.
///
/// This mirrors LDK's internal `crypto::utils::sign` under the `grind_signatures` feature
/// (which vls-core enables on its `lightning` dependency), so signatures produced here match
/// those from LDK's public signing helpers byte-for-byte.
pub fn sign<C: secp256k1::Signing>(
    secp_ctx: &Secp256k1<C>,
    msg: &Message,
    sk: &SecretKey,
) -> Signature {
    secp_ctx.sign_ecdsa_low_r(msg, sk)
}

/// Sign `msg` with `sk` using auxiliary randomness, grinding for a low-R signature.
///
/// Mirrors LDK's internal `crypto::utils::sign_with_aux_rand` under `grind_signatures`. The
/// signature is non-deterministic (the nonce uses fresh entropy each call) but always low-R.
pub fn sign_with_aux_rand<C: secp256k1::Signing, ES: EntropySource + ?Sized>(
    secp_ctx: &Secp256k1<C>,
    msg: &Message,
    sk: &SecretKey,
    entropy_source: &ES,
) -> Signature {
    loop {
        let sig =
            secp_ctx.sign_ecdsa_with_noncedata(msg, sk, &entropy_source.get_secure_random_bytes());
        if sig.serialize_compact()[0] < 0x80 {
            break sig;
        }
    }
}

/// zbase32 alphabet, as used by lnd / core-lightning message signing.
const ZBASE_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// zbase32-encode bytes. Mirrors `lightning::util::base32`'s `ZBase32` encoder (which is not
/// public outside the `fuzzing` cfg) so we produce output identical to LDK's message signing.
fn zbase32_encode(data: &[u8]) -> String {
    let output_length = (data.len() * 8 + 4) / 5;
    let mut ret = Vec::with_capacity((data.len() + 4) / 5 * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }
        ret.push(ZBASE_ALPHABET[((buf[0] & 0xF8) >> 3) as usize]);
        ret.push(ZBASE_ALPHABET[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
        ret.push(ZBASE_ALPHABET[((buf[1] & 0x3E) >> 1) as usize]);
        ret.push(ZBASE_ALPHABET[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
        ret.push(ZBASE_ALPHABET[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
        ret.push(ZBASE_ALPHABET[((buf[3] & 0x7C) >> 2) as usize]);
        ret.push(ZBASE_ALPHABET[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
        ret.push(ZBASE_ALPHABET[(buf[4] & 0x1F) as usize]);
    }
    ret.truncate(output_length);
    String::from_utf8(ret).expect("zbase32 is valid UTF-8")
}

/// Encode a recoverable node-message signature into the lnd / core-lightning zbase32 string
/// returned by LDK's `NodeSigner::sign_message`.
///
/// The input is the 65-byte form produced by the VLS signer (`Node::sign_message` /
/// `SignMessageReply`): a 64-byte compact signature followed by the raw recovery id. LDK encodes
/// `zbase32([31 + recovery_id] ++ signature)`.
pub fn encode_signed_message(sig_and_recid: &[u8; 65]) -> String {
    let mut sigrec = Vec::with_capacity(65);
    sigrec.push(sig_and_recid[64] + 31);
    sigrec.extend_from_slice(&sig_and_recid[..64]);
    zbase32_encode(&sigrec)
}

pub(crate) fn taproot_sign(
    secp_ctx: &Secp256k1<secp256k1::All>,
    privkey: &PrivateKey,
    sighash: TapSighash,
    aux_rand: &[u8; 32],
) -> schnorr::Signature {
    let message = Message::from(sighash);
    let keypair = secp256k1::Keypair::from_secret_key(secp_ctx, &privkey.inner);
    let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, None);
    let tweaked_keypair = keypair.add_xonly_tweak(secp_ctx, &tweak.to_scalar()).unwrap();

    secp_ctx.sign_schnorr_with_aux_rand(&message, &tweaked_keypair, aux_rand)
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalent of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
pub(crate) fn derive_public_revocation_key<T: secp256k1::Verification>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    countersignatory_revocation_base_point: &RevocationBasepoint,
) -> Result<RevocationKey, ()> {
    let revocation_key = RevocationKey::from_basepoint(
        secp_ctx,
        &countersignatory_revocation_base_point,
        per_commitment_point,
    );
    Ok(revocation_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// zbase32 is unpadded: `n` bytes encode to exactly `ceil(n * 8 / 5)` characters.
    /// `encode_signed_message` only ever passes 65 bytes (a multiple of 5, so the final
    /// truncation is a no-op), which would leave the length arithmetic untested.
    #[test]
    fn zbase32_encode_length_is_unpadded() {
        for len in 0..=16usize {
            let encoded = zbase32_encode(&vec![0xABu8; len]);
            assert_eq!(encoded.len(), (len * 8 + 4) / 5, "zbase32 length for {} bytes", len);
        }
    }

    /// Pin the alphabet and bit ordering against a known z-base-32 vector.
    #[test]
    fn zbase32_encode_known_vector() {
        assert_eq!(zbase32_encode(b"hello"), "pb1sa5dx");
    }

    /// The grind loop must only emit low-R signatures (first byte of the compact
    /// encoding below 0x80); low-R keeps signatures one byte shorter, which affects
    /// transaction weight.
    #[test]
    fn sign_with_aux_rand_is_low_r() {
        struct FixedEntropy(core::cell::Cell<u8>);
        impl EntropySource for FixedEntropy {
            fn get_secure_random_bytes(&self) -> [u8; 32] {
                let n = self.0.get();
                self.0.set(n.wrapping_add(1));
                [n; 32]
            }
        }

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let entropy = FixedEntropy(core::cell::Cell::new(0));
        for i in 0..16u8 {
            let msg = Message::from_digest([i; 32]);
            let sig = sign_with_aux_rand(&secp, &msg, &sk, &entropy);
            assert!(sig.serialize_compact()[0] < 0x80, "expected a low-R signature");
        }
    }

    #[test]
    fn encode_signed_message_matches_ldk() {
        // Our `encode_signed_message` must produce the exact zbase32 string LDK's
        // `NodeSigner::sign_message` returns (LDK's `message_signing::sign`).
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        for msg in [&b""[..], b"hello world", b"a slightly longer test message \x00\xff"] {
            let expected = lightning::util::message_signing::sign(msg, &sk);

            // Reproduce the VLS signer's 65-byte output: 64-byte sig followed by raw recovery id.
            let secp = Secp256k1::signing_only();
            let digest =
                sha256d::Hash::hash(&[b"Lightning Signed Message:".as_ref(), msg].concat());
            let rsig =
                secp.sign_ecdsa_recoverable(&Message::from_digest(digest.to_byte_array()), &sk);
            let (rid, sig) = rsig.serialize_compact();
            let mut bytes = [0u8; 65];
            bytes[..64].copy_from_slice(&sig);
            bytes[64] = rid.to_i32() as u8;

            assert_eq!(encode_signed_message(&bytes), expected, "mismatch for msg {:?}", msg);
        }
    }

    #[test]
    fn hkdf_tests() {
        let secret = [1u8];
        let info = [2u8];
        let salt = [3u8];
        let mut output = [0u8; 32 * 6];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(hex::encode(output), "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0efbbb13e74af4687137801e1628d1d1876d251b31d1321383568a9387da7c0baa7dee83ba374bba3774ef01140e4c4293791a512e536764bf4405aea511be32d5fd71a0b7a7ef3638312e476eb323fbac5f3d549ccf0fe0eabb38fe7bc16ad01db2288e57de45eabecd561ede4dc89164099ed7f0b0db5250e2b377e2aa84f520838612dccbde870f7b06a1e03f3cd79d30da717c55e15442a0b4dd02aafcd86");
        let mut output = [0u8; 32];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(
            hex::encode(output),
            "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0"
        );

        let secret = [1u8];
        let info = [2u8];
        let salt = [3u8];
        let result = hkdf_sha256(&secret, &info, &salt);
        assert_eq!(
            hex::encode(result),
            "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0"
        );

        let secret = [1u8];
        let info = [2u8];
        let salt = [3u8];
        let result = hkdf_sha256_keys(&secret, &info, &salt);
        assert_eq!(result.len(), 32 * 6);
        let expected_prefix = "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0";
        assert_eq!(hex::encode(&result[..32]), expected_prefix);
    }

    #[test]
    fn test_schnorr_signature_to_bitcoin_vec() {
        let test_signature_bytes: Vec<u8> = vec![0; 64];
        let test_signature = schnorr::Signature::from_slice(&test_signature_bytes).unwrap();
        let result = schnorr_signature_to_bitcoin_vec(test_signature);
        assert_eq!(test_signature_bytes, result);
    }

    #[test]
    fn test_bitcoin_vec_to_signature() {
        let sighash_type = EcdsaSighashType::All;
        let sigvec: Vec<u8> = vec![];
        let result = bitcoin_vec_to_signature(&sigvec, sighash_type);
        assert_eq!(result, Err(secp256k1::Error::InvalidSignature));

        let mut sigvec = hex::decode(
            "304402202e1f64d831e89e2b4a0dc8565cb2d0a4d6061a89f9b48f2c26d5ac0b3b9a0bb102200c8d396f8b2e9c6c623bebc015c47f1f41e8824fabe7cb028f174a0e5df3c0a0"
        ).unwrap();
        sigvec.push(1 as u8);
        let result = bitcoin_vec_to_signature(&sigvec, sighash_type).unwrap();
        sigvec.pop();
        let parsed_signature = Signature::from_der(&sigvec).expect("valid DER signature");
        assert_eq!(result, parsed_signature);
    }

    #[test]
    fn test_maybe_generate_seed() {
        let known_seed: [u8; 32] = [1; 32];
        let result = maybe_generate_seed(Some(known_seed));
        assert_eq!(result, known_seed);

        let result = maybe_generate_seed(None);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_taproot_sign() {
        let secp = Secp256k1::new();
        let privkey_bytes =
            hex::decode("d8d3a3140ba89f14144b0dfe40e04220e02ed68736a5773e050a3c4116b1e31c")
                .unwrap();
        let secret_key =
            SecretKey::from_slice(&privkey_bytes).expect("32 bytes, within curve order");
        let privkey = PrivateKey::new(secret_key, Network::Bitcoin);
        let sighash = TapSighash::hash(&[0]);
        let aux_rand: [u8; 32] = [0u8; 32];
        let signature = taproot_sign(&secp, &privkey, sighash, &aux_rand);
        let expected_signature_hex =
            "14262eb13409cd8928536ab60f431b95193d2d9c7cc476e9f43e8b8f98a8d5a8c38d3edc7bf43c389a12c9e5fad9485ee5d59df2d35f46c3f77ca07197ee1db2";
        assert_eq!(expected_signature_hex, signature.to_string());
    }

    #[test]
    fn test_derive_public_key() {
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[2; 32]).unwrap();
        let base_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let per_commitment_point = PublicKey::from_secret_key(&secp, &per_commitment_secret);
        let base_point = PublicKey::from_secret_key(&secp, &base_secret);

        let result = derive_public_key(&secp, &per_commitment_point, &base_point).unwrap();
        let expected = PublicKey::from_slice(
            &hex::decode("038f363030fd6822d5b3cfaa650fe3c37ed218e3761bbd5e7585779aeb5ac191f3")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_signature_to_bitcoin_vec() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let message = Message::from_digest([2; 32]);
        let sig = secp.sign_ecdsa(&message, &secret_key);
        let result = signature_to_bitcoin_vec(sig);
        let expected = vec![
            48, 69, 2, 33, 0, 151, 239, 48, 35, 62, 173, 37, 209, 15, 123, 178, 191, 158, 175, 87,
            26, 22, 242, 222, 179, 58, 117, 242, 8, 25, 40, 79, 12, 184, 255, 60, 193, 2, 32, 72,
            112, 202, 5, 148, 1, 153, 193, 19, 180, 220, 119, 134, 111, 0, 23, 2, 105, 28, 222, 38,
            159, 104, 53, 88, 30, 122, 234, 30, 173, 38, 96, 1,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_generate_seed() {
        #[cfg(feature = "std")]
        {
            let seed = generate_seed();
            assert_eq!(seed.len(), 32);
            assert_ne!(seed, [0; 32]);
        }
        #[cfg(not(feature = "std"))]
        {
            let result = std::panic::catch_unwind(|| generate_seed());
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ecdsa_sign() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let privkey = PrivateKey::new(secret_key, Network::Bitcoin);
        let sighash = sha256d::Hash::hash(&[2; 32]);
        let sig = ecdsa_sign(&secp, &privkey, sighash);
        let message = Message::from_digest(sighash.to_byte_array());
        let pubkey = PublicKey::from_secret_key(&secp, &secret_key);
        secp.verify_ecdsa(&message, &sig, &pubkey).unwrap();
    }

    #[test]
    fn test_derive_public_revocation_key() {
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[2; 32]).unwrap();
        let base_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let per_commitment_point = PublicKey::from_secret_key(&secp, &per_commitment_secret);
        let base_point = RevocationBasepoint::from(PublicKey::from_secret_key(&secp, &base_secret));

        let result =
            derive_public_revocation_key(&secp, &per_commitment_point, &base_point).unwrap();
        let expected = RevocationKey::from_basepoint(&secp, &base_point, &per_commitment_point);
        assert_eq!(result, expected);
    }
}
