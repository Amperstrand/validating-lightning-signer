use electrum_vls_spike::*;
use serde_json::Value;
use lightning_signer::bitcoin::bip32::Xpriv;
use lightning_signer::bitcoin::hashes::sha256::Hash as Sha256;
use lightning_signer::bitcoin::hashes::Hash as _HashTrait;
use lightning_signer::bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use lightning_signer::bitcoin::Network;
use lightning_signer::lightning::ln::chan_utils::build_commitment_secret;
use lightning_signer::signer::derive::KeyDerive;

fn derive_pubkey_bolt3(
    secp: &Secp256k1<lightning_signer::bitcoin::secp256k1::All>,
    basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let mut msg = Vec::with_capacity(66);
    msg.extend_from_slice(&per_commitment_point.serialize());
    msg.extend_from_slice(&basepoint.serialize());
    let tweak = SecretKey::from_slice(&Sha256::hash(&msg)[..]).expect("valid tweak");
    basepoint
        .add_exp_tweak(secp, &Scalar::from(tweak))
        .expect("blinding tweak")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().expect("32 bytes")
}

fn h33(v: &Value) -> [u8; 33] {
    h(v).try_into().expect("33 bytes")
}

struct Kp {
    sk: SecretKey,
    pk: lightning_signer::bitcoin::secp256k1::PublicKey,
}

fn assert_kp(case: &str, what: &str, want: &Value, got: &Kp) {
    let want_priv = h(&want["privkey"]);
    let want_pub = h(&want["pubkey"]);
    assert_eq!(
        got.sk.secret_bytes().to_vec(),
        want_priv,
        "{case}/{what} privkey mismatch"
    );
    assert_eq!(
        got.pk.serialize().to_vec(),
        want_pub,
        "{case}/{what} pubkey mismatch"
    );
}

fn as_kp(sk: SecretKey, pk: lightning_signer::bitcoin::secp256k1::PublicKey) -> Kp {
    Kp { sk, pk }
}

#[test]
fn kat_matches_electrum_lnutil() {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/electrum_kat.json")).expect("valid vector file");
    let secp = Secp256k1::new();
    let start_index = vectors["start_index"].as_u64().expect("start_index");
    assert_eq!(start_index, START_INDEX);

    for case in vectors["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let wallet_seed = h32(&case["wallet_seed"]);
        let channel_seed = h32(&case["channel_seed"]);
        let remote_node_id = h(&case["remote_node_id"]);
        let remote_funding_pubkey = h33(&case["remote_funding_pubkey"]);
        let nlocktime = case["nlocktime"].as_u64().expect("nlocktime") as u32;
        let network = Network::Bitcoin;

        let (sk, pk) = node_keypair(&wallet_seed, network, &secp);
        assert_kp(name, "node_key", &case["node_key"], &as_kp(sk, pk));
        let (sk, pk) = funding_root_keypair(&wallet_seed, network, &secp);
        assert_kp(name, "funding_root_key", &case["funding_root_key"], &as_kp(sk, pk));
        let (sk, pk) = static_payment_keypair(&wallet_seed, network, &secp);
        assert_kp(name, "static_payment_key", &case["static_payment_key"], &as_kp(sk, pk));

        let channel_master = Xpriv::new_master(network, &channel_seed).expect("channel seed");
        let (sk, pk) = family_keypair(&channel_master, 0, true, &secp);
        assert_kp(name, "multisig_key", &case["multisig_key"], &as_kp(sk, pk));
        let (sk, pk) = family_keypair(&channel_master, 1, true, &secp);
        assert_kp(name, "revocation_basepoint", &case["revocation_basepoint"], &as_kp(sk, pk));
        let (htlc_sk, htlc_pk) = family_keypair(&channel_master, 2, true, &secp);
        assert_kp(name, "htlc_basepoint", &case["htlc_basepoint"], &as_kp(htlc_sk, htlc_pk));
        let (delayed_sk, delayed_pk) = family_keypair(&channel_master, 4, true, &secp);
        assert_kp(name, "delayed_basepoint", &case["delayed_basepoint"], &as_kp(delayed_sk, delayed_pk));
        let (revocation_root_sk, _) = family_keypair(&channel_master, 5, true, &secp);
        assert_eq!(
            hex::encode(revocation_root_sk.secret_bytes()),
            case["per_commitment_secret_seed"].as_str().expect("pcss"),
            "{name}/per_commitment_secret_seed mismatch"
        );
        let pcss: [u8; 32] = h32(&case["per_commitment_secret_seed"]);

        let (fr_sk, _) = funding_root_keypair(&wallet_seed, network, &secp);
        let (sk, pk) = anchors_funding_key_we_opened(
            &fr_sk.secret_bytes(),
            &remote_node_id,
            nlocktime,
            &secp,
        );
        assert_kp(
            name,
            "anchors_funding_key_we_opened",
            &case["anchors_funding_key_we_opened"],
            &as_kp(sk, pk),
        );
        let (sk, pk) = anchors_funding_key_they_opened(
            &fr_sk.secret_bytes(),
            &remote_node_id,
            &remote_funding_pubkey,
            &secp,
        );
        assert_kp(
            name,
            "anchors_funding_key_they_opened",
            &case["anchors_funding_key_they_opened"],
            &as_kp(sk, pk),
        );
        let (sp_sk, _) = static_payment_keypair(&wallet_seed, network, &secp);
        let multisig_pubkey = h33(&case["multisig_key"]["pubkey"]);
        let (sk, pk) = anchors_payment_basepoint(&sp_sk.secret_bytes(), &multisig_pubkey, &secp);
        assert_kp(
            name,
            "payment_basepoint",
            &case["payment_basepoint"],
            &as_kp(sk, pk),
        );

        let mut point_ctn0 = None;
        let mut point_ctn1 = None;
        for entry in case["shachain"].as_array().expect("shachain") {
            let ctn = entry["ctn"].as_u64().expect("ctn");
            let index = entry["index"].as_u64().expect("index");
            assert_eq!(index, ctn_to_shachain_index(ctn), "{name} ctn->index mapping");
            let secret = per_commitment_secret(&pcss, index);
            assert_eq!(
                hex::encode(secret),
                entry["secret"].as_str().expect("secret"),
                "{name} shachain secret ctn={ctn}"
            );
            let point = lightning_signer::bitcoin::secp256k1::PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&secret).expect("valid secret"),
            );
            assert_eq!(
                hex::encode(point.serialize()),
                entry["point"].as_str().expect("point"),
                "{name} shachain point ctn={ctn}"
            );
            if ctn == 0 {
                point_ctn0 = Some(point);
            }
            if ctn == 1 {
                point_ctn1 = Some(point);
            }
        }

        let blinded = &case["blinded"];
        assert_eq!(
            hex::encode(
                derive_pubkey_bolt3(&secp, &htlc_pk, &point_ctn0.expect("ctn0 point")).serialize()
            ),
            blinded["htlc_at_ctn0"].as_str().expect("blinded htlc"),
            "{name} BOLT3 blinding (LDK derive_public_key) vs Electrum derive_pubkey"
        );
        assert_eq!(
            hex::encode(
                derive_pubkey_bolt3(&secp, &delayed_pk, &point_ctn1.expect("ctn1 point"))
                    .serialize()
            ),
            blinded["delayed_at_ctn1"].as_str().expect("blinded delayed"),
            "{name} BOLT3 blinding (LDK derive_public_key) vs Electrum derive_pubkey"
        );

        let mut diverge = 0usize;
        let total = case["shachain"].as_array().expect("shachain").len();
        for entry in case["shachain"].as_array().expect("shachain") {
            let index = entry["index"].as_u64().expect("index");
            let secret = entry["secret"].as_str().expect("secret");
            if hex::encode(build_commitment_secret(&pcss, index)) != secret {
                diverge += 1;
            }
        }
        println!(
            "{name}: vls-core build_commitment_secret vs Electrum shachain: {diverge}/{total} divergent \
             over scattered indices (0 = vls-core per-commitment machinery is Electrum-compatible)"
        );
    }
}

#[test]
fn key_derive_trait_impl_agrees_with_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/electrum_kat.json")).expect("valid vector file");
    let secp = Secp256k1::new();
    let derive = ElectrumKeyDerive::new(Network::Bitcoin);

    for case in vectors["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let wallet_seed = h32(&case["wallet_seed"]);
        let channel_seed = h32(&case["channel_seed"]);
        let master = derive.master_key(&wallet_seed);

        let (pk, sk) = derive.node_keys(&wallet_seed, &secp);
        assert_kp(name, "trait node_keys", &case["node_key"], &as_kp(sk, pk));

        let (funding, revocation_base, htlc, _payment, delayed, commitment_seed) =
            derive.channel_keys(&wallet_seed, &channel_seed, 0, &master, &secp);
        assert_eq!(
            hex::encode(funding.secret_bytes()),
            case["multisig_key"]["privkey"].as_str().expect("priv"),
            "{name} trait channel_keys funding"
        );
        assert_eq!(
            hex::encode(revocation_base.secret_bytes()),
            case["revocation_basepoint"]["privkey"].as_str().expect("priv"),
            "{name} trait channel_keys revocation_base"
        );
        assert_eq!(
            hex::encode(htlc.secret_bytes()),
            case["htlc_basepoint"]["privkey"].as_str().expect("priv"),
            "{name} trait channel_keys htlc"
        );
        assert_eq!(
            hex::encode(delayed.secret_bytes()),
            case["delayed_basepoint"]["privkey"].as_str().expect("priv"),
            "{name} trait channel_keys delayed"
        );
        assert_eq!(
            hex::encode(commitment_seed),
            case["per_commitment_secret_seed"].as_str().expect("pcss"),
            "{name} trait channel_keys commitment_seed"
        );
    }
}
