use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use electrum_vls_spike::bridge::{make_bridge, serve};
use lightning_signer::bitcoin::hashes::sha256::Hash as Sha256;
use lightning_signer::bitcoin::hashes::Hash as _HashTrait;
use lightning_signer::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning_signer::bitcoin::{Network, Txid};
use serde_json::{json, Value};

struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Client {
    fn connect(socket_path: &str) -> Client {
        let mut last_err = None;
        for _ in 0..100 {
            match UnixStream::connect(socket_path) {
                Ok(stream) => {
                    let reader = BufReader::new(stream.try_clone().expect("clone stream"));
                    return Client { stream, reader, next_id: 0 };
                }
                Err(e) => {
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        panic!("could not connect to {socket_path}: {last_err:?}");
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({"id": self.next_id, "method": method, "params": params});
        self.stream
            .write_all(format!("{request}\n").as_bytes())
            .expect("write request");
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read response");
        let response: Value = serde_json::from_str(line.trim_end()).expect("parse response");
        assert!(
            response.get("error").is_none(),
            "rpc error for {method}: {response}"
        );
        response["result"].clone()
    }
}

fn hex_vec(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn fabricated_pubkey(label: &str) -> String {
    let secp = Secp256k1::new();
    let secret =
        SecretKey::from_slice(&Sha256::hash(label.as_bytes()).to_byte_array()).expect("secret");
    hex::encode(PublicKey::from_secret_key(&secp, &secret).serialize())
}

#[test]
fn bridge_serves_electrum_keys_and_points() {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/electrum_kat.json")).expect("vectors");
    let case = &vectors["cases"][0];
    let wallet_seed: [u8; 32] = hex_vec(&case["wallet_seed"]).try_into().expect("32 bytes");
    let channel_seed_hex = case["channel_seed"].as_str().expect("channel seed");

    let socket_path = std::env::temp_dir()
        .join(format!("vls-bridge-test-{}.sock", std::process::id()))
        .to_str()
        .expect("socket path")
        .to_string();
    let bridge = make_bridge(wallet_seed, Network::Regtest);
    let server_socket = socket_path.clone();
    thread::spawn(move || serve(bridge, &server_socket).expect("serve"));
    let mut client = Client::connect(&socket_path);

    let info = client.call("node_info", json!({}));
    assert_eq!(
        info["node_id"].as_str().expect("node id"),
        case["node_key"]["pubkey"].as_str().expect("expected node id"),
        "bridge node_id must equal Electrum's node key"
    );

    let new_channel = client.call("new_channel", json!({"channel_seed": channel_seed_hex}));
    let pubkeys = &new_channel["pubkeys"];
    assert_eq!(
        pubkeys["funding_pubkey"].as_str().unwrap(),
        case["multisig_key"]["pubkey"].as_str().unwrap()
    );
    assert_eq!(
        pubkeys["htlc_basepoint"].as_str().unwrap(),
        case["htlc_basepoint"]["pubkey"].as_str().unwrap()
    );
    assert_eq!(
        pubkeys["delayed_payment_basepoint"].as_str().unwrap(),
        case["delayed_basepoint"]["pubkey"].as_str().unwrap()
    );
    assert_eq!(
        pubkeys["revocation_basepoint"].as_str().unwrap(),
        case["revocation_basepoint"]["pubkey"].as_str().unwrap()
    );
    let channel_id = new_channel["channel_id"].clone();

    let funding_txid = {
        let mut bytes = [1u8; 32];
        bytes[0] = 2;
        Txid::from_slice(&bytes).expect("txid").to_string()
    };
    let counterparty_points = json!({
        "funding_pubkey": fabricated_pubkey("cp funding"),
        "revocation_basepoint": fabricated_pubkey("cp revocation"),
        "payment_point": fabricated_pubkey("cp payment"),
        "delayed_payment_basepoint": fabricated_pubkey("cp delayed"),
        "htlc_basepoint": fabricated_pubkey("cp htlc"),
    });
    client.call(
        "setup_channel",
        json!({
            "channel_id": channel_id,
            "is_outbound": true,
            "channel_value_sat": 123456,
            "push_value_msat": 0,
            "funding_txid": funding_txid,
            "funding_vout": 1,
            "holder_selected_contest_delay": 10,
            "counterparty_selected_contest_delay": 11,
            "commitment_type": "StaticRemoteKey",
            "counterparty_points": counterparty_points,
        }),
    );
    client.call(
        "confirm_funding_lock",
        json!({"channel_id": channel_id, "funding_txid": funding_txid, "funding_vout": 1}),
    );

    let shachain = case["shachain"].as_array().expect("shachain");
    for (ctn, entry) in shachain.iter().take(2).enumerate() {
        assert_eq!(entry["ctn"].as_u64().unwrap(), ctn as u64);
        let result = client.call(
            "get_per_commitment_point",
            json!({"channel_id": channel_id, "ctn": ctn}),
        );
        assert_eq!(
            result["point"].as_str().unwrap(),
            entry["point"].as_str().unwrap(),
            "per-commitment point at ctn {ctn} must equal Electrum's"
        );
    }

    let _ = std::fs::remove_file(&socket_path);
}
