//! JSON-lines RPC over a Unix socket exposing a vls-core Node configured with
//! Electrum key derivation. Fork-local M2 sidecar skeleton: the future
//! Electrum plugin taps channel state and speaks this protocol.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use lightning_signer::bitcoin::bip32::DerivationPath;
use lightning_signer::bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning_signer::bitcoin::{Network, OutPoint, Txid};
use lightning_signer::channel::{ChannelBase, ChannelId, ChannelSetup, ChannelSlot, CommitmentType};
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::channel_keys::{
    DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint,
};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::util::status::Status;
use lightning_signer::util::test_utils::make_services;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Bridge {
    pub node: Arc<Node>,
    pub network: Network,
}

pub fn make_bridge(wallet_seed: [u8; 32], network: Network) -> Bridge {
    let config = NodeConfig {
        network,
        key_derivation_style: KeyDerivationStyle::Electrum,
        use_checkpoints: false,
        allow_deep_reorgs: true,
    };
    let services = make_services();
    Bridge {
        node: Arc::new(Node::new(config, &wallet_seed, vec![], services)),
        network,
    }
}

pub fn serve(bridge: Bridge, socket_path: &str) -> std::io::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    eprintln!("vls-bridge listening on {socket_path}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let bridge = bridge.clone();
                thread::spawn(move || handle_connection(stream, bridge));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle_connection(stream: UnixStream, bridge: Bridge) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let response = dispatch(&bridge, line.trim_end());
                if writer.write_all(format!("{response}\n").as_bytes()).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn dispatch(bridge: &Bridge, line: &str) -> Value {
    let parsed: Result<Value, _> = serde_json::from_str(line);
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) => {
            return json!({"error": {"code": -32700, "message": format!("parse error: {e}")}})
        }
    };
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let method = match parsed.get("method").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        None => return json!({"id": id, "error": {"code": -32602, "message": "missing method"}}),
    };
    let params = parsed.get("params").cloned().unwrap_or(json!({}));
    match call(bridge, &method, &params) {
        Ok(result) => json!({"id": id, "result": result}),
        Err(message) => json!({"id": id, "error": {"code": -32000, "message": message}}),
    }
}

fn call(bridge: &Bridge, method: &str, p: &Value) -> Result<Value, String> {
    match method {
        "node_info" => Ok(json!({
            "node_id": hex::encode(bridge.node.get_id().serialize()),
            "network": format!("{:?}", bridge.network),
            "key_derivation_style": "electrum",
        })),
        "new_channel" => {
            let channel_seed = hex32(p, "channel_seed")?;
            let (channel_id, slot) = bridge
                .node
                .new_channel_with_keys_id(channel_seed, &bridge.node)
                .map_err(status_msg)?;
            let secp = Secp256k1::new();
            let pubkeys = match slot {
                Some(ChannelSlot::Stub(stub)) => stub.keys.pubkeys(&secp),
                Some(ChannelSlot::Ready(chan)) => chan.keys.pubkeys(&secp),
                None => return Err("channel slot unavailable".into()),
            };
            Ok(json!({
                "channel_id": hex::encode(channel_id.as_slice()),
                "pubkeys": {
                    "funding_pubkey": hex::encode(pubkeys.funding_pubkey.serialize()),
                    "revocation_basepoint": hex::encode(pubkeys.revocation_basepoint.0.serialize()),
                    "payment_point": hex::encode(pubkeys.payment_point.serialize()),
                    "delayed_payment_basepoint": hex::encode(pubkeys.delayed_payment_basepoint.0.serialize()),
                    "htlc_basepoint": hex::encode(pubkeys.htlc_basepoint.0.serialize()),
                }
            }))
        }
        "setup_channel" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let cp = p.get("counterparty_points").ok_or("missing counterparty_points")?;
            let counterparty_points = ChannelPublicKeys {
                funding_pubkey: pubkey_field(cp, "funding_pubkey")?,
                revocation_basepoint: RevocationBasepoint(pubkey_field(cp, "revocation_basepoint")?),
                payment_point: pubkey_field(cp, "payment_point")?,
                delayed_payment_basepoint: DelayedPaymentBasepoint(pubkey_field(
                    cp,
                    "delayed_payment_basepoint",
                )?),
                htlc_basepoint: HtlcBasepoint(pubkey_field(cp, "htlc_basepoint")?),
            };
            let setup = ChannelSetup {
                is_outbound: p.get("is_outbound").and_then(Value::as_bool).unwrap_or(true),
                channel_value_sat: p
                    .get("channel_value_sat")
                    .and_then(Value::as_u64)
                    .unwrap_or(123456),
                push_value_msat: p.get("push_value_msat").and_then(Value::as_u64).unwrap_or(0),
                funding_outpoint: OutPoint {
                    txid: Txid::from_str(&str_field(p, "funding_txid")?)
                        .map_err(|e| format!("bad funding_txid: {e}"))?,
                    vout: p.get("funding_vout").and_then(Value::as_u64).unwrap_or(1) as u32,
                },
                holder_selected_contest_delay: p
                    .get("holder_selected_contest_delay")
                    .and_then(Value::as_u64)
                    .unwrap_or(10) as u16,
                holder_shutdown_script: None,
                counterparty_points,
                counterparty_selected_contest_delay: p
                    .get("counterparty_selected_contest_delay")
                    .and_then(Value::as_u64)
                    .unwrap_or(11) as u16,
                counterparty_shutdown_script: None,
                commitment_type: match p.get("commitment_type").and_then(Value::as_str) {
                    Some(s) => serde_json::from_value(Value::String(s.to_string()))
                        .map_err(|e| format!("bad commitment_type: {e}"))?,
                    None => CommitmentType::StaticRemoteKey,
                },
            };
            bridge
                .node
                .setup_channel(channel_id, None, setup, &DerivationPath::master())
                .map_err(status_msg)?;
            Ok(json!({"ok": true}))
        }
        "confirm_funding_lock" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let txid = Txid::from_str(&str_field(p, "funding_txid")?)
                .map_err(|e| format!("bad funding_txid: {e}"))?;
            let vout = p.get("funding_vout").and_then(Value::as_u64).unwrap_or(1) as u32;
            bridge
                .node
                .confirm_funding_lock(&channel_id, &OutPoint { txid, vout })
                .map_err(status_msg)?;
            Ok(json!({"ok": true}))
        }
        "get_per_commitment_point" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let ctn = p.get("ctn").and_then(Value::as_u64).ok_or("missing ctn")?;
            let slot = bridge.node.get_channel(&channel_id).map_err(status_msg)?;
            let guard = slot.lock().unwrap();
            let point = match &*guard {
                ChannelSlot::Stub(stub) => stub.get_per_commitment_point(ctn),
                ChannelSlot::Ready(chan) => chan.get_per_commitment_point(ctn),
            }
            .map_err(status_msg)?;
            Ok(json!({"point": hex::encode(point.serialize())}))
        }
        other => Err(format!("unknown method: {other}")),
    }
}

fn status_msg(e: Status) -> String {
    e.message().to_string()
}

fn str_field<'a>(p: &'a Value, name: &str) -> Result<&'a str, String> {
    p.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn hex32(p: &Value, name: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(str_field(p, name)?).map_err(|e| format!("bad hex in {name}: {e}"))?;
    bytes.try_into().map_err(|_| format!("{name} must be 32 bytes"))
}

fn pubkey_field(p: &Value, name: &str) -> Result<PublicKey, String> {
    PublicKey::from_str(str_field(p, name)?).map_err(|e| format!("bad pubkey in {name}: {e}"))
}
