//! JSON-lines RPC over a Unix socket exposing a vls-core Node configured with
//! Electrum key derivation. Fork-local M2 sidecar skeleton: the future
//! Electrum plugin taps channel state and speaks this protocol.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use lightning_signer::bitcoin::bip32::DerivationPath;
use lightning_signer::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning_signer::bitcoin::{Network, OutPoint, Transaction, Txid};
use lightning_signer::channel::{ChannelBase, ChannelId, ChannelSetup, ChannelSlot, CommitmentType};
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::channel_keys::{
    DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint,
};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::util::status::Status;
use lightning_signer::util::test_utils::make_permissive_services;
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
    let services = make_permissive_services(network);
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
            let mut parse_secret = |field: &str| -> Result<Option<SecretKey>, String> {
                match str_field(p, field) {
                    Ok(hexstr) => {
                        let bytes = hex::decode(hexstr)
                            .map_err(|e| format!("bad hex in {field}: {e}"))?;
                        let arr: [u8; 32] =
                            bytes.try_into().map_err(|_| format!("{field} must be 32 bytes"))?;
                        Ok(Some(
                            lightning_signer::bitcoin::secp256k1::SecretKey::from_slice(&arr)
                                .map_err(|e| format!("bad {field}: {e}"))?,
                        ))
                    }
                    Err(_) => Ok(None),
                }
            };
            let funding_override = parse_secret("funding_privkey")?;
            let payment_override = parse_secret("payment_privkey")?;
            let (channel_id, slot) = bridge
                .node
                .new_channel_with_keys_id(
                    channel_seed,
                    funding_override.as_ref(),
                    payment_override.as_ref(),
                    &bridge.node,
                )
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
        "sign_counterparty_commitment" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let funding_outpoint = OutPoint {
                txid: Txid::from_str(&str_field(p, "funding_txid")?)
                    .map_err(|e| format!("bad funding_txid: {e}"))?,
                vout: u64_field(p, "funding_vout", 0) as u32,
            };
            let per_commitment_point = pubkey_field(p, "per_commitment_point")?;
            let commitment_number = u64_field(p, "ctn", 0);
            let feerate_per_kw = u64_field(p, "feerate_per_kw", 0) as u32;
            let to_holder_value_sat = u64_field(p, "to_holder_sat", 0);
            let to_counterparty_value_sat = u64_field(p, "to_counterparty_sat", 0);
            let (signature, _htlc_sigs) = bridge
                .node
                .with_channel(&channel_id, |chan| {
                    chan.sign_counterparty_commitment_tx_phase2(
                        funding_outpoint,
                        &per_commitment_point,
                        commitment_number,
                        feerate_per_kw,
                        to_holder_value_sat,
                        to_counterparty_value_sat,
                        Vec::new(),
                        Vec::new(),
                    )
                })
                .map_err(status_msg)?;
            Ok(json!({"signature": hex::encode(signature.serialize_compact())}))
        }
        "sync_commitment_state" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let commit_num = u64_field(p, "commit_num", 0);
            let revoke_num = u64_field(p, "revoke_num", 0);
            let holder_num = u64_field(p, "holder_commit_num", commit_num);
            let current_point = pubkey_field(p, "per_commitment_point")?;
            bridge
                .node
                .with_channel(&channel_id, |chan| {
                    chan.enforcement_state
                        .set_next_counterparty_commit_num_for_testing(commit_num, current_point);
                    chan.enforcement_state
                        .set_next_counterparty_revoke_num_for_testing(revoke_num);
                    chan.enforcement_state
                        .set_next_holder_commit_num_for_testing(holder_num);
                    Ok(())
                })
                .map_err(status_msg)?;
            Ok(json!({"ok": true}))
        }
        "sign_counterparty_commitment_raw" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let tx_bytes = hex::decode(str_field(p, "tx")?).map_err(|e| format!("bad tx hex: {e}"))?;
            let tx: Transaction = lightning_signer::bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|e| format!("tx deserialization: {e}"))?;
            let mut witscripts = Vec::new();
            for item in p
                .get("witscripts")
                .and_then(Value::as_array)
                .ok_or("missing witscripts")?
            {
                let hexstr = item.as_str().ok_or("witscripts must be hex strings")?;
                witscripts
                    .push(hex::decode(hexstr).map_err(|e| format!("bad witscript hex: {e}"))?);
            }
            let per_commitment_point = pubkey_field(p, "per_commitment_point")?;
            let commitment_number = u64_field(p, "ctn", 0);
            let feerate_per_kw = u64_field(p, "feerate_per_kw", 0) as u32;
            let signature = bridge
                .node
                .with_channel(&channel_id, |chan| {
                    chan.sign_counterparty_commitment_tx(
                        &tx,
                        &witscripts,
                        &per_commitment_point,
                        commitment_number,
                        feerate_per_kw,
                        Vec::new(),
                        Vec::new(),
                    )
                })
                .map_err(status_msg)?;
            Ok(json!({"signature": hex::encode(signature.serialize_compact())}))
        }
        "validate_counterparty_revocation" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let revoke_num = u64_field(p, "revoke_num", 0);
            let secret_bytes = hex32(p, "secret")?;
            let old_secret = lightning_signer::bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes)
                .map_err(|e| format!("bad secret: {e}"))?;
            bridge
                .node
                .with_channel(&channel_id, |chan| {
                    chan.validate_counterparty_revocation(revoke_num, &old_secret)
                })
                .map_err(status_msg)?;
            Ok(json!({"ok": true}))
        }
        "sign_justice_sweep" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let tx_bytes = hex::decode(str_field(p, "tx")?).map_err(|e| format!("bad tx hex: {e}"))?;
            let tx: Transaction = lightning_signer::bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|e| format!("tx deserialization: {e}"))?;
            let input = u64_field(p, "input", 0) as usize;
            let revocation_secret_bytes = hex32(p, "revocation_secret")?;
            let revocation_secret =
                lightning_signer::bitcoin::secp256k1::SecretKey::from_slice(&revocation_secret_bytes)
                    .map_err(|e| format!("bad revocation_secret: {e}"))?;
            let redeemscript_bytes =
                hex::decode(str_field(p, "redeemscript")?).map_err(|e| format!("bad redeemscript hex: {e}"))?;
            let redeemscript = lightning_signer::bitcoin::Script::from_bytes(&redeemscript_bytes);
            let amount_sat = u64_field(p, "amount_sat", 0);
            let signature = bridge
                .node
                .with_channel(&channel_id, |chan| {
                    chan.sign_justice_sweep(
                        &tx,
                        input,
                        &revocation_secret,
                        redeemscript,
                        amount_sat,
                        &DerivationPath::master(),
                    )
                })
                .map_err(status_msg)?;
            Ok(json!({"signature": hex::encode(signature.serialize_compact())}))
        }
        "derive_and_report" => {
            let channel_id = ChannelId::new(&hex32(p, "channel_id")?);
            let revocation_secret_hex = p
                .get("revocation_secret")
                .and_then(Value::as_str)
                .map(str::to_string);
            let report = bridge
                .node
                .with_channel(&channel_id, |chan| {
                    let secp_ctx = Secp256k1::new();
                    let holder_keys = chan.keys.pubkeys(&secp_ctx);
                    let setup = &chan.setup;
                    let cp_points = &setup.counterparty_points;
                    let mut report = json!({
                        "funding_pubkey": hex::encode(holder_keys.funding_pubkey.serialize()),
                        "revocation_basepoint": hex::encode(holder_keys.revocation_basepoint.0.serialize()),
                        "htlc_basepoint": hex::encode(holder_keys.htlc_basepoint.0.serialize()),
                        "delayed_basepoint": hex::encode(holder_keys.delayed_payment_basepoint.0.serialize()),
                        "payment_basepoint": hex::encode(holder_keys.payment_point.serialize()),
                        "cp_funding_pubkey": hex::encode(cp_points.funding_pubkey.serialize()),
                        "cp_revocation_basepoint": hex::encode(cp_points.revocation_basepoint.0.serialize()),
                        "cp_delayed_basepoint": hex::encode(cp_points.delayed_payment_basepoint.0.serialize()),
                        "holder_selected_contest_delay": setup.holder_selected_contest_delay,
                        "counterparty_selected_contest_delay": setup.counterparty_selected_contest_delay,
                        "channel_value_sat": setup.channel_value_sat,
                    });
                    if let Some(secret_hex) = revocation_secret_hex {
                        let secret_arr: [u8; 32] = hex::decode(&secret_hex)
                            .map_err(|e| Status::invalid_argument(format!("revocation_secret hex: {e}")))?
                            .try_into()
                            .map_err(|_| Status::invalid_argument("revocation_secret must be 32 bytes"))?;
                        let pcp_secret = SecretKey::from_slice(&secret_arr)
                            .map_err(|e| Status::invalid_argument(format!("revocation_secret: {e}")))?;
                        let pcp = PublicKey::from_secret_key(&secp_ctx, &pcp_secret);
                        report["per_commitment_point"] = json!(hex::encode(pcp.serialize()));
                    }
                    Ok(report)
                })
                .map_err(status_msg)?;
            Ok(report)
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

fn u64_field(p: &Value, name: &str, default: u64) -> u64 {
    p.get(name).and_then(Value::as_u64).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_override_round_trips_through_new_channel_report() {
        let bridge = make_bridge([1u8; 32], Network::Regtest);
        let payment_priv = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let expected_pub = PublicKey::from_secret_key(&Secp256k1::new(), &payment_priv);
        let res = call(
            &bridge,
            "new_channel",
            &json!({
                "channel_seed": hex::encode([2u8; 32]),
                "payment_privkey": hex::encode(payment_priv.secret_bytes()),
            }),
        )
        .unwrap();
        assert_eq!(
            res["pubkeys"]["payment_point"].as_str().unwrap(),
            hex::encode(expected_pub.serialize())
        );
    }
}
