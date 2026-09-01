// Serialized-data schema: names are the API; schema docs in docs/splice-trace.md.
#![allow(missing_docs)]

//! Raw + decoded artifacts attached to trace events.
//!
//! Nothing here accepts secret key material — the types are deliberately
//! narrow (public tx/psbt/message data). Addresses and transactions are
//! recorded verbatim: on signet/regtest/testnet there is nothing to
//! protect (owner directive 2026-09-01) and the forensic value of the
//! full artifact is the point of the tracer.

use bitcoin::consensus::Encodable;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::prelude::String;

/// An artifact captured with an event: always the raw form, usually a
/// decoded/normalized companion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceArtifact {
    /// `tx` | `psbt` | `message` | `other`
    pub kind: String,
    /// Raw form: hex for tx, base64 for psbt, utf8 for message.
    pub raw: String,
    /// Decoded/normalized form (machine-readable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Value>,
}

fn encode_hex_tx(tx: &Transaction) -> String {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).expect("encode tx");
    hex::encode(buf)
}

fn script_addr(script: &bitcoin::ScriptBuf, network: Network) -> Value {
    // Best-effort address rendering; the script hex is always kept so
    // nothing is lost when no address form exists.
    match bitcoin::address::Address::from_script(script, network) {
        Ok(a) => json!(a.to_string()),
        Err(_) => Value::Null,
    }
}

/// Capture a bitcoin transaction: raw hex + normalized decode
/// (txid, inputs/outpoints, outputs/values/scripts/addresses, fee-relevant
/// size fields). The funding input identification happens downstream in
/// the viewer by matching outpoints against known eras.
pub fn artifact_tx(tx: &Transaction, network: Network) -> TraceArtifact {
    let decoded = json!({
        "txid": tx.compute_txid().to_string(),
        "version": tx.version.0,
        "lock_time": tx.lock_time.to_consensus_u32(),
        "size": tx.total_size(),
        "weight": tx.weight().to_wu(),
        "inputs": tx.input.iter().map(|i| json!({
            "outpoint": i.previous_output.to_string(),
            "sequence": i.sequence.0,
        })).collect::<Vec<_>>(),
        "outputs": tx.output.iter().map(|o| json!({
            "value_sat": o.value.to_sat(),
            "script_pubkey": hex::encode(o.script_pubkey.as_bytes()),
            "address": script_addr(&o.script_pubkey, network),
        })).collect::<Vec<_>>(),
    });
    TraceArtifact { kind: "tx".into(), raw: encode_hex_tx(tx), decoded: Some(decoded) }
}

/// Capture a PSBT: raw hex (consensus serialization) + normalized decode
/// of the funding-relevant fields.
pub fn artifact_psbt(psbt: &Psbt) -> TraceArtifact {
    let inputs = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, i)| {
            json!({
                "index": idx,
                "witness_utxo_value_sat": i.witness_utxo.as_ref().map(|o| o.value.to_sat()),
                "witness_utxo_script": i.witness_utxo.as_ref()
                    .map(|o| hex::encode(o.script_pubkey.as_bytes())),
            })
        })
        .collect::<Vec<_>>();
    let decoded = json!({
        "unsigned_txid": psbt.unsigned_tx.compute_txid().to_string(),
        "inputs": inputs,
        "outputs": psbt.unsigned_tx.output.iter().map(|o| json!({
            "value_sat": o.value.to_sat(),
            "script_pubkey": hex::encode(o.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>(),
    });
    TraceArtifact {
        kind: "psbt".into(),
        raw: hex::encode(psbt.serialize()),
        decoded: Some(decoded),
    }
}

/// Capture a protocol message: raw utf8 + optional decoded fields.
pub fn artifact_message(name: &str, raw: &str, decoded: Option<Value>) -> TraceArtifact {
    TraceArtifact { kind: "message".into(), raw: format!("{name}: {raw}"), decoded }
}

/// Capture an arbitrary opaque artifact.
pub fn artifact_other(kind: &str, raw: String, decoded: Option<Value>) -> TraceArtifact {
    TraceArtifact { kind: kind.into(), raw, decoded }
}
