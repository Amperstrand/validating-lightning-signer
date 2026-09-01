//! Live CLN↔VLS boundary tap for splice tracing.
//!
//! The remote_hsmd proxy sees every hsmd message CLN sends and every
//! reply VLS returns — the least invasive place to capture the CLN
//! perspective without patching CLN itself. Events use the canonical
//! `vls-trace/1` schema (actor `cln`, source `proxy-tap`) so they merge
//! with VLS/driver traces in the visualizer.
//!
//! Enable at runtime with `VLS_TRACE_DIR` (the sink is installed lazily
//! on the first splice-relevant message; the process env is the only
//! configuration surface, so unpatched deployments behave identically).

use lightning_signer::trace::sink::init_from_env;
use lightning_signer::trace::{EventPayload, TraceEvent, TraceResult};

const SPLICE_RELEVANT: &[&str] = &[
    "SetupChannel",
    "SignSpliceTx",
    "LockOutpoint",
    "SignCommitmentTx",
    "SignRemoteCommitmentTx",
    "SignMutualCloseTx",
    "CheckOutpoint",
];

fn tap_enabled() -> bool {
    if !init_from_env() {
        return false;
    }
    // First use installs the process sink (one file per proxy process;
    // the viewer merges it with the vlsd-side and driver-side traces).
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        // per-process name: the farm runs one proxy per lightningd node
        // in a shared VLS_TRACE_DIR — fixed names would clobber
        let name = std::env::var("VLS_TRACE_SCENARIO")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("cln-tap-{}", std::process::id()));
        lightning_signer::trace::TraceSink::install(&name);
    });
    true
}

/// Emit a `cln_request` event for a splice-relevant inbound message.
/// Returns the message name when a tap event was emitted (for response
/// correlation), None otherwise.
pub fn tap_request(message: &[u8], client_id: &str) -> Option<String> {
    if !tap_enabled() {
        return None;
    }
    let name = vls_protocol::msgs::message_name_from_vec(message);
    if !SPLICE_RELEVANT.contains(&name.as_str()) {
        return None;
    }
    lightning_signer::trace::emit(
        TraceEvent::cln(EventPayload::ClnRequest {
            message: name.clone(),
            detail: None,
            source: "proxy-tap".into(),
        })
        .correlation(client_id),
    );
    Some(name)
}

/// Emit the `cln_response` for a tapped request. Called only on the
/// success path (transport errors propagate past the tap — the viewer
/// tolerates a lone request event).
pub fn tap_response(tapped: Option<String>, client_id: &str, reply: &[u8]) {
    let name = match tapped {
        Some(n) if tap_enabled() => n,
        _ => return,
    };
    lightning_signer::trace::emit(
        TraceEvent::cln(EventPayload::ClnResponse {
            message: vls_protocol::msgs::message_name_from_vec(reply),
            detail: None,
            source: "proxy-tap".into(),
        })
        .correlation(client_id)
        .result(TraceResult { status: "ok".into(), code: None, message: Some(name) }),
    );
}
