//! Canonical splice/state-machine trace model (`vls-trace/1`).
//!
//! One JSONL envelope per event, emitted by three actors
//! ([`Actor::Driver`], [`Actor::Cln`], [`Actor::Vls`]) into a single
//! [`TraceSink`]. See `docs/splice-trace.md` for the architecture and
//! the schema rationale.
//!
//! Everything here is public-key/outpoint/amount data only — there is no
//! API surface through which secret key material can enter a trace, so
//! traces are publish-safe by construction. Addresses, transactions and
//! PSBTs are recorded verbatim on purpose: on signet/regtest/testnet the
//! forensic value outweighs the (worthless) coins' privacy.
//!
//! The data model requires the `splice_trace` feature (implies `std`);
//! without it the module reduces to the two no-op macros — production
//! builds carry zero cost.

#[cfg(feature = "splice_trace")]
pub mod artifact;
#[cfg(feature = "splice_trace")]
pub mod event;
#[cfg(feature = "splice_trace")]
pub mod sink;
#[cfg(feature = "splice_trace")]
pub mod snapshot;
#[cfg(all(test, feature = "splice_trace"))]
mod tests;

#[cfg(feature = "splice_trace")]
pub use artifact::{artifact_tx, TraceArtifact};
#[cfg(feature = "splice_trace")]
pub use event::{Actor, EventPayload, TraceEvent, TraceResult, SCHEMA};
#[cfg(feature = "splice_trace")]
pub use sink::{
    correlation, correlation_scope, emit, enabled, era_label, init_from_env, snap_opt, TraceSink,
};
#[cfg(feature = "splice_trace")]
pub use snapshot::{snapshot_channel, ChannelSnapshot, CommitmentSummary, FundingEraView};

/// Emit a VLS-actor operation event around a body: `before` snapshot now,
/// run the body, `after` snapshot + event + result. Compiled out entirely
/// when the `splice_trace` feature is off.
///
/// Usage inside an instrumented method (channel/node):
///
/// ```ignore
/// trace_op!(self, EventPayload::SignSpliceTx { .. }, tx_artifact(&tx), result_expr)
/// ```
///
/// The macro is deliberately dumb: capture-before / emit-after is spelled
/// inline at the call sites (see `channel.rs`) so the diff stays reviewable
/// and the body is untouched.
/// Emit a VLS-actor op event — no-op without the `splice_trace` feature.
#[cfg(not(feature = "splice_trace"))]
#[macro_export]
macro_rules! trace_op {
    ($($tt:tt)*) => {};
}

/// Emit a VLS-actor op event (`after` snapshot + artifacts + result).
#[cfg(feature = "splice_trace")]
#[macro_export]
macro_rules! trace_op {
    ($chan:expr, $payload:expr, $arts:expr, $result:expr) => {{
        if $crate::trace::enabled() {
            let __evt = $crate::trace::TraceEvent::vls($payload)
                .channel_hex(&$chan.id0.as_slice())
                .after(Some($crate::trace::snapshot_channel($chan)))
                .artifacts($arts)
                .result($crate::trace::TraceResult::from_status_value(&$result));
            $crate::trace::emit(__evt);
        }
    }};
}

/// Capture the `before` snapshot for [`trace_op!`] (None when tracing is
/// disabled). Compiles to nothing without the feature.
/// Capture the before-snapshot (unit when tracing is off).
#[cfg(not(feature = "splice_trace"))]
#[macro_export]
macro_rules! trace_before {
    ($($tt:tt)*) => {
        ()
    };
}

/// Capture the before-snapshot iff tracing is enabled.
#[cfg(feature = "splice_trace")]
#[macro_export]
macro_rules! trace_before {
    ($chan:expr) => {
        $crate::trace::snap_opt($chan)
    };
}
