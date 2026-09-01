//! Trace event envelope and typed payloads for `vls-trace/1`.
// Serialized-data schema: names are the API; schema docs in docs/splice-trace.md.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::artifact::TraceArtifact;
use super::snapshot::ChannelSnapshot;

/// The canonical schema tag. Bump on incompatible envelope changes.
pub const SCHEMA: &str = "vls-trace/1";

/// Who observed the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    /// The test/scenario driver — the narrative spine.
    Driver,
    /// CLN (or the test harness acting as CLN's protocol peer).
    Cln,
    /// The validating signer.
    Vls,
}

/// Outcome of an operation event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceResult {
    /// `accepted` | `rejected` | `error` | `ok` | `fail` | custom
    pub status: String,
    /// Status/error code when refused (e.g. `InvalidArgument`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TraceResult {
    /// A successful result.
    pub fn ok() -> Self {
        Self { status: "accepted".into(), code: None, message: None }
    }

    /// Build from any `Result<T, Status>` (value discarded).
    pub fn from_status_value<T>(r: &Result<T, crate::util::status::Status>) -> Self {
        match r {
            Ok(_) => Self::ok(),
            Err(e) => Self {
                status: "rejected".into(),
                code: Some(format!("{:?}", e.code())),
                message: Some(e.message().to_string()),
            },
        }
    }
}

/// Typed event payloads. Tagged with `"type"` in JSON; the enum is
/// open-world-friendly — the viewer treats unknown types as raw-field
/// events, and this crate's parser can be extended without a schema bump
/// for purely additive payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    // ---- driver (narrative spine) ----
    /// Scenario started; `declared_states` optionally names the state
    /// machine nodes the scenario claims to walk.
    ScenarioStart {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        declared_states: Vec<String>,
    },
    ScenarioEnd {
        /// e.g. `passed` | `failed`
        outcome: String,
    },
    /// A logical scenario step; sets the correlation context for
    /// subsequent VLS/CLN events until the next step.
    Step { name: String },
    /// A fault/action injection by the driver (reconnect, restart, RBF…).
    Inject {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
    /// An expectation checked by the driver.
    Expect { expect: String, outcome: String },
    /// An invariant assertion (also enforced in code, not just narrated).
    Invariant {
        name: String,
        passed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
    /// A declared state-machine node with its invariant set — the
    /// executable-specification view the visualizer aggregates.
    StateDeclared {
        state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        invariants: Option<Value>,
    },
    /// A declared state-machine edge.
    TransitionDeclared { from: String, to: String, trigger: String },

    // ---- cln (from test-peer model, proxy tap, or a future cln emitter) ----
    /// What CLN sent to VLS (hsmd request).
    ClnRequest {
        /// hsmd message name, e.g. `sign_splice_tx`, `setup_channel`
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
        /// `test-peer` (scenario harness acting as CLN), `proxy-tap`
        /// (live boundary), `cln` (future CLN-side emitter)
        source: String,
    },
    /// What CLN received from VLS (reply to a [`EventPayload::ClnRequest`]
    /// sharing the correlation id).
    ClnResponse {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
        source: String,
    },
    /// CLN-side channel/splice state observation (what CLN believed).
    ClnState {
        /// Funding outpoint CLN considers current, if known.
        #[serde(skip_serializing_if = "Option::is_none")]
        current_funding: Option<String>,
        /// Free-form observed fields (channel state, height, etc).
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
        source: String,
    },
    /// Other CLN-side happening (reconnect, retransmit, tx_abort…).
    ClnEvent {
        what: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
        source: String,
    },

    // ---- vls (signer choke points) ----
    /// Initial channel setup (first funding era).
    SetupChannel { outpoint: String, value_sat: u64, push_msat: u64, remote_funding_key: String },
    /// A splice swap: `from_outpoint`'s era becomes previous, a new
    /// current era begins. `prev_chain_depth` is 1 for a simple A→B
    /// splice and 2 during RBF supersession (A,B,C live).
    SpliceSetup {
        from_outpoint: String,
        to_outpoint: String,
        value_sat: u64,
        push_msat: u64,
        remote_funding_key: String,
        prev_chain_depth: u8,
    },
    /// The funding view a transaction resolved to (era matching by
    /// input outpoint). `matched: false` = fell back to current view
    /// (foreign/unknown input).
    FundingViewResolved {
        txid: String,
        resolved_outpoint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        era: Option<String>,
        matched: bool,
    },
    SignSpliceTx {
        txid: String,
        input_index: u32,
        input_outpoint: String,
        /// era the input outpoint resolved to
        #[serde(skip_serializing_if = "Option::is_none")]
        era: Option<String>,
        remote_funding_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_amount_sat: Option<u64>,
    },
    /// `validate_holder_commitment_tx` — the commitment_signed path.
    ValidateHolderCommitment {
        commitment_number: u64,
        feerate_per_kw: u32,
        funding_outpoint: String,
        /// era the commitment's funding input resolved to
        #[serde(skip_serializing_if = "Option::is_none")]
        era: Option<String>,
        /// value split lives in the before/after snapshots (the delta is
        /// the story); present only when cheaply available
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_holder_sat: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_counterparty_sat: Option<u64>,
        htlc_count: usize,
    },
    /// `sign_counterparty_commitment_tx` — the sign path.
    SignCounterpartyCommitment {
        commitment_number: u64,
        feerate_per_kw: u32,
        funding_outpoint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        era: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_holder_sat: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_counterparty_sat: Option<u64>,
        htlc_count: usize,
    },
    /// Funding lock (CLN `hsmd_lock_outpoint` after mutual
    /// `splice_locked`); retires the previous chain.
    FundingLocked {
        outpoint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        era: Option<String>,
        /// eras retired by this lock, in retirement order
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        retired: Vec<String>,
    },
    /// Chain-monitor / tracker watch changes.
    MonitorUpdate {
        what: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
    /// Signer state persisted (splice window, era chain, snapshot).
    Persisted {
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
    /// Signer restored from persistence (restart scenario leg).
    Restored {
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
}

/// The `vls-trace/1` envelope. `seq`, `actor_seq`, `ts_us`, `mono_us`
/// and `era` labels are assigned by the [`crate::sink::TraceSink`] at
/// emission time — emitters only fill semantic fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEvent {
    pub schema: String,
    pub run_id: String,
    pub scenario_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mono_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    pub event: EventPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<ChannelSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<ChannelSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<TraceArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TraceResult>,
}

impl TraceEvent {
    /// Start an event for the given actor.
    pub fn for_actor(actor: Actor, payload: EventPayload) -> Self {
        Self {
            schema: SCHEMA.into(),
            run_id: String::new(),
            scenario_id: String::new(),
            seq: None,
            actor,
            actor_seq: None,
            ts_us: None,
            mono_us: None,
            correlation_id: None,
            channel_id: None,
            event: payload,
            before: None,
            after: None,
            artifacts: vec![],
            result: None,
        }
    }

    pub fn vls(payload: EventPayload) -> Self {
        Self::for_actor(Actor::Vls, payload)
    }

    pub fn cln(payload: EventPayload) -> Self {
        Self::for_actor(Actor::Cln, payload)
    }

    pub fn driver(payload: EventPayload) -> Self {
        Self::for_actor(Actor::Driver, payload)
    }

    pub fn scenario(mut self, id: &str) -> Self {
        self.scenario_id = id.into();
        self
    }

    pub fn correlation(mut self, id: &str) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the channel id from raw `ChannelId` bytes (hex-encoded).
    pub fn channel_hex(mut self, bytes: &[u8]) -> Self {
        self.channel_id = Some(hex::encode(bytes));
        self
    }

    pub fn before(mut self, snap: Option<ChannelSnapshot>) -> Self {
        self.before = snap;
        self
    }

    pub fn after(mut self, snap: Option<ChannelSnapshot>) -> Self {
        self.after = snap;
        self
    }

    pub fn artifacts(mut self, arts: Vec<TraceArtifact>) -> Self {
        self.artifacts = arts;
        self
    }

    pub fn result(mut self, r: TraceResult) -> Self {
        self.result = Some(r);
        self
    }
}
