//! Scenario driver for traced splice tests — the narrative spine.
//!
//! Wraps the existing test_utils fixtures: each scenario emits driver
//! events (steps, injections, expectations, invariants, declared state
//! machine), the harness-as-CLN-peer emits `cln` events, and the
//! instrumented signer emits `vls` events — all into one JSONL file when
//! `VLS_TRACE_DIR` is set. Without the env var nothing is written and
//! every call is a cheap no-op, so these tests double as normal
//! regression tests.
//!
//! The `state()`/`transition()` calls make the test an executable
//! specification: the visualizer's aggregate state-machine view is
//! generated from the trace, never hand-drawn.

use serde_json::{json, Value};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::trace::sink::CorrelationScope;
use crate::trace::{EventPayload, TraceEvent, TraceSink};

pub const CLN_TEST_PEER: &str = "test-peer";

enum SinkHolder {
    Active(std::sync::Arc<TraceSink>),
    Off,
}

static SCENARIO_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// A traced scenario. Cheap when tracing is off. Scenarios serialize
/// against each other (the sink is process-global).
pub struct ScenarioRunner {
    scenario_id: String,
    sink: SinkHolder,
    step_no: u32,
    _lock: MutexGuard<'static, ()>,
}

impl ScenarioRunner {
    /// Start a scenario; installs the global sink when `VLS_TRACE_DIR`
    /// is set (the only way tracing turns on).
    pub fn new(scenario_id: &str) -> Self {
        Self::with_declared_states(scenario_id, &[])
    }

    fn with_declared_states(scenario_id: &str, states: &[&str]) -> Self {
        let sink = match TraceSink::install(scenario_id) {
            Some(s) => {
                s.emit_local(TraceEvent::driver(EventPayload::ScenarioStart {
                    declared_states: states.iter().map(|s| s.to_string()).collect(),
                }));
                SinkHolder::Active(s)
            }
            None => SinkHolder::Off,
        };
        let lock =
            SCENARIO_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());
        Self { scenario_id: scenario_id.to_string(), sink, step_no: 0, _lock: lock }
    }

    /// Start a scenario declaring its state machine up front.
    pub fn with_states(scenario_id: &str, states: &[&str]) -> Self {
        Self::with_declared_states(scenario_id, states)
    }

    fn active(&self) -> Option<&std::sync::Arc<TraceSink>> {
        match &self.sink {
            SinkHolder::Active(s) => Some(s),
            SinkHolder::Off => None,
        }
    }

    fn emit_driver(&self, payload: EventPayload) {
        if let Some(s) = self.active() {
            s.emit_local(TraceEvent::driver(payload).scenario(&self.scenario_id));
        }
    }

    fn emit_cln(&self, payload: EventPayload) {
        if let Some(s) = self.active() {
            s.emit_local(TraceEvent::cln(payload).scenario(&self.scenario_id));
        }
    }

    /// Advance to a logical step; returns a RAII scope that tags every
    /// VLS/CLN event emitted on this thread with the step's correlation
    /// id (this is what ties the three lanes together).
    pub fn step(&mut self, name: &str) -> StepScope {
        self.step_no += 1;
        let correlation = format!("s{}-{}", self.step_no, name);
        self.emit_driver(EventPayload::Step { name: name.to_string() });
        let guard =
            if self.active().is_some() { Some(CorrelationScope::new(&correlation)) } else { None };
        StepScope { _guard: guard }
    }

    /// A driver action injection (reconnect, restart, RBF…).
    pub fn inject(&self, action: &str, detail: Option<Value>) {
        self.emit_driver(EventPayload::Inject { action: action.into(), detail });
    }

    /// Record an expectation and whether it held.
    pub fn expect(&self, what: &str, ok: bool) {
        self.emit_driver(EventPayload::Expect {
            expect: what.into(),
            outcome: if ok { "ok".into() } else { "fail".into() },
        });
    }

    /// An invariant assertion: narrated into the trace AND enforced —
    /// panics when `passed` is false (tests stay tests).
    pub fn invariant(&self, name: &str, passed: bool, detail: Option<Value>) {
        self.emit_driver(EventPayload::Invariant { name: name.into(), passed, detail });
        assert!(passed, "scenario invariant failed: {name}");
    }

    /// Declare a state-machine node with its invariant set.
    pub fn state(&self, name: &str, invariants: Value) {
        self.emit_driver(EventPayload::StateDeclared {
            state: name.into(),
            invariants: Some(invariants),
        });
    }

    /// Declare a state-machine edge.
    pub fn transition(&self, from: &str, to: &str, trigger: &str) {
        self.emit_driver(EventPayload::TransitionDeclared {
            from: from.into(),
            to: to.into(),
            trigger: trigger.into(),
        });
    }

    /// What CLN (as the test peer) just sent toward VLS.
    pub fn cln_sends(&self, message: &str, detail: Option<Value>) {
        self.emit_cln(EventPayload::ClnRequest {
            message: message.into(),
            detail,
            source: CLN_TEST_PEER.into(),
        });
    }

    /// What CLN (as the test peer) got back from VLS.
    pub fn cln_receives(&self, message: &str, detail: Option<Value>) {
        self.emit_cln(EventPayload::ClnResponse {
            message: message.into(),
            detail,
            source: CLN_TEST_PEER.into(),
        });
    }

    /// What CLN believes about the channel right now (peer-side view).
    pub fn cln_state(&self, current_funding: Option<&str>, detail: Value) {
        self.emit_cln(EventPayload::ClnState {
            current_funding: current_funding.map(|f| f.to_string()),
            detail: Some(detail),
            source: CLN_TEST_PEER.into(),
        });
    }

    /// A CLN-side happening (disconnect, retransmit, tx_abort…).
    pub fn cln_event(&self, what: &str, detail: Option<Value>) {
        self.emit_cln(EventPayload::ClnEvent {
            what: what.into(),
            detail,
            source: CLN_TEST_PEER.into(),
        });
    }

    /// End the scenario (emits `scenario_end`, uninstalls the sink,
    /// flushes the JSONL file).
    pub fn finish(&mut self, outcome: &str) {
        self.emit_driver(EventPayload::ScenarioEnd { outcome: outcome.into() });
        if matches!(self.sink, SinkHolder::Active(_)) {
            TraceSink::uninstall();
            self.sink = SinkHolder::Off;
        }
    }

    /// Where the JSONL artifact lands (for test assertions + printing).
    pub fn trace_path(&self) -> Option<std::path::PathBuf> {
        self.active().map(|s| s.path.clone())
    }
}

impl Drop for ScenarioRunner {
    fn drop(&mut self) {
        // A scenario that forgot finish() still must not leak the sink.
        if matches!(self.sink, SinkHolder::Active(_)) {
            self.emit_driver(EventPayload::ScenarioEnd { outcome: "dropped".into() });
            TraceSink::uninstall();
        }
    }
}

/// RAII correlation scope for a scenario step.
pub struct StepScope {
    pub(crate) _guard: Option<CorrelationScope>,
}

/// Helper: assert on a parsed JSONL trace with volatile fields stripped
/// (seq/timestamps/run_id) — the determinism rail for tracer tests.
pub fn canonical_events(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                for k in ["seq", "actor_seq", "ts_us", "mono_us", "run_id"] {
                    obj.remove(k);
                }
            }
            v
        })
        .collect()
}

/// Helper: read the JSONL file produced by a scenario.
pub fn read_trace(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Helper: json! shim for callers without serde_json imported.
pub fn j(v: Value) -> Value {
    v
}

/// Helper for building detail objects tersely.
#[macro_export]
macro_rules! trace_detail {
    ($($k:literal : $v:expr),* $(,)?) => {
        ::serde_json::json!({ $($k: $v),* })
    };
}

/// Assert helper used by tracer self-tests: every line parses, schema
/// field is present and correct.
pub fn assert_wellformed(lines: &[String]) {
    for (i, l) in lines.iter().enumerate() {
        let v: Value =
            serde_json::from_str(l).unwrap_or_else(|e| panic!("line {i} unparseable: {e}\n{l}"));
        assert_eq!(v["schema"], crate::trace::SCHEMA, "line {i} schema mismatch");
        assert!(v["seq"].is_u64(), "line {i} missing seq");
        assert!(v["actor"].is_string(), "line {i} missing actor");
        assert!(v["provenance"].is_string(), "line {i} missing provenance stamp");
    }
    // actor_seq strictly increasing per actor
    use std::collections::HashMap;
    let mut last: HashMap<String, u64> = HashMap::new();
    for l in lines {
        let v: Value = serde_json::from_str(l).unwrap();
        let actor = v["actor"].as_str().unwrap().to_string();
        let aseq = v["actor_seq"].as_u64().unwrap();
        let prev = last.insert(actor.clone(), aseq).unwrap_or(0);
        assert!(aseq > prev, "actor_seq not monotonic for {actor}");
    }
    let _ = json!({});
}
