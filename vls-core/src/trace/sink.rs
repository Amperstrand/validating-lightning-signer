#![allow(missing_docs)]
//! The trace sink: assigns sequences/timestamps, owns era labels, writes
//! JSONL. One active sink per scenario (`ScenarioRunner` installs it);
//! instrumented code emits through the global current sink.

use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::event::TraceEvent;
use crate::prelude::{String, Vec};

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
static INSTANCE: OnceLock<Option<String>> = OnceLock::new();
static CURRENT: OnceLock<Mutex<Option<Arc<TraceSink>>>> = OnceLock::new();

fn current_slot() -> &'static Mutex<Option<Arc<TraceSink>>> {
    CURRENT.get_or_init(|| Mutex::new(None))
}

fn level_from_env() -> u8 {
    match std::env::var("VLS_TRACE_LEVEL").unwrap_or_default().to_lowercase().as_str() {
        "off" => u8::MAX,
        "core" => 0,
        "base" => 1,
        _ => 1, // extra and anything unrecognized: base
    }
}

fn configured_level() -> u8 {
    TRACE_LEVEL.load(Ordering::Relaxed)
}

/// The actor instance label (from `VLS_TRACE_INSTANCE`, e.g. `l1`) —
/// stamped on every event so multi-node farms merge into per-node lanes.
pub fn instance() -> Option<String> {
    INSTANCE.get_or_init(|| std::env::var("VLS_TRACE_INSTANCE").ok().filter(|s| !s.is_empty())).clone()
}

thread_local! {
    static CORRELATION: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Is tracing enabled for this process? (relaxed load after a one-time
/// env probe — the first call may come from an instrumentation site
/// that never reaches `emit()`, so the probe lives here, not in emit)
pub fn enabled() -> bool {
    #[cfg(feature = "splice_trace")]
    {
        static PROBE: OnceLock<()> = OnceLock::new();
        if PROBE.get().is_none() {
            let _ = PROBE.set(());
            init_from_env();
        }
        ENABLED.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "splice_trace"))]
    {
        false
    }
}

/// Decide from the environment whether this process traces at all,
/// and at which level. Called once by the first `TraceSink::install`
/// (or explicitly). `VLS_TRACE_LEVEL=off` disables tracing outright.
pub fn init_from_env() -> bool {
    let level = level_from_env();
    TRACE_LEVEL.store(if level == u8::MAX { 1 } else { level }, Ordering::Relaxed);
    let on = std::env::var("VLS_TRACE_DIR").map(|d| !d.is_empty()).unwrap_or(false)
        && level != u8::MAX;
    ENABLED.store(on, Ordering::Relaxed);
    on
}

/// The current thread's correlation id (set by the scenario runner's
/// step scope, or manually).
pub fn correlation() -> Option<String> {
    CORRELATION.with(|c| c.borrow().clone())
}

/// RAII guard setting the thread correlation context.
pub struct CorrelationScope {
    prev: Option<String>,
}

impl CorrelationScope {
    pub fn new(id: &str) -> Self {
        let prev = CORRELATION.with(|c| c.borrow().clone());
        CORRELATION.with(|c| *c.borrow_mut() = Some(id.to_string()));
        Self { prev }
    }
}

impl Drop for CorrelationScope {
    fn drop(&mut self) {
        CORRELATION.with(|c| *c.borrow_mut() = self.prev.take());
    }
}

/// Set the correlation context for the remainder of... nothing — prefer
/// [`CorrelationScope`]. This bare setter exists for driver code that
/// cannot hold a guard (rare).
pub fn correlation_scope(id: &str) -> CorrelationScope {
    CorrelationScope::new(id)
}

// ---------------------------------------------------------------------------
// Era labels — outpoint → stable per-channel letter, assigned on first
// sighting, in arrival order. Independent of the file sink so labels
// stay usable in any emission path.
// ---------------------------------------------------------------------------

static ERA_LABELS: OnceLock<Mutex<EraRegistry>> = OnceLock::new();

struct EraRegistry {
    map: HashMap<(String, String), String>,
    next_per_channel: HashMap<String, usize>,
}

fn era_registry() -> &'static Mutex<EraRegistry> {
    ERA_LABELS.get_or_init(|| {
        Mutex::new(EraRegistry { map: HashMap::new(), next_per_channel: HashMap::new() })
    })
}

fn era_letter(i: usize) -> String {
    if i < 26 {
        ((b'A' + i as u8) as char).to_string()
    } else {
        format!("E{i}")
    }
}

/// Resolve (or assign) the era label for an outpoint within a channel.
pub fn label_for(channel_hex: &str, outpoint: &bitcoin::OutPoint) -> String {
    let mut reg = era_registry().lock().unwrap();
    let key = (channel_hex.to_string(), outpoint.to_string());
    if let Some(l) = reg.map.get(&key) {
        return l.clone();
    }
    let next = reg.next_per_channel.entry(channel_hex.to_string()).or_insert(0);
    let label = era_letter(*next);
    *next += 1;
    reg.map.insert(key, label.clone());
    label
}

/// Channel-context-free lookup: returns the label only if already
/// assigned (never assigns).
pub fn label_for_outpoint(outpoint: &bitcoin::OutPoint) -> Option<String> {
    let reg = era_registry().lock().unwrap();
    let needle = outpoint.to_string();
    reg.map.iter().find(|((_, o), _)| *o == needle).map(|(_, l)| l.clone())
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

struct SinkInner {
    writer: BufWriter<File>,
    seq: u64,
    actor_seq: HashMap<String, u64>,
    start_instant: Instant,
    start_system: SystemTime,
    dropped_lines: u64,
}

/// A per-scenario JSONL trace sink.
pub struct TraceSink {
    /// Stable run id (default: time+pid; override via `VLS_TRACE_RUN_ID`)
    pub run_id: String,
    pub scenario_id: String,
    pub path: PathBuf,
    inner: Mutex<SinkInner>,
    pub local: bool,
}

fn unix_us(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

impl TraceSink {
    /// Create + install as the process's current sink. Only actually
    /// writes when the environment opted in (`VLS_TRACE_DIR`).
    pub fn install(scenario_id: &str) -> Option<Arc<TraceSink>> {
        if !enabled() && !init_from_env() {
            return None;
        }
        let dir = std::env::var("VLS_TRACE_DIR").unwrap_or_default();
        let run_id = std::env::var("VLS_TRACE_RUN_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{}-{}", unix_us(SystemTime::now()), std::process::id()));
        {
            let mut reg = era_registry().lock().unwrap();
            reg.map.clear();
            reg.next_per_channel.clear();
        }
        let mut path = PathBuf::from(&dir);
        if create_dir_all(&path).is_err() {
            return None;
        }
        path.push(format!("{scenario_id}.jsonl"));
        let file = File::create(&path).ok()?;
        let sink = Arc::new(TraceSink {
            run_id,
            scenario_id: scenario_id.to_string(),
            path,
            local: false,
            inner: Mutex::new(SinkInner {
                writer: BufWriter::new(file),
                seq: 0,
                actor_seq: HashMap::new(),
                start_instant: Instant::now(),
                start_system: SystemTime::now(),
                dropped_lines: 0,
            }),
        });
        let mut cur = current_slot().lock().unwrap();
        *cur = Some(sink.clone());
        Some(sink)
    }

    /// Create an in-memory sink for tests of the tracer itself.
    #[cfg(test)]
    pub fn in_memory(scenario_id: &str) -> Arc<TraceSink> {
        let file = tempfile::tempfile().expect("temp trace file");
        Arc::new(TraceSink {
            run_id: "test-run".into(),
            scenario_id: scenario_id.to_string(),
            path: PathBuf::from("<in-memory>"),
            local: true,
            inner: Mutex::new(SinkInner {
                writer: BufWriter::new(file),
                seq: 0,
                actor_seq: HashMap::new(),
                start_instant: Instant::now(),
                start_system: SystemTime::now(),
                dropped_lines: 0,
            }),
        })
    }

    /// Install this specific sink as current (used by tests).
    pub fn set_current(sink: Option<Arc<TraceSink>>) {
        let mut cur = current_slot().lock().unwrap();
        *cur = sink;
    }

    /// Uninstall (called by ScenarioRunner::finish).
    pub fn uninstall() {
        let mut cur = current_slot().lock().unwrap();
        if let Some(s) = cur.take() {
            s.flush();
        }
    }

    fn flush(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.writer.flush();
        }
    }

    /// Render the event to a JSONL line (assigning seq/actor_seq/ts +
    /// the provenance/level/instance stamps). Does NOT level-filter —
    /// see [`TraceSink::emit_local`].
    pub fn render_line(&self, mut ev: TraceEvent) -> String {
        let correlation = ev.correlation_id.clone().or_else(correlation);
        let mut inner = self.inner.lock().unwrap();
        inner.seq += 1;
        let seq = inner.seq;
        let actor_key = format!("{:?}", ev.actor);
        let actor_seq = inner.actor_seq.entry(actor_key).or_insert(0);
        *actor_seq += 1;
        ev.run_id = self.run_id.clone();
        ev.scenario_id = self.scenario_id.clone();
        ev.seq = Some(seq);
        ev.actor_seq = Some(*actor_seq);
        ev.ts_us =
            Some(unix_us(inner.start_system) + inner.start_instant.elapsed().as_micros() as u64);
        ev.mono_us = Some(inner.start_instant.elapsed().as_micros() as u64);
        ev.correlation_id = correlation;
        ev.provenance = Some(ev.event.provenance().to_string());
        ev.level = Some(ev.event.level_name().to_string());
        ev.actor_instance = instance();
        serde_json::to_string(&ev).unwrap_or_else(|_| {
            inner.dropped_lines += 1;
            format!("{{\"schema\":\"{}\",\"unserializable_event\":true}}", super::event::SCHEMA)
        })
    }

    /// Emit one event into this sink, honoring the configured trace
    /// level: payloads above the level are dropped; at core the
    /// before/after snapshots and artifacts are stripped; at base
    /// artifact raw bytes are stripped (decoded forms stay). Flushes
    /// per line: teardown paths (harness pkills, crashes) must not
    /// lose already-emitted events.
    pub fn emit_local(&self, ev: TraceEvent) {
        let ev = filter_to_level(ev, configured_level());
        let ev = match ev {
            Some(ev) => ev,
            None => return,
        };
        let line = self.render_line(ev);
        if let Ok(mut inner) = self.inner.lock() {
            let _ = writeln!(inner.writer, "{line}");
            let _ = inner.writer.flush();
        }
    }
}

/// Apply the level policy to an event: `None` = drop the event.
pub(crate) fn filter_to_level(mut ev: TraceEvent, level: u8) -> Option<TraceEvent> {
    use super::event::{LEVEL_BASE, LEVEL_EXTRA};
    if ev.event.trace_level() > level {
        return None;
    }
    if level < LEVEL_BASE {
        ev.before = None;
        ev.after = None;
        ev.artifacts = Vec::new();
    } else if level < LEVEL_EXTRA {
        ev.artifacts = ev
            .artifacts
            .into_iter()
            .map(|mut a| {
                a.raw = String::new();
                a
            })
            .collect();
    }
    Some(ev)
}

impl Drop for TraceSink {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Emit an event into the process's current sink. When the environment
/// opted in but no sink was installed yet (a long-running binary like
/// vlsd), installs a per-process default first — filenames carry the
/// pid so one trace dir can hold several concurrent processes (the
/// per-node vlsd farm shape); `VLS_TRACE_SCENARIO` overrides the name.
pub fn emit(ev: TraceEvent) {
    if current_slot().lock().unwrap().is_none() {
        // install WITHOUT holding the slot mutex — install() locks it
        // too, and std Mutex is not reentrant (the first live gate
        // wedged vlsd's handler thread exactly here)
        if !enabled() {
            return;
        }
        let name = std::env::var("VLS_TRACE_SCENARIO")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("vls-{}", std::process::id()));
        if TraceSink::install(&name).is_none() {
            return;
        }
    }
    let sink = current_slot().lock().unwrap().clone();
    if let Some(sink) = sink {
        sink.emit_local(ev);
    }
}

/// Convenience for instrumented code: capture the before-snapshot iff
/// tracing is enabled (None otherwise — zero cost when disabled).
pub fn snap_opt(chan: &crate::channel::Channel) -> Option<super::snapshot::ChannelSnapshot> {
    if enabled() {
        Some(super::snapshot::snapshot_channel(chan))
    } else {
        None
    }
}

/// Which funding era (outpoint, label) a transaction's funding input
/// belongs to — event-payload helper, no emission, no assignment order
/// guarantees beyond first-sight labeling.
pub fn era_of_tx(
    chan: &crate::channel::Channel,
    tx: &bitcoin::Transaction,
) -> Option<(String, String)> {
    let chan_hex = hex::encode(chan.id0.as_slice());
    for input in &tx.input {
        let o = input.previous_output;
        if o == chan.setup.funding_outpoint
            || chan.prev_setup.as_ref().map(|p| p.funding_outpoint == o).unwrap_or(false)
            || chan.prev_prev_setup.as_ref().map(|p| p.funding_outpoint == o).unwrap_or(false)
        {
            return Some((o.to_string(), label_for(&chan_hex, &o)));
        }
    }
    None
}

/// Convenience: build the era label for a channel+outpoint iff enabled.
pub fn era_label(chan: &crate::channel::Channel, outpoint: &bitcoin::OutPoint) -> Option<String> {
    if enabled() {
        Some(label_for(&hex::encode(chan.id0.as_slice()), outpoint))
    } else {
        None
    }
}

/// Test/inspection helper: last-moment parsed view of what the sink wrote.
pub fn drain_memory(_sink: &TraceSink) -> Vec<Value> {
    Vec::new() // file-backed sinks are read from disk; see trace tests
}
