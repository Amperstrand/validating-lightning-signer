# Splice state-machine tracing and visualization

**Status**: architecture as implemented (2026-09-01, branch `inr2-splice-dev`)
**Purpose**: a microscope for the CLN ↔ VLS splice state machine — one canonical
trace format, three synchronized perspectives (VLS / CLN / test-driver), a
browser visualizer that steps through a run like a debugger.

## Why

Splice windows are the hardest state in the signer: during RBF supersession
three funding generations coexist (`setup` / `prev_setup` / `prev_prev_setup`),
commitment infos belong to *different eras* than the channel-scoped fields
suggest, and the interesting bugs (era-mixing underflows, straggler
re-validation, same-number re-signs) are only visible when you can ask
*"what did each participant believe at this exact point?"*. Human log lines
cannot answer that; a correlated, stateful trace can.

## The one canonical trace

`schema: vls-trace/1` — newline-delimited JSON, one envelope per line:

```json
{
  "schema": "vls-trace/1",
  "run_id": "…",           // stable per sink (process+scenario)
  "scenario_id": "rbf_a_b_c",
  "seq": 42,               // global monotonic (assigned by the sink)
  "actor": "vls",          // driver | cln | vls
  "actor_seq": 18,         // per-actor monotonic
  "ts_us": 1735689600123,  // wall clock, unix microseconds
  "mono_us": 123456,       // monotonic offset from sink start
  "correlation_id": "step-7",  // ties driver step ↔ cln msg ↔ vls op
  "channel_id": "…hex…",
  "event": { "type": "sign_splice_tx", … typed fields … },
  "before": { …ChannelSnapshot… },
  "after": { …ChannelSnapshot… },
  "artifacts": [ { "kind": "tx", "raw": "<hex>", "decoded": { "txid": … } } ],
  "result": { "status": "rejected", "code": "InvalidArgument", "message": "…" }
}
```

Improvements over the sketch (motivated by the code):

* `event` is a **tagged enum** (`#[serde(tag = "type", rename_all = "snake_case")]`)
  — unknown future types still parse (open-world; the viewer degrades
  gracefully and shows raw fields).
* `seq`/`actor_seq`/`mono_us` are **assigned by the sink**, not the emitter —
  callers cannot get them wrong.
* era identity is **first-class**: every snapshot carries `eras: []` with
  stable labels (`A`, `B`, `C`…) assigned on first outpoint sighting, each with
  `lifecycle` (`current|previous|prev_prev|locked|retired`), value, remote
  funding key, per-era holder/counterparty commitment summaries and watch
  state. The logical model (N generations) is representable even where the
  implementation only keeps `current + prev + prev_prev` — the tracer shows
  what exists, and *shows the absence* (e.g. after `funding_locked` retires
  the chain, `retired_eras` records what was dropped).
* snapshots are built through the **same era-aware resolvers the signer uses**
  (`EnforcementState::holder_commit_info_for` etc.) — the visualization can
  never disagree with what VLS would actually resolve for a view.

### Secrets

Private key material never enters the trace **structurally**: the snapshot and
artifact builders are typed over public data only (`PublicKey`, outpoints,
txids, amounts, `CommitmentInfo2`). There is no `SecretKey`/seed parameter
anywhere in the trace API, so traces are publish-safe by construction.
Addresses, transactions and PSBTs are **never redacted** on test networks —
full forensic value is the point (owner directive 2026-09-01: signet/regtest/
testnet money is throwaway; only key material must stay out).

## Actors

| actor | emits | where |
|---|---|---|
| `driver` | scenario_start/end, step, inject, expect, invariant, state_declared, transition_declared | `ScenarioRunner` (test_utils, test-gated) |
| `vls` | setup_channel, splice_setup, funding_view_resolved, sign_splice_tx, validate_holder_commitment, sign_counterparty_commitment, funding_locked, monitor_update, restored | choke points in `channel.rs` / `node.rs` |
| `cln` | cln_request, cln_response, cln_state | (a) scenario runner acting as CLN's protocol peer (`source: "test-peer"` — genuine protocol-role data in unit tests), (b) live boundary tap in `vls-proxy` (`source: "proxy-tap"`), (c) future CLN-side emitters (`source: "cln"` — schema-ready, no CLN patch exists yet) |

The CLN *brain* (internal channeld beliefs) is **inferred from what CLN sends**
until a CLN-side emitter exists; the schema and viewer treat CLN events as
optional — a trace with no CLN lane still renders, with an explicit
"no CLN observations" state.

## Cost model

* Feature `splice_trace` is **off by default** → instrumentation compiles to
  nothing in production builds.
* With the feature on, emission is gated by a single relaxed atomic load
  (`trace::enabled()`); sink not initialized → zero work beyond the check.
* Tests enable it with `VLS_TRACE_DIR=<dir>` (opt-in per run; normal
  `cargo test` writes nothing).

## Layout

```
vls-core/src/trace/            canonical model (feature `splice_trace`)
  mod.rs                       module root, re-exports, emit helpers
  event.rs                     envelope + EventPayload (tagged enum)
  snapshot.rs                  ChannelSnapshot/FundingEraView + builder
  artifact.rs                  TraceArtifact (raw + decoded) + tx/psbt decode
  sink.rs                      JSONL sink, seq/labels, thread-local correlation
vls-core/src/util/test_utils/scenario.rs   ScenarioRunner (driver actor)
vls-core/src/splice_scenario_tests.rs      traced scenario suite
vls-proxy/src/grpc/signer_loop.rs          live cln↔vls boundary tap (same schema)
contrib/trace-viewer/          static browser visualizer + tiny server
docs/splice-trace.md           this file
```

## Workflow

From the repo root (use an absolute `VLS_TRACE_DIR` — the test binary's
CWD is the package dir, so a relative path lands in `vls-core/target/`):

```
# 1. run traced scenarios (writes <dir>/<scenario>.jsonl)
VLS_TRACE_DIR=$(pwd)/target/splice-traces \
  cargo test -p vls-core --features test_utils splice_scenario -- --test-threads=1

# 2. serve the viewer + traces
python3 contrib/trace-viewer/serve.py target/splice-traces 8799

# 3. open (note: index.html — "/" is the trace listing page)
http://localhost:8799/index.html?trace=rbf_a_b_c.jsonl
```

The viewer also works fully offline: open `contrib/trace-viewer/index.html`
directly and pick a `.jsonl` file via the file chooser (no server needed).

Live CLN runs (PROVEN 2026-09-01, gate green in 45s with 110 events
across 4 files): build the traced binaries once —

    cargo build -p vlsd --features splice_trace
    cargo build -p vls-proxy --features grpc,main,developer,splice_trace --bin remote_hsmd_socket

(the `developer` feature is mandatory in the splice-dev harness — pyln
sends hsmd_dev_preinit and a proxy without it dies at the handshake) —
then run the gate with the env set; it inherits through pytest →
lightningd → wrapper → vlsd/proxy:

    VLS_TRACE_DIR=$(pwd)/target/splice-traces-live \
      bash splice-dev/run-cln-splicing.sh "tests/test_splicing.py::test_splice"

Artifacts: one `cln-tap-<pid>.jsonl` per proxy (real hsmd boundary
traffic, source `proxy-tap`) and one `vls-<pid>.jsonl` per vlsd (real
signer events with era labels). Merge them in the viewer:
`?trace=cln-tap-X.jsonl,vls-Y.jsonl` (see docs/splice-trace-live.png —
era A locked at 1M sat, era B current at 1.1M sat from the live
splice-in). No driver lane in live runs yet — the pytest driver would
emit it (schema-ready).

Viewer layout reference: `docs/splice-trace-viewer.png` (RBF A→B→C
scenario, supersession event selected, before→after diff open).

## Scenario = executable specification

`ScenarioRunner::state()/transition()` record the *declared* state machine
(invariants attached to states) into the same trace; the viewer renders the
aggregate machine from the trace itself — no hand-written diagram that can
drift from test behavior. Each `invariant()` call is also an assertion, so
the declared model is enforced, not just narrated.

## Findings the tracer surfaced

See `docs/splice-trace-findings.md` — four divergences audited against
the pinned BOLTs and CLN source, headlined by **F1: remote funding key
rotation cannot splice through VLS** (spec-designed-in via per-splice
`funding_pubkey`s; CLN rotates its channel key only at mutual
`splice_locked` while requesting the signature — which spends the old
era's outpoint — with the still-old key). The scenario
`funding_key_rotation` pins it as `DIVERGENCE_EXPOSED`; its refusal
assert flips deliberately if the check becomes era-aware.

## Non-goals / boundaries

* The tracer does **not** redesign signer behavior. Where the logical model
  and the implementation disagree (e.g. only two previous eras retained,
  tracker listener replacement), the trace makes the mismatch visible
  (`retired_eras`, `lifecycle`, watch diffs) — behavioral fixes stay separate.
* `lightning-playground` (private) may drive scenarios later; the open VLS
  tooling has no dependency on it. The adapter surface is exactly the JSONL
  schema.
