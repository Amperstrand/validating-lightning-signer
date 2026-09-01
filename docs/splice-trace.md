# Splice state-machine tracing and visualization

**Status**: architecture as implemented (2026-09-01, branch `inr2-splice-dev`)
**Purpose**: a microscope for the CLN ↔ VLS splice state machine — one canonical
trace format, three synchronized perspectives (VLS / CLN / test-driver), a
browser visualizer that steps through a run like a debugger, a Perfetto
export for generic timelines, and a deterministic LLM-oriented text form.

## Why

Splice windows are the hardest state in the signer: during RBF supersession
three funding generations coexist (`setup` / `prev_setup` / `prev_prev_setup`),
commitment infos belong to *different eras* than the channel-scoped fields
suggest, and the interesting bugs (era-mixing underflows, straggler
re-validation, same-number re-signs) are only visible when you can ask
*"what did each participant believe at this exact point?"*. Human log lines
cannot answer that; a correlated, stateful trace can.

## Prior art — adopted and deliberately not

Researched before this design; each row says what we took and what we
consciously left.

| source | adopted | deliberately not |
|---|---|---|
| **qlog / qvis** | vantage points (our three actors are vantage points with independent testimony); importance tiers (core/base/extra ≈ qlog's Core/Base/Extra); event *titles* as short semantic names; group ids (our `correlation_id`); the "file may contain multiple traces / partial traces" tolerance; viewer with per-vantage-point lanes + sequence view | qlog conformance claim (we are not QUIC; the schema name is ours); qlog's JSON hierarchical event nesting (flat tagged payloads parse safer across languages); qvis's file format specifics |
| **QUIC interop runner** | per-implementation logs merged by the runner; reproducible result directories; test result summary (results.json); per-side logs kept raw beside the merged trace | a dedicated interop-runner service with client matrix web UI (our matrix is 1 client × pinned CLN revisions for now) |
| **Ethereum Hive** | pinned client versions recorded per run (manifest.json); simulation = neutral driver, clients observed not modified; JSON results + browser presentation (the viewer) | arbitrary-client adapter registration protocol (our "adapters" are the actor lanes: proxy tap, vlsd sink, RPC observer) |
| **OpenTelemetry** | the span-vs-point-event distinction (request→response become Perfetto slices + `cln_request`/`cln_response` point events; state changes are always instants, never durations); correlation semantics (trace id ≈ run id, span id ≈ correlation id) | an OTel collector/SDK dependency (processes must stay dependency-free; JSONL is the contract); OTel's cross-service clock assumption — we merge by wall clock *then actor rank*, an explicit causal partial order |
| **Perfetto / Chrome Trace** | the exporter (`exports/perfetto.json`): lane processes, instants, duration slices for hsmd request/response pairs, flow arrows for cross-actor correlations — generic timeline view for free | Perfetto as the primary UI (no Lightning-specific semantics: eras, policies, brains); the Perfetto trace-proto native format (Chrome JSON opens fine) |
| **lnprototest / LN interop initiative** | the *vertical/horizontal/self* testing split (unit ↔ protocol-handler ↔ full-CLN integration); tests as an executable specification with assertions in the trace | the lnprototest DSL/runner (pyln + CLN's own tests via import-farm already cover it better for us) |
| **vls-hsmd system-test repo** | version pinning, the CLN test reuse (import-farm) pattern, signer substitution via `SUBDAEMON` wrapper | hosting the framework there — the VLS repo owns VLS instrumentation; the harness only drives |
| **CLN pyln-testing / test_splicing.py** | `node_factory`, real daemons, dev_disconnect, wait_for_log, RPC state inspection — the live scenarios ARE CLN's tests; the driver plugin wraps them at runtime | patching CLN test files (the plugin is runtime interception: zero CLN-tree changes); a CLN structured-trace fork (stock RPC + hsmd proxy tap suffice today — see visibility gaps) |
| **LND lntest** | failure artifact discipline (traces survive test failure; crashes become events when detectable; artifact retention tiers) | LND's Go test harness (we stay pytest/pyln) |
| **LDK/rust-lightning testing** | deterministic scenario seeds; persistence-reload reconstruction tests (the restore scenario); "assert values, not verdicts" | LDK's fuzz-target-per-component shape (we have the splice fuzz harness with checkpoint emission instead) |

## The one canonical trace

`schema: lightning-trace/1` (renamed from `vls-trace/1` when the model grew
provenance/level/instance semantics — readers accept both tags) —
newline-delimited JSON, one envelope per line:

```json
{
  "schema": "lightning-trace/1",
  "run_id": "…",
  "scenario_id": "rbf_a_b_c",
  "seq": 42,
  "actor": "vls",              // driver | cln | vls
  "actor_instance": "l1",      // which node of that kind (farm lanes)
  "actor_seq": 18,
  "ts_us": 1735689600123,
  "mono_us": 123456,
  "provenance": "observed",    // observed | expected — sink-assigned
  "level": "core",             // core | base | extra — sink-assigned
  "correlation_id": "step-7",
  "channel_id": "…hex…",
  "event": { "type": "sign_splice_tx", … typed fields … },
  "before": { …ChannelSnapshot… },
  "after": { …ChannelSnapshot… },
  "artifacts": [ { "kind": "tx", "raw": "<hex>", "decoded": { "txid": … }, "sha256": "…" } ],
  "result": { "status": "rejected", "code": "InvalidArgument", "message": "…" }
}
```

Structural rules (each earned by a use case):

* `event` is a **tagged enum** — unknown future types still parse (open-world;
  the viewer degrades gracefully and shows raw fields).
* `seq`/`actor_seq`/`mono_us` are **assigned by the sink**, not the emitter.
* **provenance is sink-assigned from the payload type**: driver assertions and
  declared state-machine models are `expected`; everything an implementation
  emits is `observed`. `derived` exists only in consumers (the viewer's
  disagreement detector, the LLM renderer's footer) — no emitter can produce
  it, so inference can never be laundered as testimony. CLN events additionally
  carry a `source` (`cln-rpc` | `proxy-tap` | `test-peer` | …) naming the
  observation boundary.
* **levels** (qlog-style importance): `core` = small semantic events (CI-safe),
  `base` = state snapshots + decoded diagnostics, `extra` = raw bytes. The sink
  filters attachments: core strips `before`/`after`/`artifacts`; base keeps
  decoded artifacts but strips `raw`; extra keeps everything. Switch:
  `VLS_TRACE_LEVEL=off|core|base|extra` (default base; `off` disables tracing
  outright).
* **actor_instance** (`VLS_TRACE_INSTANCE`, e.g. `l1`) is stamped by the sink:
  live farms run one vlsd + one proxy per lightningd, all in one trace dir —
  instance stamps merge them into `cln:l1` / `vls:l1` lanes.
* era identity is **first-class**: every snapshot carries `eras: []` with
  stable labels (`A`, `B`, `C`…) assigned on first outpoint sighting, each with
  `lifecycle` (`current|previous|prev_prev|locked|retired`), value, remote
  funding key, per-era holder/counterparty commitment summaries and watch
  state. The logical model (N generations) is representable even where the
  implementation only keeps `current + prev + prev_prev` — the tracer shows
  what exists, and *shows the absence* (e.g. `retired` lists record what a
  `funding_locked` dropped).
* snapshots are built through the **same era-aware resolvers the signer uses**
  (`EnforcementState::holder_commit_info_for` etc.) — the visualization can
  never disagree with what VLS would actually resolve for a view.
* `artifacts` may carry `sha256` — content-addressed raw bytes in the run
  directory (`artifacts/sha256-<h>`), de-duplicated; the viewer fetches on
  demand. Big raws are replaced by the reference.

### Secrets

Private key material never enters the trace **structurally**: the snapshot and
artifact builders are typed over public data only (`PublicKey`, outpoints,
txids, amounts, `CommitmentInfo2`). There is no `SecretKey`/seed parameter
anywhere in the trace API, so traces are publish-safe by construction — pinned
by a Rust test against the channel's real key material, and the Python writer
additionally *refuses* secret-shaped payload keys. Addresses, transactions and
PSBTs are **never redacted** on test networks (owner directive 2026-09-01:
signet/regtest/testnet money is throwaway; only key material must stay out).

## Actors and observation boundaries

| actor | emits | boundary / source label |
|---|---|---|
| `driver` | scenario_start/end, step, inject, expect, invariant, state/transition_declared | unit: `ScenarioRunner`; live: `ptrace.pytest_plugin` (runtime-wraps pyln `LightningRpc.call` + `LightningNode.restart` — zero CLN-tree changes) |
| `cln` | cln_request, cln_response, cln_state, cln_event | (a) `test-peer` (unit scenarios, harness as CLN's protocol peer), (b) `proxy-tap` (live hsmd boundary in vls-proxy), (c) `cln-rpc` (live stock-RPC snapshots from `listpeerchannels` via `ptrace.cln_observer`) |
| `vls` | setup_channel, splice_setup, funding_view_resolved, sign_splice_tx, validate_holder_commitment, sign_counterparty_commitment, funding_locked, monitor_update, persisted, restored, snapshot_checkpoint | choke points in `channel.rs` / `node.rs` (feature `splice_trace`, off by default) + the fuzz harness |

**Honesty rules**: CLN's *channel state* observations come only from real RPC
fields (`cln-rpc`) or real hsmd boundary traffic (`proxy-tap`); the CLN *brain*
(internal channeld beliefs between observations) is NOT inferred. Visibility
gaps (documented, not faked): no continuous state stream (snapshots exist at
observation points), no channeld-internal transient state, inflight `last_tx`
recorded as a sha256 fingerprint (a real txid would require non-witness
serialization we don't do there). A future CLN developer-only structured trace
hook would slot in as a fourth source label; nothing in the schema or viewer
depends on its existence.

## Cost model

* Feature `splice_trace` is **off by default** → instrumentation compiles to
  nothing in production builds.
* With the feature on, emission is gated by a single relaxed atomic load
  (`trace::enabled()`); sink not initialized → zero work beyond the check.
* CORE-level live tracing is small by construction (attachments stripped).
* Tests enable it with `VLS_TRACE_DIR=<dir>` (opt-in per run; normal
  `cargo test` writes nothing).

## Layout

```
vls-core/src/trace/            canonical model (feature `splice_trace`)
  mod.rs                       module root, re-exports, emit macros
  event.rs                     envelope + EventPayload + provenance/levels
  snapshot.rs                  ChannelSnapshot/FundingEraView + builder
  artifact.rs                  TraceArtifact (raw + decoded) + tx/psbt decode
  sink.rs                      JSONL sink, seq/labels, levels, instance stamps
vls-core/src/util/test_utils/scenario.rs   ScenarioRunner (driver actor)
vls-core/src/splice_scenario_tests.rs      traced scenario suite (8)
vls-proxy/src/trace_tap.rs                live cln↔vls boundary tap
contrib/protocol-trace/                   Python toolchain (ptrace)
  ptrace/schema.py             envelope writer + level/provenance tables
  ptrace/cln_observer.py       stock-RPC CLN observer
  ptrace/pytest_plugin.py      live driver lane (pyln runtime wrapper)
  ptrace/merge.py              run-directory assembler
  ptrace/llm.py                deterministic trace.llm.md renderer
  ptrace/perfetto.py           Chrome Trace JSON exporter (+validation)
  ptrace/cli.py                merge / render / perfetto / view verbs
  tests/test_ptrace.py         21 self-tests (no pyln, no CLN)
contrib/trace-viewer/          static browser visualizer + tiny server
docs/splice-trace.md           this file
```

## Run directories

Every live execution produces a self-describing directory (the gate assembles
it automatically when `VLS_TRACE_DIR` is set; `ptrace merge` manually
otherwise):

```
<trace-dir>/trace-runs/<run-id>/
    manifest.json        VLS/CLN git versions, env, exact repro command,
                         source files + event counts, node map
    trace.jsonl          merged canonical trace (wall clock, then actor
                         rank driver<cln<vls — the causal partial order)
    trace.llm.md         deterministic LLM-oriented rendering
    results.json         scenario outcomes + failed invariants
    actors/              per-lane files (driver.jsonl, cln-l1.jsonl, …)
    artifacts/           content-addressed raw artifacts (sha256-<h>)
    exports/perfetto.json  Chrome Trace JSON (generic timeline)
```

## Workflow

### Unit scenarios (deterministic, no CLN)

From the repo root (absolute `VLS_TRACE_DIR` — the test binary's CWD is the
package dir):

```
VLS_TRACE_DIR=$(pwd)/target/splice-traces \
  cargo test -p vls-core --features test_utils splice_scenario -- --test-threads=1

python3 contrib/trace-viewer/serve.py target/splice-traces 8799
# open http://localhost:8799/index.html?trace=rbf_a_b_c.jsonl
```

### One real CLN+VLS scenario, end to end (the developer workflow)

Build the traced binaries once —

```
cargo build -p vlsd --features splice_trace
cargo build -p vls-proxy --features grpc,main,developer,splice_trace --bin remote_hsmd_socket
```

(`developer` is mandatory in the splice-dev harness — pyln sends
`hsmd_dev_preinit` and a proxy without it dies at the handshake) — then run
the gate with the env set; it inherits through pytest → lightningd → wrapper
→ vlsd/proxy:

```
VLS_TRACE_DIR=$(pwd)/target/splice-traces-live \
  bash ~/src/lightning-playground/splice-dev/run-cln-splicing.sh \
      "tests/test_splicing.py::test_splice"
```

On exit the gate prints `TRACE RUN DIR: …/trace-runs/<id>` — the assembled
directory (merged three-lane trace, manifest with versions, LLM rendering,
Perfetto export). Inspect it three ways:

```
# browser: step through the three brains
python3 contrib/trace-viewer/serve.py <run-dir> 8799
# open http://localhost:8799/index.html?trace=trace.jsonl

# LLM / terminal: deterministic dense text
less <run-dir>/trace.llm.md

# generic timeline (slices + flow arrows)
# open https://ui.perfetto.dev → "Open with legacy JSON" → exports/perfetto.json
```

The three-brain live view is proven: `docs/splice-trace-three-brain.png`
(DRIVER/CLN/VLS lanes all populated from three separate processes — pytest
plugin + proxy taps + vlsd — merged by timestamp; first proof 2026-09-01,
gate green in 42s, 113 events across 5 files), and
`docs/splice-trace-live.png` (era A locked at 1M sat, era B current at
1.1M sat from the live splice-in). Viewer layout reference:
`docs/splice-trace-viewer.png` (RBF A→B→C scenario, supersession event
selected, before→after diff open).

The same machinery runs any CLN splice test (e.g. `test_splice_rbf` for the
A→B→C supersession, the disconnect pair for retransmit/restart windows).

## Scenario = executable specification

`ScenarioRunner::state()/transition()` record the *declared* state machine
(invariants attached to states) into the same trace; the viewer renders the
aggregate machine from the trace itself — no hand-written diagram that can
drift from test behavior. Each `invariant()` call is also an assertion, so
the declared model is enforced, not just narrated.

## Determinism / replay

The manifest carries VLS + CLN git describe, env (VLS_MODE, VLS_PERMISSIVE,
VLS_TRACE_LEVEL, TEST_NETWORK), the exact command, and the node map. Unit
scenarios are deterministic by construction (no clocks in the assertions —
`canonical_events` strips volatile fields). Known limitation, honestly
recorded: **era labels are per-signer-process** — a restarted vlsd re-labels
from `A` on re-sighting; the outpoint (always present) is the durable era
identity across restarts.

## Findings the tracer surfaced

See `docs/splice-trace-findings.md` — four divergences audited against the
pinned BOLTs and CLN source, headlined by **F1: remote funding key rotation
cannot splice through VLS** (spec-designed-in via per-splice
`funding_pubkey`s; CLN rotates its channel key only at mutual
`splice_locked` while requesting the signature — which spends the old era's
outpoint — with the still-old key). The scenario `funding_key_rotation` pins
it as `DIVERGENCE_EXPOSED`.

## CI tiers

Tracing is opt-in per run; CI should keep it that way:

| tier | tracing | what runs |
|---|---|---|
| normal unit CI | off | full `cargo test` (the tracer's own unit tests included — they use in-memory sinks, no `VLS_TRACE_DIR`) |
| splice compatibility CI | `VLS_TRACE_LEVEL=core` | the traced live gate on the **pinned supported CLN revision**; on failure upload the run dir (trace + llm.md + perfetto + component logs) |
| nightly / extended | `VLS_TRACE_LEVEL=base` | RBF/restart/disconnect/chaos scenarios; latest CLN release + CLN master informational jobs |
| manual troubleshooting | `extra` | raw artifacts on, full forensic fidelity |

Repository-local commands above are exactly what CI calls; the exact CLN
compatibility matrix (pinned-required / latest-release / master-nightly) is
recorded per run in `manifest.json.versions`.

## Non-goals / boundaries

* The tracer does **not** redesign signer behavior. Where the logical model
  and the implementation disagree (e.g. only two previous eras retained,
  tracker listener replacement), the trace makes the mismatch visible —
  behavioral fixes stay separate (the strict94 fix series landed beside the
  tracer, not inside it).
* No React/framework in the viewer; no OTel/collector dependency; no qlog
  conformance claim; no mandatory CLN patch.
