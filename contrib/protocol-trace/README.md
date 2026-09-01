# protocol-trace — the lightning-trace/1 toolchain

Developer observability, interop-testing and visualization for the
CLN ↔ VLS state machine. One canonical JSONL schema
([`lightning-trace/1`](../../docs/splice-trace.md)), three independent
brains (driver / CLN / VLS), one run directory per execution.

| piece | what it is |
|---|---|
| `ptrace/schema.py` | envelope writer — seq/timestamps/provenance/level assigned by the writer, never the caller; refuses secret-shaped payload keys |
| `ptrace/cln_observer.py` | CLN's brain via **stock** `listpeerchannels` RPC (source `cln-rpc`) — no CLN patch, no prose parsing; inflight `last_tx` recorded as a sha256 fingerprint, never a fabricated txid |
| `ptrace/pytest_plugin.py` | driver lane for live runs: splice/fault/payment RPCs become `step`+`inject` events with before/after CLN snapshots; node restarts become `restart_cln`; loaded via `-p ptrace.pytest_plugin` — zero CLN-tree changes |
| `ptrace/merge.py` | run-dir assembler: merged `trace.jsonl` (wall-clock then actor-rank order), per-lane `actors/*.jsonl`, content-addressed `artifacts/`, `manifest.json` (VLS/CLN versions, env, repro command), `results.json` |
| `ptrace/llm.py` | deterministic `trace.llm.md` rendering — information-dense, LLM-ready, derived sections explicitly labeled |
| `ptrace/perfetto.py` | Chrome Trace JSON export (instants, request/response slices, cross-actor flow arrows) — open at ui.perfetto.dev |
| `tests/` | self-tests: serialization, redaction, level filtering, malformed/partial streams, merge order, determinism, perfetto validity, observer normalization |

## Commands

```sh
# assemble a run directory from a trace dir (live gate output)
python3 ptrace/cli.py merge <trace-dir> --out trace-runs/<id> \
    --vls-src ~/src/vls-splice/vls --cln-src ~/src/vls-splice/lightning \
    --command '<the exact gate command>'

# deterministic LLM text form of any trace
python3 ptrace/cli.py render <trace.jsonl>

# validated Perfetto/Chrome Trace export
python3 ptrace/cli.py perfetto <trace.jsonl> exports/perfetto.json

# serve the browser viewer on a run dir
python3 ptrace/cli.py view <run-dir> 8799
```

## Self-tests

```sh
python3 tests/test_ptrace.py        # or: python3 -m pytest tests -q
```

No pyln, no CLN, no network — pure fixtures.

## Env knobs (shared with the Rust sink)

| var | meaning |
|---|---|
| `VLS_TRACE_DIR` | tracing off unless set (all producers) |
| `VLS_TRACE_LEVEL` | `core` \| `base` (default) \| `extra` — core strips snapshots/artifacts, base keeps decoded artifacts, extra keeps raw bytes |
| `VLS_TRACE_INSTANCE` | actor instance label (`l1`, `l2`…) — set per node by the splice-dev wrapper so proxy/vlsd/driver lanes merge |
| `VLS_TRACE_SCENARIO` | scenario id override |
| `VLS_TRACE_RUN_ID` | stable run id override |
