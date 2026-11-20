# Fork-delta upstreamability map — `inr2-splice-dev` vs upstream `main`

Scope: 93 commits, 91 files, +14,469/−262 over the merge base
`adc1b333` (upstream `main` at the fork point). This map groups the
delta for the eventual upstream split required by issue #2. **No
upstream MR is opened from this map alone** — each group lands only
after owner coordination (issue #2's rule).

Groups follow the issue's taxonomy (policy / persistence / transport /
trace-only) plus three the delta actually contains (core state model,
tests/rails, fuzz) and a drop-list. Commits cited by short SHA.

## A. Policy — signer-side safety rules

The splice window breaks upstream's burial/unspent assumptions by
design; these commits teach the policy layer the window.

| What | Commits | Upstream posture |
|---|---|---|
| Splice-aware onchain policy: `ChainState::splice_pending`, burial no longer required mid-window, unspent/closing checks always on | `37d261fd` | Design discussion needed — changes a safety rule's shape, not its goal |
| Era-aware valuation: `EnforcementState::{holder,counterparty}_commit_info_for`, per-era `claimable_balances` fallbacks, retry rails era-aware (#106 cross-scale fix) | `2a588b44`, `827401dd`, `3ab799e5` | The disconnect-tier root cause; strongest correctness MR material |
| Graceful rejection on claimable underflow (no signer kill) | `4c82e753` | Pure hardening, upstreamable as-is |
| `VLS_POLICY_BACKTRACE` gate (unconditional backtrace symbolization on temporary warnings: 1.14 s per post-splice sign) | `f8c00726` | Perf fix; generalizes beyond splice |
| Era-blind remote-key check fix (F1: a rotating peer can never splice through VLS) | `b7c82769` | Security-relevant latent bug; spec-anchored (BOLT #2 quotes, `42a5fead`) |
| Funding-era token on the `_phase2` twins (era-blind cross-scale binding removed, #112) | `95e4d71a` | Wire-visible semantics; needs upstream schema coordination |
| Capability advertisement refresh (comment-only) | `7ab24e4a` | Trivial |

Files: `vls-core/src/policy/{validator,simple_validator,onchain_validator}.rs`,
`vls-core/src/chain/` (ChainState).

## B. Persistence — additive, serde-defaulted fields

| What | Commits | Notes |
|---|---|---|
| `prev_setup` on `ChannelEntry` (serde default; old datadirs load as `None`), threaded through `kvv.rs` + restore | `b41be620` | Additive; upstream-safe |
| `prev_prev_setup` two-deep chain (RBF window: three coexisting fundings), same pattern | `dc5b77e7` | Additive |
| Tracker-listener retirement at the splice swap (restore no longer panics on dual entries) | `f6f264f5` | Ties into monitor group E |
| Snapshot survives persist round-trip; restored signer accepts stragglers | `2a588b44` (rail `splice_window_state_survives_persist_roundtrip`) | Rails ride with the feature |

Files: `vls-core/src/persist/model.rs`, `vls-persist/src/kvv.rs`,
`vls-core/src/channel.rs` (fields).

## C. Transport — hsmd ↔ signer ↔ proxy robustness

All independent of splice semantics; each fixes a proxy/vlsd death or
hang observed live. Best-first upstream candidates.

| What | Commits |
|---|---|
| Failed oneshot reply-send demoted from proxy-wide shutdown to warn+drop (restarts stopped killing the proxy) | `881c1a10` |
| Unknown/duplicate request-ID demotion (at-least-once redelivery no longer fatal) | `72bcfa00` |
| Empty vlsd reply → `TransportTransient` (was: raw forward, CLN parses `Bad setup_channel_reply`, node dies) | `cdc72bf3` |
| `signer_stream` establishment retries instead of unwrap-panic; ping retries; proxy continues on signer errors | `40bd7662`, `e7682b17` |
| Handler `expect("pubkey")` sweep → graceful `invalid_argument` (fuzz-bait hardening) | `0aa7653d` |
| `HsmdDevPreinit2` replay on stream reconnect (was a panic) | `f06a1df1` (handler arm) |

Files: `vls-proxy/src/grpc/adapter.rs`, `vlsd/src/grpc/signer.rs`,
`vls-protocol-signer/src/handler.rs`.

## D. Trace-only — feature `splice_trace`, near-zero semantic delta

Largest volume, fully separable behind the feature flag; instrumentation
compiles to nothing when off (one relaxed atomic load per site when on
without `VLS_TRACE_DIR`).

Delta disclosure: not literally zero — `c99a64b0`'s wrapper-fn pattern
makes `containing_function!()` emit `_inner` names, and the same commit
updates 8 policy-failure expectations
(`sign_counterparty_commitment_tx` → `…_inner`): an observable
error-string change for any client or test inspecting policy-failure
error strings (fork tests were updated in-commit). Preserving original
function identity would remove the delta; as mapped, disclose it in the
MR description.

- Schema + envelope: `7eb737f4` (vls-trace/1 → `lightning-trace/1` via
  `c606e469`) — **no-secret-by-convention** (no trace API is *meant* to
  accept key material; owner directive 2026-09-01). Precision: this is a
  convention enforced by review, not by construction —
  `artifact_other`/`artifact_message` (`vls-core/src/trace/artifact.rs`)
  accept arbitrary strings with no secret-shaped validation and
  `TraceArtifact.raw`/`.decoded` are `pub`, so the rule lives in the
  module doc comment. Upstreaming as-is relies on that convention; a
  narrowing pass (validator or private fields) would make it
  construction-enforced and is the stronger form of the argument.
- Instrumented choke points + wrapper-fn pattern: `c99a64b0`
- Live-run plumbing, self-deadlock fix, pid-named sinks:
  `9c2b59b4`, `a20ad771`, `23af16f7`
- ScenarioRunner + traced scenarios (`splice_scenario_tests.rs`,
  `#[cfg(all(test, feature = "splice_trace"))]`): `1cd79fae`, `8afe7bcb`
- Proxy tap (`vls-proxy/src/trace_tap.rs`), Python toolchain
  (`contrib/protocol-trace/`), viewer (`contrib/trace-viewer/`):
  `6385dcb0`, `94d96b84`, `020ebfd3`
- Docs: `docs/splice-trace.md`, `docs/splice-trace-findings.md`
  (`22b2ee01`, `730c466d`, `0a872304`, `3e8141c8`)

Hazards: 6 committed `.pyc` files under
`contrib/protocol-trace/ptrace/__pycache__/` — **drop before any MR**
(see drop-list).

## E. Core splice engine / state model — the main series

The heart of the fork; must be split further for review. Arcs, in
dependency order:

1. **Sign path**: `f06a1df1` (SignSpliceTx + setup transition),
   `b6417f51` (sign prev funding input), `eb451bc2` (host-tx fork —
   splice-resume rejection loop).
2. **Same-number commitment model**: `f5ebf971`, `5a44eed8`,
   `a354ac0e`, `2e036bc1`, `2d5c4db1` (carve-outs gated on an actual
   splice window), `07cadcf0`/`d0b8c640` (view-parameterized
   recomposition; per-funding slots), `0d953a36` (route validation by
   the tx's funding).
3. **Funding-view snapshots & stragglers**: `684cc197`, `41777237`,
   `2a588b44` (era-mixing cluster — see also group A).
4. **RBF window**: `942b16b6` (keep-oldest prev_setup) → `dc5b77e7`
   (two-deep chain — the 12/12 delivery commit).
5. **Lockin lifecycle**: `5c1a9ec6` (conditional lockin-clearing),
   `a3113ca9` (baseline commitment infos at lockin — mutual-close fix),
   `b8d8933e`/`f0e8c8cb` (num-0 replay guards), `1eaa6264`.
6. **Monitor**: `769d4c89` (multi-input spend = splice, not close),
   `3946b7f7` (window reorg rails).
7. **Fundee conventions**: `8f58e48d` (wrapped push_value on out-splices).

Files: `vls-core/src/{channel,node,monitor}.rs`, `vls-core/src/tx/`,
`vls-core/src/signer/`.

## F. Tests & rails — ride with their target groups

`strict_mode_tests.rs` (883 lines, the #94 classes A–D fixes
`f75bc339` + class-B kill proofs `2e2f9775`/`74586f59`),
`validate_holder_commitment_tests.rs` (744), `setup_channel_tests.rs`
(518), `straggler_balance_tests.rs` (428, mutation-kill rails
`6dba9146`/`e490e247`), `mutant_rails_tests.rs` (350, `00d54ddb`),
`phase2_era_rails_tests.rs` (305), `sign_splice_tests.rs` (156),
`splice_restore_test.rs` (152, `f4052bac`), scenario infra
(`util/test_utils/scenario.rs`). BOLT-quote anchors across the seven
splice-semantics sites: `42a5fead` (spec-quotes-verified against bolts
pin `1528972`).

## G. Fuzz — splice-aware harness + corpus

`15e5f234` (six Actions / six invariants over the real Node+channel),
`4ac8430e` (corpus seeder; `arbitrary` 1.4.2 byte format derived),
`5e566f59` (era-unique funding txid — the banked
`crash-ea2b01b6` corpus file is a harness false-positive record, replayed
in CI), `ed0df7da`, `989db24c`, `f20f3b18` (the `--cfg=fuzzing` test
contract), `3d240e9e` (fuzzer joins the snapshot model). Note:
`15e5f234` also carries the lightning-0.2.5 `MAX_HTLCS` compat const —
upstreamable separately as a dependency-bump fix.

## H. Fork-local build/config — the drop-list (never upstream as-is)

| Item | Commit | Disposition |
|---|---|---|
| `[patch.crates-io] txoo = { path = "../txoo-src" }` | `f06a1df1` | Drop at MR time (self-noted in `a121c683`); CI must keep cloning the pinned sibling `4220cf69` instead |
| `[profile.mutants]` | `a121c683` | Drop at MR time (self-noted) |
| `vls-core-test/Cargo.lock` | `573f1812` | Rework: make the excluded crate resolve without a committed lock |
| `contrib/protocol-trace/ptrace/__pycache__/*.pyc` (6 files) | trace series | Delete + `.gitignore` |
| `VLS_DELAY_MS` latency knob (vlsd) | `b528121e` | Dev tooling; owner decision (guard-gated MR or keep fork-local) |
| Root `Cargo.lock` churn | various | Rides the MRs' dep bumps |

## Suggested MR order (smallest-risk first; NOT all independently landable)

Dependency correction: B's `b41be620` (`prev_setup` on `ChannelEntry`)
and A's `b7c82769`/`f6f264f5` modify fields/paths introduced by E's
`f06a1df1` — B and A are NOT independently landable before E's
foundational arc against the stated base `adc1b333`. E goes first (or
those three commits split out as an E-prerequisite MR).

1. C — transport robustness (no semantic dependencies)
2. E — core engine, split by the seven arcs above; the `f06a1df1`
   foundational arc lands FIRST (B and A's commits depend on its
   fields/paths)
3. B — persistence fields (additive, serde-defaulted; rides E's
   `f06a1df1` fields)
4. A — policy fixes (design discussion; strongest items: `4c82e753`,
   `b7c82769`, `f8c00726`)
5. F — rails riding their targets (already inside the arcs' commits
   where co-located; standalone files land with the matching arc)
6. G — fuzz harness + corpus
7. D — trace tooling, last and optional (large; the no-secret-by-
   construction property is the argument; drop-list items die here)

Every step requires owner coordination before anything is filed
upstream (issue #2 rule). Status claims stay synced to
[docs/splice-status.md](./splice-status.md).
