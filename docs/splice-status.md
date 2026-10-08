# Splicing support status — the single source of truth

This file is the tracked, machine-checkable record of CLN splice-suite
support on this fork. The repository description and any external status
claims must agree with it. `contrib/check-splice-status.sh` validates the
machine-readable block below and fails on drift; CI runs it on every PR.

## Verdict

**12 of 12 CLN splice-suite cases green** — delivered 2026-08-30 in
`dc5b77e73e93896f5f9af371ef3304b27ca9ec5c` ("THE TWO-DEEP PREV CHAIN",
12 passed in 372.99 s, native speed) and retained by every later commit
on `inr2-splice-dev`. Verified in **both** permissive and strict
(`VLS_PERMISSIVE=0`) signer modes.

The pre-delivery history (10/12, 11/12 milestones) is campaign history,
not current status. Any doc, badge, or description saying otherwise is
stale — fix the doc, not the ladder.

## Machine-readable status

```toml
[status]
verified_cases = 12
total_cases = 12
modes = ["permissive", "strict"]
last_delivered = 2026-08-30
last_strict_verified = 2026-10-08
delivery_commit = "dc5b77e73e93896f5f9af371ef3304b27ca9ec5c"

[cln]
# Delivery ladder (2026-08-30): CLN v26.06.6 + harness-side wrapper
# (counter wrapper, lightning-playground @ 7721ef2) + fixtures patch 0003.
delivery_revision = "v26.06.6"
# Strict-mode re-verification (2026-09-02/03) and all later ladder runs:
# the CLN fork branch, @ 5f8f28785 (pushed 2026-09-02) with replay rails
# @ 1fe46dec3; branch advances, ladder re-proven per advance.
# 2026-09-30 (D1 negative-guard redesign, playground #268): strict
# re-verified on the -ff lineage + D1 convention branch — push_value is
# the fundee TOTAL post-splice balance (owed + fundee-pending HTLCs +
# signed relative); the same stack is pending lineage merge (owner call).
# 2026-09-30 late (D1 final): the newest verification below ran the FULL
# D1 pair — CLN negative-guard-redesign-v26@988251455 (D1 host term on
# -v26.06.8) + vls negative-guard-redesign@fd710500; pin tracks it.
fork_repo = "Amperstrand/lightning"
fork_branch = "negative-guard-redesign-v26"
strict_verified_revision = "988251455"
suite_file = "tests/test_splicing.py"

[vls]
branch = "inr2-splice-dev"
# The deterministic (no live nodes) splice suites CI must keep green:
unit_suite = "cargo test -p vls-core --features test_utils splice"
scenario_suite = "cargo test -p vls-core --features test_utils,splice_trace splice_scenario"
restore_suite = "cd vls-core-test && cargo test --test splice_restore_test"
fuzz_suite = "cd fuzz && RUSTFLAGS=--cfg=fuzzing cargo test"

[verification_log]
# Newest last. Only full-ladder rows belong here.
2026-08-30 = "delivery: 12 passed in 372.99s (2x consecutive)"
2026-08-31 = "soak: 5/5 rc=0, arm-verified (claim upgraded 2x -> 7x)"
2026-09-02 = "permissive full matrix 59/0 incl. test_splicing 12/12"
2026-09-03 = "strict 12 passed in 385.42s @ the 1800s bound"
2026-09-30 = "strict 12/12 manifest green, 19P/0F before a 1800s reap in the non-manifest EC-7 late force-close remainder (abort_after_sigs_sent itself green post 63aa71b6) — CLN inr2-splice-harness-v26.06.8@5e799b8f2 (full 3-bug fundee fix: units + channel-role + prior-balance, = upstream PR 9591 splice-fundee-msat semantics), vlsd bins splice-initial-allowance-exact@4a82f3b8 (PR-A/B/C + 63aa71b6 EC-7 close fix + 7effd825 carried-term drop: allowance = reported push exactly), ARM cln:socket 54 starts; native arm rc=0; D1 FINAL same day (playground #268 owner decision, negative-guard-redesign pair: CLN negative-guard-redesign-v26@988251455 + twin -ff branch negative-guard-redesign@50b3b6bf8 — host total now includes pending-at-setup HTLCs attributable to the fundee — and vls negative-guard-redesign@fd710500 — WARN stray-host detectors + fundee-splice-out rail): manifest 12/12 strict in a COMPLETED 326.80s run, ARM cln:socket 50 starts, vls-core 687/0, unit rails 3x + RED/GREEN A/B; EC-7 family deselected there (pre-existing base stall, reproduced identically with D1-free control bins @5ff8c8d8), non-manifest rbf_htlc_sigs teardown gossip error; -ff lineage full file under D1 18/19 (sole failure = the pre-existing -ff gossip drift, present in the pre-D1 soak)"
2026-10-08 = "strict 24/24 rc=0 in a COMPLETED 395.32s full-file run (manifest 12/12 within), ARM cln:socket — the single canonical union branch (d1-integration + verification-row docs) vlsd@342683a3, CLN inr2-splice-harness-v26.06.9@c29c545ae (upstream v26.06.9 patch base; #125 machinery dropped as superseded by .9 upstream crash-resume series; #124/#130 tolerance loop, #270 wedge series, lightning PRs #1-3, D1 absolute-balance carried; stamps aligned v26.06.9-32-gc29c545) — same-day battery green: two_chan strict rc=0, permissive full-matrix rc=0, edges rc=0, crash-window rc=0, vls-core 669/0; re-verified on the union after the merge (first pass on the pre-union base: 24/24 in 540.22s)"
```

## The 12-case ladder

From the CLN fork's `tests/test_splicing.py` (branch
`inr2-splice-harness`). This table is the executable manifest — the
checker counts these rows against `verified_cases`.

| # | Case (`tests/test_splicing.py`) | Delivered | Strict-verified |
|---|---|---|---|
| 1 | `test_splice` | 2026-08-30 | 2026-09-30 |
| 2 | `test_two_chan_splice_in` | 2026-08-30 | 2026-09-30 |
| 3 | `test_splice_rbf` | 2026-08-30 | 2026-09-30 |
| 4 | `test_splice_nosign` | 2026-08-30 | 2026-09-30 |
| 5 | `test_splice_gossip` | 2026-08-30 | 2026-09-30 |
| 6 | `test_splice_listnodes` | 2026-08-30 | 2026-09-30 |
| 7 | `test_splice_out` | 2026-08-30 | 2026-09-30 |
| 8 | `test_invalid_splice` | 2026-08-30 | 2026-09-30 |
| 9 | `test_commit_crash_splice` | 2026-08-30 | 2026-09-30 |
| 10 | `test_splice_stuck_htlc` | 2026-08-30 | 2026-09-30 |
| 11 | `test_route_by_old_scid` | 2026-08-30 | 2026-09-30 |
| 12 | `test_splice_unannounced` | 2026-08-30 | 2026-09-30 |

Release/master CLN probes are **informational** until explicitly promoted
to this table (promotion = a full-ladder row in `[verification_log]`).

## Determinism record

- 2× consecutive at delivery (2026-08-30), upgraded to 7× consecutive by
  the N=5 soak (2026-08-31, every run rc=0, every row arm-verified
  `cln:socket` — i.e. VLS actually signed, not a stock-hsmd escape).
- Permissive full matrix 59 green / 0 failed (test_splicing 12/12,
  disconnect 2/2, splice_edges 4/4, insane 6/6, crash_window 1/1),
  2026-09-02.
- Strict mode all-green at the proper 1800 s bound (2026-09-03); the
  earlier strict rc=124s were under-sized timeout bounds, not failures.

## Where evidence lives

Live-ladder evidence (ledgers, verdicts, wire decodes) is retained in the
private `Amperstrand/lightning-playground` campaign tree
(`splice-dev/STATE.md`, `test-artifacts/`) — nothing there belongs in
this public repo. Public, reproducible proof of the deterministic layers
is exactly what CI on this repo provides (see `.github/workflows/`).

## Drift rules

1. A ladder result changes status only through a new
   `[verification_log]` row + table update in this file, in the same
   commit as the claim.
2. The repository description must mirror `status.verified_cases` /
   `status.total_cases` ("12/12"). The description update is an owner
   action (`gh repo edit`), listed in issue #2.
3. `contrib/check-splice-status.sh` must stay green in CI; it fails on
   any count/revision/table disagreement inside this file.
