# Splice tracer findings — the microscope's output, audited against spec + CLN source

**Date**: 2026-09-01 · **Method**: `vls-trace/1` traces (unit scenarios + live gate),
[BOLTs pinned at 1528972](/home/ubuntu/src/bolts) `02-peer-protocol.md` splicing sections,
CLN source at `~/src/vls-splice/lightning` (v26.06.6 tree). Each verdict names what the
trace proved and what the sources say; fixes stay separable from the tracer per policy.

---

## F1 — Remote funding key rotation breaks splice signing against VLS (REAL BUG, spec-supported)

**What the trace proved** (`scenario_funding_key_rotation`, state `DIVERGENCE_EXPOSED`):
after a key-rotating splice swap A/KA → B/KB, era A's snapshot carries
`remote_funding_key = KA` while `sign_splice_tx` refuses every key except KB —
including KA, the key of the era whose outpoint the input spends.

**What the spec says** (BOLTs 1528972, `splice_init`/`splice_ack`): the new funding
output is built from per-splice `funding_pubkey` points — **rotation is designed in**.
All splices in a window spend the *original* funding output (the Splice Completion
diagram: Funding Tx → Splice Tx / Splice RBF #1 / RBF #2), so an input's redeemscript
is always the PREVIOUS funding's 2-of-2.

**What CLN does** (channeld.c): both `sign_splice_tx` call sites (3903, 4649) pass
`peer->channel->funding_pubkey[REMOTE]` — the channel-level key. That key is rotated
**only at mutual `splice_locked`** (line 499: `funding_pubkey[REMOTE] =
inflight->remote_funding`, immediately before `lock_signer_outpoint`). Meanwhile the
post-splice `hsmd_setup_channel` re-send (which lands the rotated key in VLS's
CURRENT setup) happens BEFORE the splice signature request — the ordering VLS's own
`Node::setup_channel` comment documents ("CLN sends the post-splice SetupChannel
BEFORE requesting the splice tx signature").

**The broken dance, step by step**:
1. splice negotiation rotates the remote key KA → KB (spec-legal)
2. splice commitments secured
3. CLN re-sends `hsmd_setup_channel(B, KB)` → VLS `setup.counterparty_points.funding_pubkey = KB`
4. CLN requests `sign_splice_tx(spends A, remote_funding_key = KA)` — its channel key is still KA
5. VLS: `KA != KB` → **`remote funding key mismatch` → the splice dies**

**Fix direction** (not silently applied): make the check era-aware — resolve the
funding view for the INPUT (the existing `setup_for_tx`/outpoint-matching logic),
and accept the remote key belonging to that era (it is the key in the redeemscript
being signed). The `funding_key_rotation` scenario's refusal assert flips
deliberately when this lands. Severity: rotation is rare in practice today (CLN
sends a fresh keypair per splice by default? — `inflight->remote_funding` comes from
`splice_ack`; whether CLN reuses the old key or rotates is a counterparty choice
either side may make per spec), but when a counterparty rotates, the channel cannot
splice through VLS.

---

## F2 — Era A's resolver output reads `None` post-swap while the justice snapshot holds the info (BY DESIGN, subtle)

**What the trace proved**: after the swap, the era-A view shows `holder_commitment: —`
while `prev_funding_commitment.has_holder_info = true` — side by side in the VLS brain.

**Why it's correct-but-subtle**: `EnforcementState::holder_commit_info_for` resolves
tag-first: the tag still says A (the swap snapshots the infos but does not move the
tag), so view-A lookups return the channel-level `current_holder_commit_info` — which
the swap just emptied into the snapshot. Every consumer handles this:
`claimable_balances` reads the snapshot directly for stragglers; the retry rails
(R30) treat "no era info" as first-arrival. The tracer displaying both fields
simultaneously is the intended exposure — anyone touching the resolvers now sees
the tag-vs-snapshot asymmetry immediately.

---

## F3 — `funding_locked` is not persisted (MINOR GAP, upstream-question candidate)

**What the trace proved** (`Restored` event detail + restore-path test assertion):
after a mid-window restart, `funding_locked` restores as `None` while
`prev_setup`/`prev_prev_setup`/justice snapshot all survive.

**Impact**: the lockout record is lost, but the window logic is intact (the era chain
survives; `confirm_funding_locked` is idempotent and re-arms on CLN's re-send). Worth
persisting for symmetry; not urgent. The restore-path test pins the current behavior.

---

## F4 — Pending HTLCs are not carried into the lock-time baseline (ACCEPTED TRADEOFF, risk visible)

**What the trace proved** (`scenario_pending_htlc_at_lock`): `funding_locked B` with an
HTLC still pending installs empty-HTLC baseline infos (`current_holder_commit_info`
becomes the num-0-equivalent split).

**Why**: the lock-path's own history (crash27/xpay decode + the mutual-close fix) —
old-funding-scale infos at lockin are worthless (the funding is spent), and NIL-ing
them broke mutual close, so the NEW funding's baseline went in. The enforcement view
is re-established by the next `commitment_signed` on B. Spec-wise HTLCs survive
splices via re-commitment ("payments must be valid for all splice transactions"),
and CLN owns HTLC tracking. **Residual risk**: between lock and the next commitment,
holder/counterparty enforcement infos understate in-flight HTLCs — a mutual close in
that window validates against the baseline only. Known, visible in every trace diff.

---

## Spec notes banked while auditing

- `splice_locked` foreign-txid handling is a CLN-side MUST ("warning + disconnect, or
  error + fail the channel") — VLS's `confirm_funding_locked` rejection
  (`funding_locked: X is not the current funding`) is signer-side defense in depth;
  scenario `stale_funding_locked` pins it.
- The spec's completion diagram IS the tracer's era model: one commitment set per
  live funding ("Nodes keep track of multiple commitment transactions (one for the
  current funding transaction and one for each splice transaction)").

---

## F5 — the dev-box rbf/commit_crash "load stalls" are ONE named mechanism: era-B value rejections in a retry loop (2026-09-01, first corpus forensics)

**What the trace proved** (first traced 12/12 ladder, dev box, run dirs
`test-artifacts/trace-corpus/20260901-192332/` in the playground):
the two chronic non-green splice tests share an identical, now-captured
signature —

- `test_splice_rbf` (rc=124, reaped at 420s): **14 consecutive**
  `validate_holder_commitment` rejections, every one
  `"commitment totals exceed the funding value"` (InvalidArgument),
  era **B**, commitment **num 1**, on `vls:l1`; onset at seq 131
  immediately after a HEALTHY validation (seq 128, accepted) — l1 was
  mid-flow, not wedged from the start.
- `test_commit_crash_splice` (rc=1, convergence TimeoutError): **12**
  rejections, same message, same shape.

The loop pattern in the tail — `validate(reject) → funding_view_resolved
×2 → validate(reject)` — is the proxy's terminal-error retry cycle
(the known decoded behavior: terminal error → empty reply →
TransportTransient → re-send) re-presenting the same commitment
indefinitely while channeld waits and the test times out. The trace
shows the signer never crashes and every funding-view resolution keeps
succeeding: the stall is one deterministic rejection × retry loop.

**Relation to known classes**: same message family as the
disconnect-tier era-mixing underflow (fixed at 2a588b44 via the
era-aware resolvers + claimable_balances per-era valuation) but on a
DIFFERENT path — the rbf A→B→C supersession window and the
commit-crash restart window, era-B commitments valued against a view
that rejects them. NOT the strict94 class-A "recomposed tx mismatch"
(different check). This is a live behavioral finding on
`inr2-splice-dev`, deliberately NOT fixed here: the observability
deliverable captures it; the behavioral correction stays separable
(the value-check arithmetic on the supersession/restart paths).

**Debug acceleration**: this decode took ONE command against the run
dirs. The same signature cost multi-day farm forensics in the
pre-tracer era (STATE.md 2026-08-31 IV/V). The corpus entry point:
`trace.jsonl` per run + `trace.llm.md`; filter
`validate_holder_commitment + rejected` (one checkbox in the viewer).

---

## F5 addendum (2026-09-01, later same evening) — the mechanism side is named; the unit rail lives with #106

The banked vlsd log (splice-farm-logs-317777, node 69110b18, retained by
the gate's 24h policy) pins the exact request sequence entering the rbf
retry loop — and proves the incoming commitment FITS its own view
(validate-diag req 81: `view=B view_value=894199 fee=3755 to_b=889319` —
893,074 total ≤ 894,199), so the rejection is a **state-valuation
underflow on the currents side**, not a bad transaction:

1. sign A num-1 (claimable-diag2: cur=None/None)
2. sign B num-1 (cur_cp_total=995_120 — A-scale)
3. validate A num-1 (to_b=995_120, ACCEPTED — stores A-scale holder
   currents)
4. validate B num-1 → "commitment totals exceed the funding value",
   forever (the proxy retry loop = the stall)

Leading hypothesis (unproven at unit level as of this addendum): the
A-scale holder currents (995,120) stored by step 3 get valued against
B's 894,199 view — i.e. the validate-tail's funding tag does not route
the way the sign-tail's does (the 2a588b44 fix covered the sign tail;
the validate tail on this path is the suspect).

**Coordination**: the #106 fix session independently reproduced the
commit_crash manifestation at unit level (rail `scenario_commit_crash_
b_validate_post_restart`, commit 853053f5, built directly on this
corpus's live decode — same numbers) and owns the behavioral fix; their
next step is a traced gate at `--log-level=debug` for the claimable-diag
side identification. An rbf-variant pin (no restart: splice-in window +
the interleaved A re-validation) was drafted and PARKED at
`/tmp/opencode/f5-rbf-pin.rs` (6-arg sign_cp_helper, ready to append)
when their mid-flight edits landed in the same file — it belongs with
their rail once the tree is at a clean boundary. F5's rbf and
commit_crash manifestations are ONE mechanism (this file, F5 body);
the fix should flip both.

---

## F5 RESOLVED (2026-09-02, vls 827401dd) — two mechanisms, both fixed, both stalls GREEN live

The corpus's F5 arc closed end-to-end: finding → mechanism → RED rails →
fix → live proof.

1. **The fresh-store tag** (channel.rs validate tail): fresh old-funding
   commitments stored A-scale info tagged with the CHANNEL's current
   funding → the next same-window validation underflowed at `cur_holder`.
   Fixed to the routed view (the sign tail's 2a588b44 pattern).
2. **The tag/currents interleave** (validator.rs `claimable_balances`):
   the resume dance's alternating-era signs leave A-scale info in a
   B-tagged slot (live probe `side=cur_cp ×15`); the currents side and
   the new-tx fallbacks now treat cross-scale underflow as "no usable
   before-state" per the R30 doctrine — never a rejection. Explicit new
   transactions still hard-error.

**Live proof**: `test_splice_rbf` rc=0 (32.8s, 37.2s — was rc=124 on
every prior run of this branch) and `test_commit_crash_splice` rc=0
(39.2s, zero rejections — was rc=1 with the 12× loop). Three RED→GREEN
rails in the default suite (the restructured commit_crash rail, the
cp-interleave rail, the rbf-window rail). Decode cost of the whole arc:
one evening, instrumented by the trace corpus + one labeled probe —
against the pre-tracer era where this signature cost multi-day farm
forensics.
