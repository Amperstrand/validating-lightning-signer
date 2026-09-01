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
