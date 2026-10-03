# Gate mode (M10): VLS approves before Electrum signs

## Design

`VLS_GATE=1` turns the mirror into a gate: the tapped
`Channel.sign_next_commitment` asks the bridge to sign the commitment
FIRST (`sign_counterparty_commitment_raw`, the proven M4 path). If VLS
refuses, the tap raises before `sign_original` runs — Electrum's
signature never happens. Decisions append to /tmp/vls-gate.jsonl.

`VLS_FAULT=<mode>` injects deterministic faults into the request for
testing: `stale_ctn` (ctn-10 replay), `tamper_tx` (one flipped byte at
75% tx depth).

## Demonstrated (2026-10-02, channel 1463x1x1)

- **Positive**: channel opened and five payments completed through the
  gate (ctn 0, 3-6, 10) — every commitment signature approved by VLS
  first, then cross-verified post-sign (the M4 check).
- **Structural rejection**: `tamper_tx` → VLS's `decode_commitment_tx`
  rejected the corrupted output script ("script pubkey doesn't match
  inner script") → GATE: CLOSED → the payment failed with the raise →
  the channel survived unharmed → a clean payment succeeded afterward.
- **Fail-closed (accidental)**: during bring-up, a request missing the
  HTLC witscript was refused ("missing witscript for p2wsh") — the gate
  closed on a malformed request exactly as a fail-closed design should.
  This surfaced a real witscript gap: `build_witscripts` had no HTLC
  candidates; fixed by deriving offered/received HTLC scripts from
  `hm.get_htlcs_in_next_ctx` with both party-orientation fan-outs.

## Phase-2 live verification (2026-10-02, later)

The migration is LIVE and verified in both directions:

- **Approval**: a payment flowed through `sign_counterparty_commitment_full`
  with `GATE: open ctn=19, htlc_signatures=1` followed by
  `ctn=20, htlc_signatures=0` — the first HTLC signature produced under
  full vls-core validation (claimable_balances, ctn/pcp checks, tx
  reconstruction). Payment succeeded end-to-end.
- **Value rejection**: vls-core's phase-2 rejected incorrect
  to_holder/to_counterparty values with "commitment totals exceed the
  funding value" — observed across ~200 closure records when the capture
  (pre-fix) sent fee-disregarding balance sums. This is the same
  validation the `tamper_value` fault targets; the closure evidence
  exists in the gate log with fault provenance as the capture bug
  rather than the injection.

Two capture bugs found by the live run (both fixed, `0abc4d81`):
TxOutpoint uses `out_idx` not `n`; values must come from the actual
commitment outputs (classified by witness script) because
`chan.balance()` disregards fees by design.

**Fault replays (2026-10-02, completed)** — clean provenance, fresh
channel, all recorded in /tmp/vls-gate.jsonl:

- `tamper_value` (+500k to to_holder): GATE: CLOSED — "commitment
  totals exceed the funding value" (`fault: tamper_value`), signature
  suppressed, payment blocked.
- `stale_ctn` (ctn−10): GATE: CLOSED — "commitment number replay: 0 <
  last signed 3" (`fault: stale_ctn`) — the bridge ctn guard firing
  through the phase-2 handler.
- Recovery: after both rejections, a clean payment succeeded with the
  gate open (ctn 4, htlc_signatures 1) — the channel was unharmed.

**Tolerance finding (completed with the one-shot replay)**: a +1000-sat
to_holder tamper passes BOTH validation layers — the totals check
(fee-headroom window) and the claimable_balances delta (tested via a
one-shot injection against a clean honest baseline: injected at ctn 8
over the ctn-7 baseline, gate OPENED). The tolerance is structural:
commitment fees vary between rounds, so value-shift validation must
tolerate fee-scale differences — a sub-fee tamper is indistinguishable
from fee variation. Practical detection floor ≈ the commitment fee
(~1-2k sat at regtest feerates; scale with real feerates). Tampering at
~0.5% of channel value and above is rejected immediately (500k sat:
instant closure, verified).

Fault tooling: `VLS_FAULT_ONCE=1` disarms after the first injection
(one-shot semantics for baseline-vs-tamper experiments);
`VLS_FAULT_TAMPER_SAT` sets the magnitude (default 500000).

## HTLC-signature gating: the precise gap

`htlc_sigs` currently pass through the gate unvalidated. They cannot
be signed at the raw layer cheaply: BOLT-2 HTLC signatures are over
the SECOND-STAGE HTLC transactions (SIGHASH_SINGLE|ACP for anchors
channels), and vls-core produces them only in
`sign_counterparty_commitment_tx_phase2`, which reconstructs the
commitment from its own channel state (channel.rs:~2690 —
build_htlc_transaction → p2wsh_signature_hash → sign with the derived
counterparty_htlc_key).

The clean migration: the gate's bridge call moves from
`sign_counterparty_commitment_raw` to `phase2` (the bridge already
uses phase2 for `sign_holder_commitment`). The tap then sends
(funding_outpoint, pcp, ctn, feerate, to_holder_sat,
to_counterparty_sat, offered/received HTLC lists as HTLCInfo2) and
receives (sig, htlc_sigs) under full vls-core validation — amounts,
HTLC data, and sequencing checked against mirrored state rather than
trusting the raw tx bytes. That is the next focused unit of work.

## Bridge-restart self-healing

The tap's bridge-channel registry is daemon-side memory; a bridge
restart without a daemon restart left it stale and the gate fail-closed
on "no such channel" (found live during the persistence test).
`gate_approve` now evicts the stale entry, re-registers, and retries
once. The ctn-guard state persists across bridge restarts via
`<socket>.ctn` (loaded at serve() start, written through per update).

The stale-ctn gap is now closed at the bridge layer: every
`sign_counterparty_commitment_raw` call checks the requested ctn
against the per-channel last-signed value and rejects strictly-older
numbers ("commitment number replay: N < last signed M"). Re-signing
the same ctn is allowed (BOLT-2 retransmission semantics). Verified
live: the `stale_ctn` fault now produces GATE: CLOSED with the replay
message, the payment is blocked, the channel survives, and clean
payments resume. This guard lives in the bridge RPC layer, so the M5
testing-sync cannot bypass it. The deeper vls-core enforcement
(phase-2 signing paths) remains the production-grade mechanism; the
bridge guard is the mirror-architecture equivalent.
