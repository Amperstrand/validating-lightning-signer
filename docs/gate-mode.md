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

## Sequencing enforcement (added after the initial run)

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
