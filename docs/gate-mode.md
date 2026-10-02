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

## Known limitation (honest boundary)

`stale_ctn` replay is NOT rejected: the raw-sign shim validates
transaction structure (decode, witscripts, script consistency) but not
commitment-number sequencing — the M5 `set_next_..._for_testing` sync
structurally bypasses sequencing enforcement. A production gate would
need the full protocol handshake in the bridge (the mirror becomes a
protocol peer) rather than the testing shims. Sequencing enforcement is
core VLS (present in `sign_counterparty_commitment_tx_phase2` paths)
but is deliberately side-stepped in this spike's raw-sign fast path.
