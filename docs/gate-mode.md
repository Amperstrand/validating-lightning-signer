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
