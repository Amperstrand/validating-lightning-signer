# Derivation-Checkpoint Protocol (DCP)

## Purpose

Formalize the "split-brain auditor" architecture: two implementations
(Electrum and VLS) independently derive the same values from the same
inputs; an auditor compares them at every checkpoint and flags divergence.

## What gets compared

The bridge's `derive_and_report` RPC emits VLS's **inputs** — public channel
data (basepoints, contest delays, channel value) plus the per-commitment
point when a revocation secret is supplied. Electrum's side is derived in
the auditor via `lnutil`. Both sides' values are pure functions of the
channel state and MUST be identical across implementations:

```json
{
  "checkpoint": "commitment_round",
  "verdict": "match | diverge | cannot_determine",
  "electrum": {
    "funding_pubkey": "03...",
    "revocation_basepoint": "03...",
    "htlc_basepoint": "02...",
    "delayed_basepoint": "02...",
    "payment_basepoint": "03...",
    "to_self_delay": 144
  },
  "vls": {
    "funding_pubkey": "03...",
    "revocation_basepoint": "03...",
    "htlc_basepoint": "02...",
    "delayed_basepoint": "02...",
    "payment_basepoint": "03...",
    "holder_selected_contest_delay": 144
  },
  "context": {}
}
```

## Checkpoint types

| Checkpoint | When it fires | What's compared |
|---|---|---|
| `channel_open` | After funding locked | All basepoints, funding script |
| `commitment_round` | After each commitment_signed + revoke_and_ack | Per-commitment point, to_local/to_remote scripts |
| `revocation` | After each received revoke_and_ack | Per-commitment secret, derived pcp |
| `justice` | When a stale ctx is detected | Revocation key, witness script, justice spk |
| `sweep` | When a sweep is attempted | Sweep script, sighash |

## Why this is deterministic

The derivations are pure functions of the inputs:
- Key derivation: BIP-32/BOLT-03 math
- Per-commitment point: EC scalar multiplication
- Witness script: deterministic script construction
- Sighash: deterministic BIP-143 computation

The ONLY non-deterministic part is signature generation (nonce derivation
differs between implementations). For signatures, we use **verification**
instead of comparison: verify A's signature against B's sighash and vice versa.

## How VLS serves as auditor

VLS already:
1. Independently tracks channel state (it's a validating signer)
2. Derives all keys from the same seeds (proven by M1 KAT)
3. Validates signing requests against its own state (M5, live)
4. Validates revocations (M7a, shachain chain)
5. Passes correctness tests for edge cases (shachain_coverage_tests.rs)

What we add:
- A `derive_and_report` RPC on the bridge that emits the full
  DerivationRecord for the current channel state
- A comparison engine in the tap that calls both implementations and
  compares the outputs
- A verdict log that persists to a JSON audit trail

## Reproducibility

The audit trail is a JSON file: `audit-trail.json`. Each line is a
DerivationRecord. The sequence is deterministic given the same:
- Wallet seed
- Channel seed
- Message sequence (which we control via the replay driver)
- Block sequence (which we control via regtest)

Re-running with the same seeds produces the same audit trail.
Divergences are reproducible by construction.
