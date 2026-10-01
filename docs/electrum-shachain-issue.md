# Security Issue: Electrum RevocationStore returns wrong secrets for old commitments

## Summary

Electrum's `RevocationStore.retrieve_secret()` can silently return a **wrong
per-commitment secret** for old commitment positions. The witness script derived
from the wrong secret produces a different scriptpubkey than the actual on-chain
commitment output — meaning **the justice path (breach punishment) fails to
match and sweep the revoked outputs**.

## Impact

A malicious peer can broadcast an old (revoked) commitment transaction. The
Electrum wallet detects it as revoked (`is_revocation=True`) but the justice
sweep cannot find the to_local output because the derived address doesn't match.
The wallet silently fails to punish the breach.

## Evidence

Reproduced on regtest with a CLN ↔ Electrum channel:

1. Open channel, make payments, snapshot CLN state
2. Advance the channel (more payments, revocations exchanged)
3. Restore CLN to the snapshot (stale state)
4. CLN unilaterally closes with the stale commitment
5. Electrum's lnwatcher detects the breach → `is_revocation=True`
6. But `sweep_their_ctx_justice()` cannot find the to_local output

### Diagnostic output (from the instrumented tap)

```
tap: CTN ctn=7 oldest_unrevoked=21 → BREACH     # correctly classified as breach
tap: justice wrap CALLED                          # justice sweep function invoked
tap: SCRIPT-AGREE spk=002059169f...               # both derivation paths agree
tap: justice cross-check skipped (to_local not found)

# But the actual on-chain commitment has:
out[2] (to_local) = 00203d5234... val=2000016     # DIFFERENT scriptpubkey
```

### The shachain bucket state at the time

```
bucket[0] → ctn=20
bucket[1] → ctn=17
bucket[2] → ctn=19
bucket[3] → ctn=7     ← the target ctn IS stored
bucket[4] → ctn=15
```

Even though ctn 7's secret IS stored in bucket 3, the retrieval/derivation
produces a wrong value. The derivation chain from bucket 3's stored position
to the requested position apparently hashes through a different path than
what the counterparty used.

## Root cause hypothesis

`RevocationStore.retrieve_secret()` iterates buckets 0→48 and returns the
FIRST bucket where `shachain_derive()` succeeds (doesn't raise
`UnableToDeriveSecret`). The prefix check in `shachain_derive()` may pass
for a bucket whose derivation chain doesn't actually produce the correct
secret for the requested position — it checks only the prefix, not the
full derivation path.

Contrast with the VLS implementation (`CounterpartyCommitmentSecrets` in
`vls-core/src/policy/validator.rs`), which passes 6 correctness tests
verifying that `get_secret()` either returns the correct value or `None`,
never a wrong secret.

## Reproduction

```bash
# Requires: the vls-electrum-spike rig (see github.com/... /justice-replay.sh)
./scripts/justice-replay.sh 3 8  # 3 pre-snapshot payments (ctn ~7), 8 post
# Check daemon pane for: SCRIPT-AGREE + "to_local not found"
```

## Suggested fix

In `RevocationStore.retrieve_secret()`: after deriving a secret from a
bucket, verify it by checking that the derived per-commitment point matches
the commitment transaction's outputs. If not, continue to the next bucket
instead of returning the wrong value.

Alternatively: in `shachain_derive()`, tighten the prefix check to also
verify the lower bits agree with the bucket's trailing-zero count.

## Affected versions

Tested on master @ ede66c89 (2026-09-29). The `RevocationStore` is
"closely based on code in lightningnetwork/lnd" — LND may share this issue.
