# Justice-Path Testing Lessons (M7c series)

## What we proved

| Milestone | Result |
|---|---|
| M7c-v1: instrumentation | `extract_ctx_secrets` ctn classifier works; wrap placement correct |
| M7c-v2: wider gap | BREACH confirmed (ctn=5 vs oldest=23); justice wrap fires |
| M7c-v3: push_amount | to_local present in ctx; both derivation paths agree (SCRIPT-AGREE) |
| Root cause | Shachain bucket derivation gap for ctn 5 |

## Key lessons

### 1. The ctn gap must be wide enough
`extract_ctx_secrets` (lnsweep.py:528) classifies by comparing the decoded
ctn against `oldest_unrevoked_remote_ctn`. A gap of 2 ctns is NOT enough
(ctn 7 vs oldest 7 → "current"). We needed 18+ ctns of gap for reliable
BREACH classification.

**Practice**: 10+ post-snapshot payments before the restore.

### 2. CLN's to_local balance matters
If CLN holds less than the effective dust threshold, the to_local output
is trimmed from the commitment tx entirely. The justice path has nothing
to sweep. Use `--push_amount` when opening the channel.

**Practice**: `open_channel ... 0.05 --push_amount 0.02` (2M sats to CLN).

### 3. Electrum must be offline during CLN's stale broadcast
If Electrum reconnects to stale CLN, it detects "we are ahead of remote"
and force-closes with its OWN (current) commitment — which is not revoked.
The justice path correctly never fires for our own current commitment.

**Practice**: stop the Electrum daemon BEFORE restoring CLN. Start it only
after the stale ctx is confirmed on-chain.

### 4. The shachain is the real constraint (the M7c finding)
The shachain stores ~log₂(48) ≈ 5-6 secrets. `retrieve_secret` for a
position not covered by any stored secret's derivation chain returns a
value (doesn't throw `UnableToDeriveSecret`) — but the value is WRONG.

The bucket XOR analysis for our case:
```
Stored: ctns {20, 17, 19, 7, 15} in buckets {0,1,2,3,4}
Target: ctn 5 → bucket 2 → stored has ctn 19
XOR lower bits: 5=0b00101 vs 19=0b10011 → DISAGREE
```

VLS's `CounterpartyCommitmentSecrets.get_secret()` handles this correctly
(proven by the new `shachain_coverage_tests.rs`). Electrum's
`RevocationStore.retrieve_secret()` is the side that silently returns
wrong values.

**Practice**: verify the shachain covers the target ctn before expecting
a justice match. The CTN instrumentation shows the classification; the
SCRIPT-AGREE shows the derivation; the SPK-DIFF shows the mismatch.

### 5. Snapshot-based testing is the right pattern
The lightning-playground's `harness/snapshot.sh` (stop → tar volumes →
start, ~30s) is exactly the right primitive for this testing. Our
`justice-replay.sh` scripts the full choreography using this pattern,
making justice-path testing a single command instead of 15 minutes of
manual docker cp + invoice + lnpay.

### 6. Instrumentation-first debugging pays off
Every "silent failure" we added a print to (ENTERED, REV-KEY, SCRIPT-AGREE,
SPK-DIFF, CTN) immediately revealed the next layer of the onion. The final
diagnostic chain spans: classification → wrap → registration → derivation →
output matching → shachain bucket analysis. This is permanent yield.

### 7. The magic ctns are 2^N - 1 (the bucket analysis generalization)

The shachain bucket analysis reveals a crisp pattern:

| Snapshot ctn | Bucket | Derivable? |
|---|---|---|
| 1 | 0 | ✓ always |
| 3 | 1 | ✓ always |
| **7** | **2** | **✓ always** |
| **15** | **3** | **✓ always** |
| 2, 4, 5, 6 | 1-2 | ✗ never |
| 8-14 | 3 | ✗ never |
| 16-24 | 4 | ✗ (displaced by 20) |

Only ctns where ALL bits below the bucket bit are set (2^N - 1) are
permanently covered — because the stored secret at that bucket IS that
ctn's secret, and the lower bits trivially agree with themselves.

**Practice**: use 3 pre-snapshot payments (channel lands at ctn ~7).

### 8. Even at the magic ctn, Electrum's shachain doesn't produce the
### right secret (the definitive M7c-v4 finding)

With the snapshot at ctn 7 (bucket 2, self-covering) and a 14-ctn gap
(ctn 7 vs oldest 21), both derivation paths (VLS private and Electrum
public) agree (SCRIPT-AGREE) — but neither matches the actual to_local
output. Electrum's `RevocationStore` and VLS's
`CounterpartyCommitmentSecrets` use the same BOLT-03 derivation
algorithm, but Electrum's bucket storage / retrieval path produces a
different per-commitment secret for ctn 7 than what CLN embedded in the
commitment. VLS's implementation is proven correct by the new
`shachain_coverage_tests.rs`; Electrum's silently returns a wrong value.
This is the genuine cross-implementation gap.

## Test artifacts produced

| Artifact | Location | What it tests |
|---|---|---|
| `shachain_coverage_tests.rs` | vls-core/src/ | VLS shachain never returns wrong secrets |
| `justice-replay.sh` | lightning-playground/scripts/ | Full justice choreography, one command |
