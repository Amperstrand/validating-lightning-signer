//! #96 corpus campaign: encode the three deterministic seed action
//! sequences (the `tests` mod in `channel_splice.rs`) into libfuzzer
//! corpus files for the `splice_channel` target, then round-trip-assert
//! every file before declaring success.
//!
//! Byte format — derived from the arbitrary 1.4.2 crate source (the
//! version pinned in fuzz/Cargo.lock):
//! - `Vec<SpliceAction>::arbitrary_take_rest` iterates via
//!   `arbitrary_take_rest_iter`: each element is preceded by one
//!   "keep going" byte (`bool::arbitrary` = `u8 & 1 == 1`); iteration
//!   stops on an even byte or data exhaustion (fill_buffer zero-pads).
//! - Enum variants are chosen from `<u32 as Arbitrary>` (4 bytes LE):
//!   `variant = (u64::from(x) * variant_count) >> 32` (derive_arbitrary
//!   `arbitrary_enum_method`, the Lemire multiply-shift).
//! - Scalars are little-endian via `fill_buffer`: u8 = 1 byte,
//!   i64 = 8 bytes, bool = 1 byte (`& 1`).
//! - `with_recursive_count` consumes nothing while data is non-empty.
//!
//! Run from the fuzz crate root: `cargo run --bin gen-splice-seeds`
//! (writes `corpus/splice_channel/seed_*`).
use arbitrary::{Arbitrary, Unstructured};
use vls_fuzz::channel_splice::SpliceAction;

/// A u32 whose Lemire mapping lands on `idx`:
/// `(x * n) >> 32 == idx` for x in [ceil(idx * 2^32 / n),
/// ceil((idx+1) * 2^32 / n) - 1]; take the midpoint for margin.
fn u32_for_variant(idx: u64, n_variants: u64) -> u32 {
    let lo = (idx * (1u64 << 32) + n_variants - 1) / n_variants;
    let hi = (((idx + 1) * (1u64 << 32)) / n_variants).saturating_sub(1);
    assert!(lo <= hi, "no u32 encoding for variant {idx}/{n_variants}");
    let mid = lo + (hi - lo) / 2;
    assert!(mid <= u32::MAX as u64, "midpoint overflows u32");
    mid as u32
}

/// Encode one action sequence in the exact byte shape
/// `Vec<SpliceAction>::arbitrary_take_rest` consumes.
fn encode(actions: &[SpliceAction]) -> Vec<u8> {
    const N: u64 = 6; // SpliceAction variant count (declaration order)
    let mut out = Vec::new();
    for action in actions {
        out.push(0x01); // keep-going byte (odd = continue)
        match action {
            SpliceAction::SetupChannelSplice {
                funding_outpoint_idx,
                value_delta,
            } => {
                enc_u32(&mut out, u32_for_variant(0, N));
                enc_u8(&mut out, *funding_outpoint_idx);
                enc_i64(&mut out, *value_delta);
            }
            SpliceAction::SignSpliceAttempt {
                outpoint_idx,
                garbage_input,
            } => {
                enc_u32(&mut out, u32_for_variant(1, N));
                enc_u8(&mut out, *outpoint_idx);
                enc_u8(&mut out, u8::from(*garbage_input));
            }
            SpliceAction::CheckOutpoint(idx) => {
                enc_u32(&mut out, u32_for_variant(2, N));
                enc_u8(&mut out, *idx);
            }
            SpliceAction::FundingLocked(idx) => {
                enc_u32(&mut out, u32_for_variant(3, N));
                enc_u8(&mut out, *idx);
            }
            SpliceAction::SameNumDifferentFunding => {
                enc_u32(&mut out, u32_for_variant(4, N));
            }
            SpliceAction::TxAbort(idx) => {
                enc_u32(&mut out, u32_for_variant(5, N));
                enc_u8(&mut out, *idx);
            }
        }
    }
    // No terminator needed: the next keep-byte read zero-pads
    // (0 & 1 == 0 -> stop).
    out
}

fn enc_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn enc_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn enc_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Assert the encoded bytes decode back to EXACTLY the seed sequence.
fn round_trip(seed: &[SpliceAction]) {
    let bytes = encode(seed);
    let decoded =
        <Vec<SpliceAction> as Arbitrary>::arbitrary_take_rest(Unstructured::new(&bytes))
            .expect("seed corpus must decode cleanly");
    assert_eq!(
        format!("{decoded:?}"),
        format!("{seed:?}"),
        "round-trip mismatch: encoded {:?}, decoded {:?}",
        seed,
        decoded
    );
}

fn seeds() -> Vec<(&'static str, Vec<SpliceAction>)> {
    // The three deterministic seeds, verbatim from the `tests` mod in
    // channel_splice.rs (supersession chain incl. sign-every-view +
    // lock; tx_abort-then-resplice; theft rail).
    vec![
        (
            "seed_supersession_chain",
            vec![
                SpliceAction::SetupChannelSplice { funding_outpoint_idx: 1, value_delta: 1_000 },
                SpliceAction::SignSpliceAttempt { outpoint_idx: 0, garbage_input: false },
                SpliceAction::SetupChannelSplice { funding_outpoint_idx: 2, value_delta: 2_000 },
                SpliceAction::SignSpliceAttempt { outpoint_idx: 0, garbage_input: false },
                SpliceAction::SignSpliceAttempt { outpoint_idx: 1, garbage_input: false },
                SpliceAction::SignSpliceAttempt { outpoint_idx: 2, garbage_input: false },
                SpliceAction::FundingLocked(2),
            ],
        ),
        (
            "seed_tx_abort_resplice",
            vec![
                SpliceAction::SetupChannelSplice { funding_outpoint_idx: 3, value_delta: 5_000 },
                SpliceAction::TxAbort(7),
                SpliceAction::FundingLocked(2),
            ],
        ),
        (
            "seed_theft_rail",
            vec![SpliceAction::SameNumDifferentFunding],
        ),
    ]
}

fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/splice_channel");
    std::fs::create_dir_all(&dir).expect("create corpus dir");
    for (name, actions) in seeds() {
        round_trip(&actions);
        let bytes = encode(&actions);
        let path = dir.join(name);
        std::fs::write(&path, &bytes).expect("write corpus file");
        println!("wrote {} ({} actions, {} bytes)", path.display(), actions.len(), bytes.len());
    }
    println!("corpus seeded: 3 files in {}", dir.display());
}
