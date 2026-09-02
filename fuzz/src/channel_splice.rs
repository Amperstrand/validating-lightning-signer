use arbitrary::Arbitrary;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::bip32::DerivationPath;
use lightning_signer::bitcoin::hashes::Hash;
use lightning_signer::bitcoin::blockdata::locktime::absolute::LockTime;
use lightning_signer::bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn};
use lightning_signer::bitcoin::blockdata::witness::Witness;
use lightning_signer::bitcoin::transaction::{Sequence, Version};
use lightning_signer::channel::ChannelId;
use lightning_signer::node::Node;
use lightning_signer::util::test_utils::{
    init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
};
use secp256k1::ecdsa::Signature;
use std::sync::Arc;

use bitcoin::secp256k1;

// R12.2 splice-aware extension of the channel fuzz harness: the six
// splice Actions run against the SAME real Node + channel the channel.rs
// harness uses, with the six invariants asserted after EVERY step. The
// default (non-permissive) policy is deliberate: the theft rail
// (policy-commitment-retry-same) must be observable as an error return.
#[derive(Debug, Arbitrary)]
pub enum SpliceAction {
    SetupChannelSplice {
        funding_outpoint_idx: u8,
        value_delta: i64,
    },
    SignSpliceAttempt {
        outpoint_idx: u8,
        garbage_input: bool,
    },
    CheckOutpoint(u8),
    FundingLocked(u8),
    SameNumDifferentFunding,
    TxAbort(u8),
}

#[derive(Debug)]
pub struct SpliceChannelFuzz {
    node: Arc<Node>,
    channel_id: ChannelId,
    base_value: u64,
    // every funding outpoint this channel has ever had (index 0 = the
    // original); the view/sign actions index into it
    fundings: Vec<OutPoint>,
    // fundings swapped away without a lock in between — the snapshot's
    // only legal provenance (invariant 3)
    retired: Vec<OutPoint>,
    current_locked: bool,
    // the snapshot outpoint recorded at the last accepted swap, for the
    // survive-until-lock check (invariant 5)
    snapshot_facts: Option<OutPoint>,
    holder_num_watermark: u64,
    cp_num_watermark: u64,
    tracker_len_watermark: usize,
    dummy_sig: Signature,
}

impl SpliceChannelFuzz {
    pub fn new() -> Self {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let base_value = node
            .with_channel(&channel_id, |chan| Ok(chan.setup.channel_value_sat))
            .expect("base value");
        let original = node
            .with_channel(&channel_id, |chan| Ok(chan.setup.funding_outpoint))
            .expect("original outpoint");
        let tracker_len_watermark = node.get_tracker().listeners.len();
        Self {
            node,
            channel_id,
            base_value,
            fundings: vec![original],
            retired: vec![],
            current_locked: false,
            snapshot_facts: None,
            holder_num_watermark: 0,
            cp_num_watermark: 0,
            tracker_len_watermark,
            dummy_sig: Signature::from_compact(&[0; 64]).unwrap(),
        }
    }

    pub fn run(&mut self, data: Vec<SpliceAction>) {
        for (step, action) in data.into_iter().enumerate() {
            #[cfg(feature = "debug")]
            println!("{:?}", action);
            let __label = format!("{:?}", action);
            match action {
                SpliceAction::SetupChannelSplice {
                    funding_outpoint_idx,
                    value_delta,
                } => {
                    let value = (self.base_value as i128 + value_delta as i128)
                        .clamp(100_000, 20_000_000) as u64;
                    self.attempt_swap(funding_outpoint_idx % 250, value);
                }
                SpliceAction::TxAbort(seed) => {
                    // tx_abort is peer-wire; the signer never sees it. The
                    // signer-side observable is the NEXT splice setup
                    // superseding the unconfirmed candidate (R8.3) — model
                    // the abort as that immediate re-splice.
                    self.attempt_swap(seed % 250, self.base_value + 1_000);
                }
                SpliceAction::SignSpliceAttempt {
                    outpoint_idx,
                    garbage_input,
                } => {
                    let outpoint = if garbage_input {
                        OutPoint::null()
                    } else {
                        self.fundings[outpoint_idx as usize % self.fundings.len()]
                    };
                    let tx = splice_tx_spending(outpoint);
                    let remote_key = make_test_channel_setup()
                        .counterparty_points
                        .funding_pubkey;
                    // refusal Results are correct behavior (foreign
                    // outpoint, value mismatch); a panic here is the bug
                    let _ = self.node.with_channel(&self.channel_id, |chan| {
                        chan.sign_splice_tx(&tx, 0, &remote_key, None)
                    });
                }
                SpliceAction::CheckOutpoint(idx) => {
                    let outpoint = self.fundings[idx as usize % self.fundings.len()];
                    let tx = splice_tx_spending(outpoint);
                    let view = self
                        .node
                        .with_channel(&self.channel_id, |chan| chan.setup_for_tx(&tx))
                        .expect("setup_for_tx resolves");
                    assert!(
                        self.fundings.contains(&view.funding_outpoint),
                        "view resolution returned an unknown funding {:?}",
                        view.funding_outpoint
                    );
                }
                SpliceAction::FundingLocked(idx) => {
                    let outpoint = self.fundings[idx as usize % self.fundings.len()];
                    let current = self
                        .node
                        .with_channel(&self.channel_id, |chan| {
                            Ok(chan.setup.funding_outpoint)
                        })
                        .expect("current outpoint");
                    let result = self.node.with_channel(&self.channel_id, |chan| {
                        chan.confirm_funding_locked(&outpoint)
                    });
                    // an early-Ok re-lock of an already-locked stale
                    // outpoint is not a lock of the CURRENT funding
                    if result.is_ok() && outpoint == current {
                        self.current_locked = true;
                    }
                }
                SpliceAction::SameNumDifferentFunding => {
                    // the same-number machinery: a first validation at the
                    // expected num (the legal same-num store — the splice
                    // re-sign shape), then invariant 4's theft-rail probe
                    let (num, value) = self
                        .node
                        .with_channel(&self.channel_id, |chan| {
                            Ok((
                                chan.enforcement_state.next_holder_commit_num,
                                chan.setup.channel_value_sat,
                            ))
                        })
                        .expect("num and value");
                    let (to_holder, to_counterparty) = (value / 2, value / 2 - 10_000);
                    let first = self.node.with_channel(&self.channel_id, |chan| {
                        chan.validate_holder_commitment_tx_phase2(
                            chan.setup.funding_outpoint,
                            num,
                            2000,
                            to_holder,
                            to_counterparty,
                            vec![],
                            vec![],
                            &self.dummy_sig,
                            &[],
                        )
                    });
                    if first.is_ok() {
                        let retry_shifted = self.node.with_channel(&self.channel_id, |chan| {
                            chan.validate_holder_commitment_tx_phase2(
                                chan.setup.funding_outpoint,
                                num,
                                2000,
                                to_holder - 1_000,
                                to_counterparty + 1_000,
                                vec![],
                                vec![],
                                &self.dummy_sig,
                                &[],
                            )
                        });
                        assert!(
                            retry_shifted.is_err(),
                            "theft rail: same num + different info must be refused"
                        );
                    }
                }
            }
            self.check_invariants();
            // The trace checkpoint: fuzz and deterministic tests observe
            // the SAME snapshot model — a fuzzer-found panic carries its
            // full state history in JSONL (viewable like any scenario).
            #[cfg(feature = "splice_trace")]
            if lightning_signer::trace::enabled() {
                let label = __label.clone();
                let _ = self.node.with_channel(&self.channel_id, |chan| {
                    lightning_signer::trace::emit(
                        lightning_signer::trace::TraceEvent::vls(
                            lightning_signer::trace::EventPayload::SnapshotCheckpoint {
                                label,
                                step: step as u64,
                            },
                        )
                        .channel_hex(chan.id0.as_slice())
                        .after(Some(lightning_signer::trace::snapshot_channel(chan))),
                    );
                    Ok(())
                });
            }
        }
    }

    fn attempt_swap(&mut self, vout: u8, value: u64) {
        let mut setup = make_test_channel_setup();
        // Every splice era carries a UNIQUE funding outpoint (a real
        // splice funds a NEW tx). The factory's fixed txid made
        // same-vout eras collide, and crash-ea2b01b6 rode exactly that:
        // an old era's idempotent funding_locked Ok matched the new
        // era's colliding outpoint -> the harness inferred current-locked
        // while the splice snapshot was open -> false invariant-5 panic
        // on a state the protocol cannot reach.
        let mut txid_bytes = [2u8; 32];
        txid_bytes[..8].copy_from_slice(&(self.fundings.len() as u64).to_be_bytes());
        setup.funding_outpoint.txid =
            bitcoin::hash_types::Txid::from_slice(&txid_bytes).expect("era txid");
        setup.funding_outpoint.vout = vout as u32;
        setup.channel_value_sat = value;
        let prev_current = self
            .node
            .with_channel(&self.channel_id, |chan| Ok(chan.setup.funding_outpoint))
            .expect("prev current");
        match self.node.setup_channel(
            self.channel_id.clone(),
            None,
            setup,
            &DerivationPath::master(),
        ) {
            Ok(chan) => {
                let new_outpoint = chan.setup.funding_outpoint;
                if new_outpoint != prev_current {
                    if !self.fundings.contains(&new_outpoint) {
                        self.fundings.push(new_outpoint);
                    }
                    if !self.retired.contains(&prev_current) {
                        self.retired.push(prev_current);
                    }
                    self.current_locked = false;
                    self.snapshot_facts = self
                        .node
                        .with_channel(&self.channel_id, |chan| {
                            Ok(chan
                                .enforcement_state
                                .prev_funding_commitment
                                .as_ref()
                                .map(|s| s.outpoint))
                        })
                        .expect("snapshot facts");
                }
                // identical setup replay: idempotent, no bookkeeping change
            }
            // incompatible setup (same outpoint, different value) — refused
            Err(_) => {}
        }
    }

    // R12.2's six invariants, after every action. (1) no panic is the
    // fuzz run itself; (4) is probed inside SameNumDifferentFunding (a
    // probe mutates state, so it cannot run after every step).
    fn check_invariants(&mut self) {
        let (holder_num, cp_num, snapshot_outpoint) = self
            .node
            .with_channel(&self.channel_id, |chan| {
                let es = &chan.enforcement_state;
                Ok((
                    es.next_holder_commit_num,
                    es.next_counterparty_commit_num,
                    es.prev_funding_commitment.as_ref().map(|s| s.outpoint),
                ))
            })
            .expect("invariant reads");
        assert!(
            holder_num >= self.holder_num_watermark,
            "invariant 2: holder numbering regressed {} < {}",
            holder_num,
            self.holder_num_watermark
        );
        assert!(
            cp_num >= self.cp_num_watermark,
            "invariant 2: counterparty numbering regressed {} < {}",
            cp_num,
            self.cp_num_watermark
        );
        self.holder_num_watermark = holder_num;
        self.cp_num_watermark = cp_num;
        if let Some(outpoint) = snapshot_outpoint {
            assert!(
                self.retired.contains(&outpoint),
                "invariant 3: funding-keyed slot holds an outpoint that was never retired: {:?}",
                outpoint
            );
        }
        if self.current_locked {
            assert!(
                snapshot_outpoint.is_none(),
                "invariant 5: funding_locked must retire the snapshot"
            );
        } else if let Some(facts) = self.snapshot_facts {
            assert_eq!(
                snapshot_outpoint,
                Some(facts),
                "invariant 5: the old funding's slots must survive until funding_locked"
            );
        }
        let tracker_len = self.node.get_tracker().listeners.len();
        assert!(
            tracker_len >= self.tracker_len_watermark,
            "invariant 6: monitor watches dropped {} < {}",
            tracker_len,
            self.tracker_len_watermark
        );
        self.tracker_len_watermark = tracker_len;
    }
}

fn splice_tx_spending(outpoint: OutPoint) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![],
    }
}

// these need `RUSTFLAGS=--cfg=fuzzing cargo test` to work
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_supersession_chain() {
        // splice, sign the original view, supersede with a second splice
        // (the tx_abort shape), sign every view, lock the newest
        let mut fuzz = SpliceChannelFuzz::new();
        fuzz.run(vec![
            SpliceAction::SetupChannelSplice { funding_outpoint_idx: 1, value_delta: 1_000 },
            SpliceAction::SignSpliceAttempt { outpoint_idx: 0, garbage_input: false },
            SpliceAction::SetupChannelSplice { funding_outpoint_idx: 2, value_delta: 2_000 },
            SpliceAction::SignSpliceAttempt { outpoint_idx: 0, garbage_input: false },
            SpliceAction::SignSpliceAttempt { outpoint_idx: 1, garbage_input: false },
            SpliceAction::SignSpliceAttempt { outpoint_idx: 2, garbage_input: false },
            SpliceAction::FundingLocked(2),
        ]);
        assert_eq!(fuzz.fundings.len(), 3);
        assert!(fuzz.current_locked);
    }

    #[test]
    fn seed_tx_abort_resplice() {
        let mut fuzz = SpliceChannelFuzz::new();
        fuzz.run(vec![
            SpliceAction::SetupChannelSplice { funding_outpoint_idx: 3, value_delta: 5_000 },
            SpliceAction::TxAbort(7),
            SpliceAction::FundingLocked(2),
        ]);
        assert!(fuzz.current_locked, "the re-splice (vout 7) locked");
    }

    #[test]
    fn seed_theft_rail() {
        let mut fuzz = SpliceChannelFuzz::new();
        fuzz.run(vec![SpliceAction::SameNumDifferentFunding]);
    }
}
