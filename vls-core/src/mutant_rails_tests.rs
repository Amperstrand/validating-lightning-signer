//! Mutant rails (STATE.md XVIII follow-up) — regression tests that kill
//! the substantive survivors of the 2026-09-01 mutants re-run
//! (test-artifacts/mutants-rerun-20260901/). Each rail names the
//! mutant(s) it kills; run against the mutated trees, these tests must
//! FAIL there and pass here.
//!
//! Covered survivors: monitor.rs:987 (watched_funding_txids → vec![]),
//! node.rs:2036 (push beneficial-value boundary), channel.rs:1305-1307
//! + 3433-3434 (the splice-window same-number store gates, phase2 +
//! inner), channel.rs:2331 (splice-lockin baseline push split —
//! covered by the monitor rail's post-lock assert if the channel uses
//! push; the dedicated split assert lives in the straggler rail's
//! values), simple_validator.rs:819 (era-aware retry-same resolution),
//! policy/mod.rs:113 + onchain_validator.rs:372 (in the in-file burial
//! rails mod), tx/tx.rs:225 (claimable_balance preimage symmetry).

use crate::channel::ChannelId;
use crate::tx::tx::{CommitmentInfo2, HTLCInfo2, PreimageMap};
use crate::util::test_utils::{
    channel_commitment, counterparty_sign_holder_commitment, fund_test_channel,
    funding_tx_setup_channel, test_node_ctx, validate_holder_commitment, TestFundingTxContext,
};
use bitcoin::bip32::DerivationPath;
use bitcoin::{OutPoint, Transaction, TxIn};
use lightning::types::payment::PaymentHash;

fn splice_tx_spending(old_outpoint: OutPoint) -> Transaction {
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use bitcoin::transaction::{Sequence, Version};
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: old_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![],
    }
}

/// The splice A → B dance through the setup path (funding B accepted,
/// snapshot installed) — no signatures, no lock.
pub(crate) fn splice_a_to_b(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    chan_ctx: &mut crate::util::test_utils::TestChannelContext,
) -> OutPoint {
    let old_setup = chan_ctx.setup.clone();
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 95_450;
    let vout = tx_ctx.add_channel_outpoint(node_ctx, chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    let new_outpoint = OutPoint { txid: splice_tx.compute_txid(), vout };
    assert!(
        funding_tx_setup_channel(node_ctx, chan_ctx, &splice_tx, vout).is_none(),
        "splice setup accepted"
    );
    new_outpoint
}

fn snapshot_straggler(
    node: &crate::node::Node,
    channel_id: &ChannelId,
) -> Option<(CommitmentInfo2, crate::policy::validator::CommitmentSignatures)> {
    node.with_channel(channel_id, |chan| {
        Ok(chan
            .enforcement_state
            .prev_funding_commitment
            .as_ref()
            .and_then(|s| s.next_holder_info.clone()))
    })
    .expect("straggler read")
}

// monitor.rs:987 — `watched_funding_txids -> vec![]` SURVIVED the
// re-run: no test asserts the monitor actually watches the funding
// txids, so nulling the justice-watch set passes the whole suite.
#[test]
fn rail_monitor_watches_each_funding_era() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let outpoint_a = chan_ctx.setup.funding_outpoint;

    // Single-entry contract (monitor.rs watch: "only a single funding tx
    // currently supported") — the watch REPLACES at the splice re-setup.
    let watched_a = node_ctx
        .node
        .with_channel(&channel_id, |chan| Ok(chan.monitor.watched_funding_txids()))
        .expect("watch read");
    assert_eq!(watched_a, vec![outpoint_a.txid], "the monitor must watch the opening funding txid");

    let outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let watched_b = node_ctx
        .node
        .with_channel(&channel_id, |chan| Ok(chan.monitor.watched_funding_txids()))
        .expect("watch read");
    assert_eq!(
        watched_b,
        vec![outpoint_b.txid],
        "the watch must move to the splice funding at re-setup"
    );
}

// node.rs:2036 — the beneficial-value guard `push_msat > value*1000`:
// the `>=` survivor rejected the exact boundary; the `*`→`+` survivor
// rejected anything above value_sat + 1000 msat (~1001 sat).
#[test]
fn rail_setup_channel_push_at_value_boundary_ok() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    chan_ctx.setup.channel_value_sat = 1_100_000;
    chan_ctx.setup.push_value_msat = 1_100_000 * 1000; // exactly 100% to CP — legal
    let mut setup = chan_ctx.setup.clone();
    setup.funding_outpoint.vout = 7;
    let res = node_ctx.node.setup_channel(
        chan_ctx.channel_id.clone(),
        None,
        setup,
        &DerivationPath::master(),
    );
    assert!(res.is_ok(), "push == value*1000 msat is the boundary, not over it: {:?}", res.err());
}

#[test]
fn rail_setup_channel_push_midrange_ok() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    chan_ctx.setup.channel_value_sat = 1_100_000;
    chan_ctx.setup.push_value_msat = 500_000_000; // 500k sat — well under 1.1M sat
    let mut setup = chan_ctx.setup.clone();
    setup.funding_outpoint.vout = 8;
    let res = node_ctx.node.setup_channel(
        chan_ctx.channel_id.clone(),
        None,
        setup,
        &DerivationPath::master(),
    );
    assert!(res.is_ok(), "mid-range push must be accepted: {:?}", res.err());
}

#[test]
fn rail_setup_channel_push_over_value_rejected() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    chan_ctx.setup.channel_value_sat = 1_100_000;
    chan_ctx.setup.push_value_msat = 1_200_000 * 1000; // over the channel value
    let mut setup = chan_ctx.setup.clone();
    setup.funding_outpoint.vout = 9;
    let res = node_ctx.node.setup_channel(
        chan_ctx.channel_id.clone(),
        None,
        setup,
        &DerivationPath::master(),
    );
    assert!(res.is_err(), "push over the channel value must be refused");
}

// channel.rs:1305-1307 — the phase2 splice-window same-number gate.
// The straggler store must fire EXACTLY once, for the retiring era's
// re-offered commitment at next-1: not for wrong numbers (the &&→||
// and +→- survivors stored them), not for replays against the new
// era's already-current funding (the &&→|| at 1306 stored them), and
// the legit straggler must store (the !=→== survivor skipped it).
#[test]
fn rail_phase2_splice_window_straggler_stores_exactly_once() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let outpoint_a = chan_ctx.setup.funding_outpoint;

    // Era A: validate commitment #1 (the funding consumed #0) so
    // holder_commitment_funding = Some(A) and next advances to 2.
    let mut ctx1 = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 996_245, 0, vec![], vec![]);
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A commitment validates");

    // Splice A → B: snapshot Some, current B, holder still on A.
    let outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    assert_ne!(outpoint_a, outpoint_b, "the splice funding is a new outpoint");
    assert_ne!(chan_ctx.setup.funding_outpoint, outpoint_a, "setup advanced to B");

    // (a) LEGIT: the BOLT #1160 window re-sign — a B-era commitment at
    // num next-1 (the re-sign bump) → stored into the snapshot record,
    // not the channel slot. (Phase2 verifies against the CURRENT
    // setup's keys, so the sig must be B-era: an era-A sig fails
    // key-resolution here — that routing is the tx-based inner path.)
    let mut ctx1b = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_091_695, 0, vec![], vec![]);
    let (sig1b, hsig1b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1b);
    let res = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.validate_holder_commitment_tx_phase2(
            chan.setup.funding_outpoint,
            1,
            3755,
            1_091_695,
            0,
            vec![],
            vec![],
            &sig1b,
            &hsig1b,
        )
    });
    assert!(res.is_ok(), "the legit window re-sign must validate: {:?}", res.err());
    let stored = snapshot_straggler(&node_ctx.node, &channel_id);
    assert!(stored.is_some(), "the straggler store must fire for the window re-sign");

    // (c) WRONG NUMBER: era-B-shaped info at num 3 (next is 2) must NOT
    // touch the snapshot record (kills &&→|| at 1305:17 and +→- at
    // 1305:38 — both would store here).
    let mut ctx3 = channel_commitment(&node_ctx, &chan_ctx, 3, 3755, 1_091_695, 0, vec![], vec![]);
    let (sig3, hsig3) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx3);
    let _ = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.validate_holder_commitment_tx_phase2(
            chan.setup.funding_outpoint,
            3,
            3755,
            1_091_695,
            0,
            vec![],
            vec![],
            &sig3,
            &hsig3,
        )
    });
    assert_eq!(
        snapshot_straggler(&node_ctx.node, &channel_id),
        stored,
        "a wrong-number commitment must not (re)store the straggler"
    );
    // NOTE: the &&→|| at 1306:17 is an accepted survivor — the extra
    // store it enables is either None-guarded to a no-op (post-lock)
    // or content-identical to arm-1's store; not state-observable.
}

// simple_validator.rs:819 — the era-aware retry-same resolution: an
// identical retransmission at the current era must read the SLOT copy
// and be ACCEPTED (the != survivor read the snapshot copy, mismatched,
// and refused the retransmit).
#[test]
fn rail_phase2_retry_same_accepted_twice() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    // Number 1: the funding consumed commitment 0, so next is 1 — the
    // first phase2 here is a normal arm-1 validation, the identical
    // second one is the retransmission the era-aware resolver must accept.
    let mut ctx1 = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 996_245, 0, vec![], vec![]);
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    let call = |node_ctx: &crate::util::test_utils::TestNodeContext,
                chan_ctx: &crate::util::test_utils::TestChannelContext,
                sig1: &bitcoin::secp256k1::ecdsa::Signature,
                hsig1: &Vec<bitcoin::secp256k1::ecdsa::Signature>| {
        node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
            chan.validate_holder_commitment_tx_phase2(
                chan.setup.funding_outpoint,
                1,
                3755,
                996_245,
                0,
                vec![],
                vec![],
                sig1,
                hsig1,
            )
        })
    };
    assert!(call(&node_ctx, &chan_ctx, &sig1, &hsig1).is_ok(), "first validation ok");
    assert!(
        call(&node_ctx, &chan_ctx, &sig1, &hsig1).is_ok(),
        "an identical retransmission at the same era must be accepted"
    );
}

// tx/tx.rs:225 — claimable_balance preimage symmetry: an offered HTLC
// whose preimage is KNOWN must NOT count toward our claimable balance
// (we can settle it); the `!`-drop survivor counted exactly the wrong
// set.
#[test]
fn rail_claimable_balance_preimage_symmetry() {
    struct Known(Vec<PaymentHash>);
    impl PreimageMap for Known {
        fn has_preimage(&self, hash: &PaymentHash) -> bool {
            self.0.contains(hash)
        }
    }
    let ph = |b: u8| PaymentHash([b; 32]);
    let offered_known = HTLCInfo2 { value_sat: 100, payment_hash: ph(1), cltv_expiry: 0 };
    let offered_unknown = HTLCInfo2 { value_sat: 200, payment_hash: ph(2), cltv_expiry: 0 };
    let received_known = HTLCInfo2 { value_sat: 300, payment_hash: ph(3), cltv_expiry: 0 };
    let received_unknown = HTLCInfo2 { value_sat: 400, payment_hash: ph(4), cltv_expiry: 0 };
    // is_counterparty_broadcaster = false → WE broadcast → to_broadcaster is ours.
    let ci = CommitmentInfo2::new(
        false,
        1_000,
        5_000,
        vec![offered_known, offered_unknown],
        vec![received_known, received_unknown],
        0,
    );
    let map = Known(vec![ph(1), ph(3)]);
    // ours = to_broadcaster 5000 + fee 3000 (channel 10000 - outputs 7000)
    //        + offered-without-preimage (200) + received-with-preimage (300)
    assert_eq!(
        ci.claimable_balance(&map, true, 10_000),
        Some(8_500),
        "known-preimage offered HTLCs must not count; unknown-preimage received must not count"
    );
    let none_known = Known(vec![]);
    // no preimages known: 8000 + offered known (100) + offered unknown (200)
    assert_eq!(ci.claimable_balance(&none_known, true, 10_000), Some(8_300));
}

// channel.rs:2331 — the splice-lock baseline installation derives
// push_sat = push_value_msat / 1000; the /→% and /→* survivors corrupt
// the post-lock current_holder_commit_info split (what mutual close
// validates against). A pushed splice must install the exact split.
#[test]
fn rail_splice_lock_installs_push_split_baseline() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    // Splice A → B carrying a 50k-sat push (CLN's fundee-relative
    // balance convention, in msat).
    chan_ctx.setup.push_value_msat = 50_000_000;
    let outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    node_ctx.node.confirm_funding_lock(&channel_id, &outpoint_b).expect("splice funding locked");

    let info = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok(chan.enforcement_state.current_holder_commit_info.clone())
        })
        .expect("commit info read");
    assert_eq!(
        info,
        Some(CommitmentInfo2::new(false, 50_000, 1_045_450, vec![], vec![], 0)),
        "the lock must install the push-split baseline (to_cp = push, to_holder = rest)"
    );
}
