//! EC-7 rails (playground #268, teardown-wedge decode
//! /root/splice-ec7-evidence-2026-09-30/DECODE-EC7.md): the force-close
//! signing path must NEVER panic on a splice-era state that has no
//! validated holder commitment.
//!
//! Live bug (strict run 2026-09-28, test_splice_abort_after_sigs_sent):
//! at the post-abort unilateral close, channeld requests the holder close
//! signature for commitment 0 of the (never-completed) splice era. The
//! close selector lands on `closing with current holder commitment 0`,
//! the sync check passes (`0 + 1 == next_holder_commit_num`), and
//! `get_current_holder_commitment_info` hits
//! `estate.current_holder_commit_info.as_ref().unwrap()` — the comment
//! says "this is safe because we must have validated a holder
//! commitment", which is FALSE after an aborted splice. The panic KILLS
//! vlsd; the proxies hold the SignCommitmentTx in transport retry and
//! the whole node teardown wedges until the gate reap (19 min, evidence
//! pernode-18fb3029d84f / pernode-cea1e630825c + proxy-wedge-window.log).
//!
//! Rails (campaign doctrine — crash fixes get the never-crash rail plus
//! the unaffected-neighbor control):
//! - rail_abort_close_after_splice_refuses_loudly: the abort-shaped
//!   close must return a TYPED error (never panic) — RED pre-fix (panics
//!   at validator.rs get_current_holder_commitment_info).
//! - rail_plain_close_after_holder_validation_still_signs: a channel
//!   WITH a validated holder commitment still closes (signs) — the
//!   refusal is state-specific, not a blanket close ban.

use crate::channel::{Channel, ChannelBase};
use crate::mutant_rails_tests::splice_a_to_b;
use crate::util::test_utils::{
    channel_commitment, counterparty_sign_holder_commitment, fund_test_channel, test_node_ctx,
    validate_holder_commitment,
};

/// The abort-shaped close: splice into era B, never validate an era-B
/// holder commitment (the splice aborted), then force-close. The signer
/// MUST answer with a typed error instead of crashing the process —
/// with the PR-A proxy plumbing a typed refusal fails the request
/// loudly and the node teardown proceeds.
#[test]
fn rail_abort_close_after_splice_refuses_loudly() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    // A validated era-A holder commitment (num 1, full-value to us),
    // mirroring the sibling rails' era-A establishment.
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    // The splice into era B — setup swaps, era-B holder commitments are
    // never validated (the aborted-splice state).
    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    // Where does the close selector land? Mirror the real close entry:
    // sign_holder_commitment_tx_phase2 with the CURRENT view's number.
    let close_num = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok(if chan.enforcement_state.next_holder_commit_info.is_some() {
                chan.enforcement_state.next_holder_commit_num
            } else {
                chan.enforcement_state.next_holder_commit_num.saturating_sub(1)
            })
        })
        .expect("close number");

    let res = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.sign_holder_commitment_tx_phase2(close_num)
    });

    // Pre-fix this PANICS (unwrap on None) — the test cannot even reach
    // this assert. Post-fix: a typed error, never a crash.
    assert!(
        res.is_err(),
        "abort-shaped close must be refused (typed), got Ok"
    );
    let err = res.unwrap_err();
    let text = format!("{:?}", err);
    assert!(
        !text.trim().is_empty() && text.len() > 2,
        "refusal must carry a diagnosable message: {:?}",
        err
    );
}

/// Control: the same close entry on a channel whose holder commitment
/// IS validated (no splice, plain era) still signs. Guards against the
/// fix becoming a blanket close refusal.
#[test]
fn rail_plain_close_after_holder_validation_still_signs() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let close_num = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok(chan.enforcement_state.next_holder_commit_num.saturating_sub(1))
        })
        .expect("close number");

    let res = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.sign_holder_commitment_tx_phase2(close_num));
    assert!(res.is_ok(), "plain close must still sign: {:?}", res.err());
}

/// R1 (EC-7 part 2): the era-B initial holder commitment — validated at
/// num = next-1 on the CURRENT funding (the numbering-carry shape CLN's
/// splice flow produces) — must be STORED, and the unilateral close at
/// that number must SIGN from it. Pre-fix: validated, replied Ok, stored
/// NOWHERE (the retransmit no-op branch); close refused.
#[test]
fn rail_splice_initial_holder_commitment_stored_and_closable() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    // Era A: one validated holder commitment (num 1).
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    // The splice swap: numbering carries, current holder info cleared.
    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    let (next_num, current_some) = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok((
                chan.enforcement_state.next_holder_commit_num,
                chan.enforcement_state.current_holder_commit_info.is_some(),
            ))
        })
        .expect("state read");
    assert!(!current_some, "era swap clears current holder info");

    // Era-B initial holder commitment at num = next-1 (the CLN shape:
    // commit_index = next_index-1 on the new funding, numbering carried).
    let era_b_value = chan_ctx.setup.channel_value_sat;
    let mut ctx_b = channel_commitment(
        &node_ctx,
        &chan_ctx,
        next_num - 1,
        3755,
        era_b_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig_b, hsig_b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx_b);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx_b, &sig_b, &hsig_b)
        .expect("era-B initial holder commitment validates");

    // STORED? The pending slot must carry it, tagged with era B's funding.
    let (pending_some, tagged_b) = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok((
                chan.enforcement_state.next_holder_commit_info.is_some(),
                chan.enforcement_state.holder_commitment_funding
                    == Some(chan.setup.funding_outpoint),
            ))
        })
        .expect("state read");
    assert!(
        pending_some && tagged_b,
        "era-B initial commitment must be stored pending + tagged: pending={} tagged={}",
        pending_some,
        tagged_b
    );

    // And the close at that number must SIGN (from the pending record).
    let res = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.sign_holder_commitment_tx_phase2(next_num - 1)
        });
    assert!(res.is_ok(), "era-B close must sign: {:?}", res.err());
}

/// R4: the retransmit no-op is preserved — re-validating the CURRENT
/// commitment on a normal channel (num = next-1, view == setup, current
/// present) must NOT clobber state or change closeability.
#[test]
fn rail_current_commitment_revalidation_is_still_a_noop() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let before = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok((
                chan.enforcement_state.next_holder_commit_num,
                chan.enforcement_state.current_holder_commit_info.as_ref().map(|i| i.total_value()),
                chan.enforcement_state.next_holder_commit_info.is_some(),
            ))
        })
        .expect("state before");

    // Re-validate the SAME num-1 (retransmit shape; current is present).
    let (sig1b, hsig1b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1b, &hsig1b)
        .expect("retransmission validates");

    let after = node_ctx
        .node
        .with_channel(&channel_id, |chan: &mut Channel| {
            Ok((
                chan.enforcement_state.next_holder_commit_num,
                chan.enforcement_state.current_holder_commit_info.as_ref().map(|i| i.total_value()),
                chan.enforcement_state.next_holder_commit_info.is_some(),
            ))
        })
        .expect("state after");

    assert_eq!(before, after, "retransmit must remain a no-op");

    // And the plain close still signs.
    let res = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.sign_holder_commitment_tx_phase2(before.0 - 1)
        });
    assert!(res.is_ok(), "close after retransmit must sign: {:?}", res.err());
}
