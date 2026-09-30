//! Playground #268 I-4/EC-4b rails: pin the revocation-hygiene design of
//! per-commitment points across funding eras — the security review that
//! closed EC-4b as NOT a vulnerability (Oracle adjudication, banked at
//! /root/splice-ec5-evidence-2026-09-30/I4-ORACLE-ADJUDICATION-FULL.md).
//!
//! The design (all pinned here, all pre-existing behavior):
//! - Commitment numbering CARRIES OVER across splices — BOLT #2 quoted
//!   in-fork: "MUST reuse the same commitment number for its next
//!   commitment_signed" (simple_validator.rs:824, node.rs:2050,
//!   validator.rs:808). `snapshot_funding_for_splice` moves commitment
//!   infos but never touches the numbering; CLN's `next_index` is
//!   monotonic across the splice (channeld.c:3349/:3430).
//! - Per-commitment derivation is num-indexed from era-invariant channel
//!   keys, so point(n) is IDENTICAL across eras — and that is REQUIRED,
//!   not a defect: the spec-mandated same-num re-sign across the funding
//!   swap presents the SAME point, and VLS refuses a changed point on a
//!   same-funding retry (`policy-commitment-retry-same`).
//! - Era hygiene is enforced at the CHAIN layer (the splice spends the
//!   retiring funding; stale old-funding commitments are double-spends)
//!   plus the numbering discipline: a commitment number in revoked
//!   territory is refused in ANY era (`policy-commitment-holder-not-
//!   revoked`, simple_validator.rs:973), and the per-commitment secret
//!   release gate (channel.rs:591, `n + 2 <= next_holder_commit_num`)
//!   marches monotonically with it. A released index is therefore never
//!   re-derived-and-signed — the harm model considered in EC-4b cannot
//!   materialize.
//!
//! These rails are regression pins (GREEN throughout). A RED here means
//! the numbering-continuity design broke — treat it as a security-shaped
//! finding, not a test bug.

use crate::channel::{Channel, ChannelBase, ChannelId};
use crate::mutant_rails_tests::splice_a_to_b;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::util::test_utils::key::*;
use crate::util::test_utils::{
    channel_commitment, counterparty_sign_holder_commitment, fund_test_channel, test_node_ctx,
    validate_holder_commitment,
};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::chan_utils::CommitmentTransaction;

const ERA_B_REMOTE_POINT_NDX: u8 = 11;

fn remote_point(ndx: u8) -> PublicKey {
    make_test_pubkey(ndx)
}

/// Build a counterparty-broadcastable commitment for the CURRENT funding
/// view (the splice_era_totals_rails construction), then have the channel
/// sign it.
fn sign_current_view_counterparty_commitment(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    channel_id: &ChannelId,
    point: &PublicKey,
    commit_num: u64,
    to_broadcaster: u64,
    to_countersigner: u64,
) -> Result<bitcoin::secp256k1::ecdsa::Signature, crate::util::status::Status> {
    node_ctx.node.with_channel(channel_id, |chan| {
        let view = chan.setup.clone();
        let channel_parameters = chan.make_channel_parameters_with_setup(&view);
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let keys = chan.make_counterparty_tx_keys(point);
        let mut htlcs = vec![];

        let commitment_tx = CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commit_num,
            point,
            to_countersigner,
            to_broadcaster,
            3755,
            htlcs.clone(),
            &parameters,
            &chan.secp_ctx,
        );

        let redeem_scripts = crate::util::test_utils::build_tx_scripts(
            &keys,
            to_countersigner,
            to_broadcaster,
            &mut htlcs,
            &parameters,
            &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
            &view.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
        let tx = commitment_tx.trust().built_transaction().transaction.clone();
        chan.sign_counterparty_commitment_tx(
            &tx,
            &output_witscripts,
            point,
            commit_num,
            3755,
            vec![],
            vec![],
        )
    })
}

/// Era A: validate holder commitments at num 0 (the initial, done by
/// fund_test_channel) then num 1, advancing `next_holder_commit_num`
/// to 2 — the state where secret(0) is releasable (`0 + 2 <= 2`) and
/// num 0 is in revoked territory.
fn establish_era_a_history(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    chan_ctx: &mut crate::util::test_utils::TestChannelContext,
) {
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = channel_commitment(node_ctx, chan_ctx, 1, 3755, channel_value - 3755, 0, vec![], vec![]);
    let (sig1, hsig1) = counterparty_sign_holder_commitment(node_ctx, chan_ctx, &mut ctx1);
    validate_holder_commitment(node_ctx, chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");
}

fn holder_point(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    channel_id: &ChannelId,
    num: u64,
) -> Result<PublicKey, crate::util::status::Status> {
    node_ctx
        .node
        .with_channel(channel_id, |chan| chan.get_per_commitment_point(num))
}

// Accept+gate rail: the continuity design end-to-end. Era A reaches
// released-secret depth (next_holder_commit_num = 2); the splice swaps
// the era; the era-B same-num re-sign (num 1, the spec-mandated reuse)
// validates; numbering advances; the secret release gate marches with
// it — secret(1) stays locked while next=2, unlocks at next=3. Point(1)
// is byte-identical across the era swap (num-indexed derivation).
#[test]
fn rail_splice_era_numbering_carries_and_release_gate_marches() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    establish_era_a_history(&node_ctx, &mut chan_ctx);

    let point_1_before = holder_point(&node_ctx, &channel_id, 1).expect("point(1) era A");

    // secret(1) locked while next_holder_commit_num = 2 (1 + 2 > 2)
    let secret_locked = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.get_per_commitment_secret(1))
        .is_err();
    assert!(secret_locked, "secret(1) must stay locked while next_holder_commit_num is 2");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    // Derivation continuity: same num -> same point across the era swap.
    let point_1_after = holder_point(&node_ctx, &channel_id, 1).expect("point(1) era B");
    assert_eq!(
        point_1_before, point_1_after,
        "point(n) must be num-indexed and era-invariant — the spec-mandated same-num re-sign depends on it"
    );

    // The era-B same-num re-sign: a holder commitment at num 1 (=
    // next_holder_commit_num - 1, the current number carried from era A)
    // for the NEW funding. Values mirror the splice (95_450 added).
    let value_b = chan_ctx.setup.channel_value_sat;
    let mut ctx1b = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, value_b - 3755, 0, vec![], vec![]);
    let (sig1b, hsig1b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1b);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1b, &sig1b, &hsig1b)
        .expect("the era-B same-num re-sign must validate (BOLT #2: reuse the same commitment number)");

    // Advance to num 2 on funding B.
    let mut ctx2b = channel_commitment(&node_ctx, &chan_ctx, 2, 3755, value_b - 3755, 0, vec![], vec![]);
    let (sig2b, hsig2b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx2b);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx2b, &sig2b, &hsig2b)
        .expect("era-B num-2 holder commitment validates (numbering advanced across the era)");

    // The release gate marched with continuity: secret(1) unlocks at
    // next_holder_commit_num = 3 (1 + 2 <= 3).
    let secret_1 = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.get_per_commitment_secret(1));
    assert!(
        secret_1.is_ok(),
        "secret(1) must be releasable once next_holder_commit_num reaches 3"
    );
}

// Refusal rail: a commitment number in revoked territory is refused in
// ANY era — post-splice, a holder commitment at num 0 (secret(0) already
// releasable in era A) must hit policy-commitment-holder-not-revoked.
// This is the invariant that makes the cross-era point reuse safe: the
// signer never re-validates (nor signs against) a released index.
#[test]
fn rail_splice_era_revoked_num_refused_across_eras() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    establish_era_a_history(&node_ctx, &mut chan_ctx);

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    let value_b = chan_ctx.setup.channel_value_sat;
    let mut ctx0b = channel_commitment(&node_ctx, &chan_ctx, 0, 3755, value_b - 3755, 0, vec![], vec![]);
    let (sig0b, hsig0b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx0b);
    let err = validate_holder_commitment(&node_ctx, &chan_ctx, &ctx0b, &sig0b, &hsig0b)
        .expect_err("a revoked commitment number must be refused in the new era too");
    assert!(
        err.message().contains("can't validate revoked commitment_number 0"),
        "refusal must be policy-commitment-holder-not-revoked, got: {}",
        err.message()
    );
}

// Refusal rail: the same-funding retry point discipline the era design
// leans on — inside the era-B window, re-signing the counterparty
// commitment at the same num with a CHANGED point is refused
// (policy-commitment-retry-same). The spec-mandated cross-era re-sign
// reuses the SAME point precisely because derivation is num-indexed.
#[test]
fn rail_splice_era_same_funding_retry_changed_point_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    establish_era_a_history(&node_ctx, &mut chan_ctx);

    // Advance the counterparty numbering in era A (num 0 sign) so the
    // era-B signs below are legal progressions of it.
    let channel_id = chan_ctx.channel_id.clone();
    let p0 = remote_point(ERA_B_REMOTE_POINT_NDX - 1);
    sign_current_view_counterparty_commitment(&node_ctx, &channel_id, &p0, 0, 996_245, 0)
        .expect("era-A num-0 counterparty sign establishes the numbering");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let value_b = chan_ctx.setup.channel_value_sat;

    // First era-B counterparty sign at num 1 establishes the funding-B
    // point at that num.
    let p1 = remote_point(ERA_B_REMOTE_POINT_NDX);
    sign_current_view_counterparty_commitment(&node_ctx, &channel_id, &p1, 1, value_b - 3755, 0)
        .expect("first era-B counterparty sign at num 1 establishes the point");

    let p2 = remote_point(ERA_B_REMOTE_POINT_NDX + 1);
    let err = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &p2,
        1,
        value_b - 3755,
        0,
    )
    .expect_err("a same-num retry with a changed point must be refused");
    assert!(
        err.message().contains("changed point") || err.message().contains("changed info"),
        "refusal must be policy-commitment-retry-same, got: {}",
        err.message()
    );
}
