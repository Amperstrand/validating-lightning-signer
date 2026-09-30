//! Playground #268 item 3 rails: the splice-era initial-funding policy
//! allowance is EXACTLY the reported push_value (owner decision
//! 2026-09-30, handoff item 1(b) "carried-term keep-vs-drop" -> drop).
//!
//! BOLTs #1160 splicing starts a fresh commitment-number era on the new
//! funding, so the first new-era commitment re-runs the commit_num == 0
//! policy checks. The CLN fork's splice-era convention
//! (lightning-playground #268 EC-2 / upstream PR 9591's splice-fundee-msat
//! branch, semantically identical) sends the fundee's FULL post-splice
//! balance in push_value: pre-splice owed[] plus their signed
//! contribution, selected by channel-opener role. The signer-side
//! carried-balance term that used to be ADDED to the allowance
//! double-counted that balance against the honest report (over-allowance
//! of exactly the carried amount); its snapshot floor duplicated what
//! owed[] already carries. Both dropped — the allowance is push_value.
//!
//! Rails (campaign doctrine — every carve-out gets both):
//! - must-accept: first new-era commitment pays the fundee exactly the
//!   REPORTED push_value (which carries their full entitlement).
//! - must-refuse: anything above the reported push_value is rejected —
//!   including the pre-drop "carried + push" shape, which double-counts.
//! - must-accept (unexchanged era): a channel spliced before any
//!   commitments were exchanged carries the fundee's entitlement purely
//!   via the reported push.
//! - must-accept (D1 splice-out): a fundee withdrawal reports a REDUCED
//!   total; the first new-era commitment paying exactly that reduced
//!   total signs, and the pre-reduction balance refuses.
//! - control: a FRESH channel's initial commitment paying the fundee more
//!   than push_value stays rejected (the original invariant, unweakened).

use crate::util::test_utils::{
    fund_test_channel, test_node_ctx, channel_commitment, counterparty_sign_holder_commitment,
    validate_holder_commitment,
};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::chan_utils::CommitmentTransaction;

use crate::channel::{Channel, ChannelBase};
use crate::mutant_rails_tests::splice_a_to_b;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::util::test_utils::key::*;

const ERA_A_REMOTE_POINT_NDX: u8 = 10;
const ERA_B_REMOTE_POINT_NDX: u8 = 11;

fn remote_point(ndx: u8) -> PublicKey {
    make_test_pubkey(ndx)
}

/// Establish a prior-era counterparty balance: an era-A holder commitment at
/// num 1 paying the counterparty `cp_value_sat` (num >= 1 clears the
/// initial-commitment checks, so a payment-shifted balance is legal there).
fn establish_era_a_counterparty_balance(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    chan_ctx: &mut crate::util::test_utils::TestChannelContext,
    cp_value_sat: u64,
) {
    let channel_value = chan_ctx.setup.channel_value_sat;
    const FEERATE_PER_KW: u32 = 3755;
    const FEE_SAT: u64 = 3755;
    let mut ctx1 = channel_commitment(
        node_ctx,
        chan_ctx,
        1,
        FEERATE_PER_KW,
        channel_value - FEE_SAT - cp_value_sat,
        cp_value_sat,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(node_ctx, chan_ctx, &mut ctx1);
    validate_holder_commitment(node_ctx, chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");
}

/// Build a counterparty-broadcastable commitment for the CURRENT funding
/// view (the strict_mode_tests construction), then have the channel sign it.
fn sign_current_view_counterparty_commitment(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    channel_id: &crate::channel::ChannelId,
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

// must-accept rail: the honest first new-era commitment — fundee paid
// exactly the REPORTED push_value, which (CLN fork / PR 9591 semantics)
// already carries their prior-era balance plus contribution.
#[test]
fn rail_splice_era_initial_commitment_pays_reported_entitlement() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);

    // What an EC-2-convention host reports: the fundee's full
    // post-splice entitlement (their carried balance; the harness
    // carries setup.push_value_msat into the new era).
    chan_ctx.setup.push_value_msat = CARRIED_CP_SAT * 1000;

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;
    assert_eq!(
        chan_ctx.setup.push_value_msat / 1000,
        CARRIED_CP_SAT,
        "harness carries the reported push into the new setup"
    );

    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_B_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - CARRIED_CP_SAT,
        CARRIED_CP_SAT,
    );
    assert!(
        res.is_ok(),
        "the first new-era commitment must pay the reported entitlement: {:?}",
        res.err()
    );
}

// must-refuse rail: paying MORE than the reported push_value stays
// rejected — the report carries the entitlement, it does not open a cap.
#[test]
fn rail_splice_era_initial_commitment_over_reported_entitlement_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);
    chan_ctx.setup.push_value_msat = CARRIED_CP_SAT * 1000;

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;

    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_B_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    let overpaid = CARRIED_CP_SAT + 50_000;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - overpaid,
        overpaid,
    );
    let err = res.expect_err("over the reported entitlement must be refused");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}

// flip rail (was the pre-drop must-accept): the "carried + push" shape
// DOUBLE-COUNTS once the report carries the balance — it must refuse.
#[test]
fn rail_splice_era_initial_commitment_double_counted_carried_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);
    chan_ctx.setup.push_value_msat = CARRIED_CP_SAT * 1000;

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;

    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_B_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    // The pre-drop allowance was push + carried = 2x the entitlement;
    // paying it must now refuse.
    let double_counted = CARRIED_CP_SAT * 2;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - double_counted,
        double_counted,
    );
    let err = res.expect_err("the double-counted shape must refuse post-drop");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}

// control rail (GREEN today and after the fix): a FRESH channel's initial
// commitment paying the fundee beyond push_value stays rejected — the
// original anti-theft invariant is untouched by the era fix.
#[test]
fn control_fresh_channel_initial_over_push_still_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    // No splice: era-A numbering straight to the num-0 counterparty sign.
    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_A_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    let over_push = 50_000;
    let value = chan_ctx.setup.channel_value_sat;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_A_REMOTE_POINT_NDX),
        0,
        value - 3755 - over_push,
        over_push,
    );
    let err = res.expect_err("a fresh channel's initial over-push payment must be refused");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}

// D1 rail: the fundee SPLICES OUT. The host's report is the fundee's
// REDUCED total (owed + pending + a negative signed relative — the
// negative-guard shape that motivated D1); the first new-era commitment
// paying exactly that reduced total must sign, and the pre-reduction
// balance must refuse: the reduction travels in the report, it does not
// ride a wrapped value or a carried term.
#[test]
fn rail_splice_era_fundee_splice_out_reduced_total_signs() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    const SPLICE_OUT_SAT: u64 = 50_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);

    // The D1-convention host report for a fundee splice-out: the fundee's
    // total balance REDUCED by the withdrawal (channeld peer-fails only
    // if this would go negative — a true over-draw).
    chan_ctx.setup.push_value_msat = (CARRIED_CP_SAT - SPLICE_OUT_SAT) * 1000;

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;
    assert_eq!(
        chan_ctx.setup.push_value_msat / 1000,
        CARRIED_CP_SAT - SPLICE_OUT_SAT,
        "harness carries the reduced report into the new setup"
    );

    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_B_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    // Exactly the reduced total: must sign.
    let reduced = CARRIED_CP_SAT - SPLICE_OUT_SAT;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - reduced,
        reduced,
    );
    assert!(
        res.is_ok(),
        "the first new-era commitment must pay the reduced total: {:?}",
        res.err()
    );

    // The PRE-reduction balance: above the reported total, must refuse
    // (the withdrawal is binding, not advisory).
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - CARRIED_CP_SAT,
        CARRIED_CP_SAT,
    );
    let err = res.expect_err("the pre-reduction balance must refuse");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}

// unexchanged-era rail: a channel spliced before any commitments were
// exchanged carries the fundee's entitlement purely via the reported
// push (owed[] carried it upstream all along — the dropped snapshot
// floor duplicated this).
#[test]
fn rail_splice_era_unexchanged_entitlement_via_reported_push() {
    let node_ctx = test_node_ctx(1);
    const PUSH_MSAT: u64 = 500_000; // dust-safe: the fundee output must clear the 354-sat dust check
    let push_sat = PUSH_MSAT / 1000;

    let mut chan_ctx = {
        let mut ctx = crate::util::test_utils::test_chan_ctx_with_push_val(
            &node_ctx,
            1,
            1_000_000,
            PUSH_MSAT,
        );
        let stype = crate::node::SpendType::P2wpkh;
        let incoming = 1_000_000 + 2_000_000;
        let fee = 1000;
        let change = incoming - 1_000_000 - fee;
        let mut tx_ctx = crate::util::test_utils::TestFundingTxContext::new();
        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &ctx, 1_000_000);
        let tx = tx_ctx.to_tx();
        crate::util::test_utils::funding_tx_setup_channel(&node_ctx, &mut ctx, &tx, outpoint_ndx);
        ctx
    };
    let channel_id = chan_ctx.channel_id.clone();

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;
    let new_push_sat = chan_ctx.setup.push_value_msat / 1000;
    assert_eq!(new_push_sat, push_sat, "harness carries the push into the new setup");

    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                0,
                remote_point(ERA_B_REMOTE_POINT_NDX),
            );
            Ok(())
        })
        .expect("numbering install");

    // Exactly the reported push: must sign.
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - push_sat,
        push_sat,
    );
    assert!(
        res.is_ok(),
        "an unexchanged era carries the entitlement via the report: {:?}",
        res.err()
    );

    // The pre-drop shape (retiring push + new push) double-counts now.
    let over = push_sat * 2;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - over,
        over,
    );
    let err = res.expect_err("the double-counted unexchanged shape must refuse");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}
