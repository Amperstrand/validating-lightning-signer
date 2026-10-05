//! Playground #268 item 3 rails: the splice-era initial-funding policy must
//! evaluate against the CARRIED prior-era balances, not against push_value
//! alone.
//!
//! BOLTs #1160 splicing starts a fresh commitment-number era on the new
//! funding, so the first new-era commitment legitimately re-runs the
//! commit_num == 0 policy checks. `policy-commitment-initial-funding-value`
//! assumes a FRESH channel there (fundee entitled to push_value only) — but a
//! SPLICED channel's fundee carries their entire prior-era balance into the
//! new era, so an honest first new-era commitment is refused and the splice
//! wedges (live evidence: the strict two_chan run, signer refusal at the
//! STFU-complete moment).
//!
//! Both rails (campaign doctrine — every carve-out gets both):
//! - must-accept: first new-era commitment pays the counterparty exactly
//!   their prior-era balance + push_value -> SignRemoteCommitmentTx succeeds.
//! - must-refuse: the same shape paying MORE than prior balance + push_value
//!   is still rejected.
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

// must-accept rail (RED against current code): the honest first new-era
// commitment — counterparty receives exactly their carried prior-era
// balance plus the new era's push_value — must sign in strict policy.
#[test]
fn rail_splice_era_initial_commitment_pays_carried_balance_plus_push() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;
    let push_sat = chan_ctx.setup.push_value_msat / 1000;
    assert!(push_sat == 0, "test setup uses a zero-push splice");

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

    let cp_entitlement = CARRIED_CP_SAT + push_sat;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - cp_entitlement,
        cp_entitlement,
    );
    assert!(
        res.is_ok(),
        "the first new-era commitment must pay carried balance + push: {:?}",
        res.err()
    );
}

// must-refuse rail: the same shape paying MORE than carried + push stays
// rejected — the carve-out carries prior state, it does not open the cap.
#[test]
fn rail_splice_era_initial_commitment_over_carried_balance_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    const CARRIED_CP_SAT: u64 = 200_000;
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, CARRIED_CP_SAT);

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    let new_value = chan_ctx.setup.channel_value_sat;
    let push_sat = chan_ctx.setup.push_value_msat / 1000;

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

    let overpaid = CARRIED_CP_SAT + push_sat + 50_000;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - overpaid,
        overpaid,
    );
    let err = res.expect_err("over the carried balance + push must be refused");
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

// push-floor rail (RED before the retiring-push snapshot field): a channel
// spliced immediately after opening has NO exchanged commitments to
// snapshot, so the fundee's carried entitlement is exactly the retiring
// setup's push (the live two_chan shape: refusal read "prior-era balance
// (0)" while the fundee legitimately carried the era-A push).
#[test]
fn rail_splice_era_carried_push_floor_for_unexchanged_era() {
    let node_ctx = test_node_ctx(1);
    const PUSH_MSAT: u64 = 500_000; // dust-safe: the fundee output must clear the 354-sat dust check
    let push_sat = PUSH_MSAT / 1000;

    // fund_test_channel with a push: the initial holder commitment pays the
    // fundee 0 (an allowed underpay), so no commitment info ever carries
    // the fundee's entitlement — the snapshot floor is the only carrier.
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
    // the new era keeps the push (the harness carries it into the new setup)
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

    let fundee_entitlement = push_sat + new_push_sat;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - fundee_entitlement,
        fundee_entitlement,
    );
    assert!(
        res.is_ok(),
        "an unexchanged era carries the retiring push: {:?}",
        res.err()
    );
}

// spent-down rail (RED before the floor-restriction fix): the retiring push
// must NOT floor a carried balance that an exchanged prior-era commitment
// already records below the push. The fundee received push_sat at open,
// spent down to spent_down_sat (< push_sat), then the channel spliced:
// carried is spent_down_sat — the push floor applies only to the
// never-exchanged era (see the rail above).
#[test]
fn rail_splice_era_spent_down_balance_is_not_floored_by_retiring_push() {
    let node_ctx = test_node_ctx(1);
    const PUSH_MSAT: u64 = 500_000;
    const SPENT_DOWN_SAT: u64 = 400; // dust-safe (>= 354) and below push_sat (500)
    let push_sat = PUSH_MSAT / 1000;
    assert!(SPENT_DOWN_SAT < push_sat, "rail needs a spent-down balance below the push");

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
        let mut tx = tx_ctx.to_tx();
        crate::util::test_utils::funding_tx_setup_channel(&node_ctx, &mut ctx, &tx, outpoint_ndx);

        // advance the commitment numbering exactly like fund_test_channel:
        // validate the initial (num 0) holder commitment, which the
        // push-val construction pays to the fundee as an allowed underpay.
        let mut commit_tx_ctx =
            crate::util::test_utils::channel_initial_holder_commitment(&node_ctx, &ctx);
        let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid initial holder commitment");
        // (no funding-tx witvec validation here: the push-carrying channel
        // output trips the dual-funding guard in validate_onchain_tx, same
        // as the unexchanged-era rail above)
        ctx
    };
    let channel_id = chan_ctx.channel_id.clone();

    // era-A exchanged commitment recording the fundee spent down to
    // SPENT_DOWN_SAT (a payment back to the funder; legal at num >= 1).
    establish_era_a_counterparty_balance(&node_ctx, &mut chan_ctx, SPENT_DOWN_SAT);

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

    // must-accept: spent-down balance + new push signs in strict policy.
    let entitlement = SPENT_DOWN_SAT + new_push_sat;
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - entitlement,
        entitlement,
    );
    assert!(
        res.is_ok(),
        "spent-down balance + push must sign: {:?}",
        res.err()
    );

    // must-refuse: an overpay that the old unconditional push floor would
    // have admitted (spent_down + 2*push is inside push + max(spent_down,
    // push)) must now be rejected — the exchanged commitment is
    // authoritative, the floor does not resurrect spent funds.
    let overpaid = SPENT_DOWN_SAT + new_push_sat + 100;
    assert!(
        overpaid <= push_sat + push_sat,
        "overpay must sit inside the old floor's cap to prove the fix"
    );
    let res = sign_current_view_counterparty_commitment(
        &node_ctx,
        &channel_id,
        &remote_point(ERA_B_REMOTE_POINT_NDX),
        0,
        new_value - 3755 - overpaid,
        overpaid,
    );
    let err = res.expect_err("over the spent-down balance + push must be refused");
    assert!(
        err.message().contains("initial commitment may only send push_value_msat"),
        "refusal must be the initial-funding policy, got: {}",
        err.message()
    );
}
