//! Playground #268 EC-5 rails: `validate_onchain_tx` needs a splice branch
//! for EXISTING channels — the `policy-onchain-no-fund-inbound` family.
//!
//! The channel-funding-output branch of `validate_onchain_tx`
//! (simple_validator.rs, `ChannelSlot::Ready` case) still runs the
//! fresh-open walls on every funding-shaped psbt:
//! - wall 1 `policy-onchain-initial-commitment-countersigned`
//!   (`next_holder_commit_num != 1`),
//! - wall 2 `policy-onchain-no-fund-inbound` (`!is_outbound`),
//! - wall 3 `policy-onchain-no-channel-push` (`push_value > 0`).
//! A splice wallet-input SignWithdrawal into an EXISTING channel violates
//! wall 1 by definition (the channel has commitment history) and walls 2/3
//! whenever the fundee holds value (the era convention carries the fundee's
//! post-splice balance in `push_value`). Live evidence: strict
//! two_chan_splice_in refuses at `policy-onchain-no-fund-inbound`
//! (tests/test_splicing.py:199), strict splice_stuck_htlc refuses at
//! `policy-onchain-initial-commitment-countersigned` (pernode-fac979ffcf72
//! req 444, banked /root/splice-ff-evidence-2026-09-28/).
//!
//! Rails (campaign doctrine — every carve-out gets both):
//! - must-accept (RED today): a splice psbt that spends the retiring
//!   funding and re-funds the same channel signs — both the fundee
//!   (two_chan l2) and the with-history (stuck_htlc) shapes.
//! - must-refuse (RED today): a mid-splice psbt that does NOT spend the
//!   retiring funding outpoint is refused — the new-funding output must be
//!   tied to the era it retires, not a parallel funding.
//! - kept rails (GREEN today and after): the value-match and script-match
//!   checks still bind mid-splice; a FRESH inbound channel's dual-fund
//!   psbt stays refused (the original invariant, unweakened).

use crate::node::SpendType;
use crate::util::test_utils::{
    channel_commitment, channel_initial_holder_commitment, counterparty_sign_holder_commitment,
    funding_tx_setup_channel, test_chan_ctx, test_node_ctx, validate_holder_commitment,
    TestChannelContext, TestFundingTxContext, TestNodeContext,
};
use bitcoin::bip32::DerivationPath;
use bitcoin::transaction::{Sequence, TxIn};
use bitcoin::{Transaction, TxOut};

const ERA_A_CHANNEL_VALUE: u64 = 1_000_000;
const SPLICE_IN_CONTRIB: u64 = 100_000;
const ERA_B_CHANNEL_VALUE: u64 = ERA_A_CHANNEL_VALUE + SPLICE_IN_CONTRIB;
/// The fundee's post-splice balance in the era convention (msat): carried 0
/// + fresh 100k contribution (the live two_chan l2 shape).
const ERA_B_PUSH_MSAT: u64 = SPLICE_IN_CONTRIB * 1000;

fn channel_input_spending(outpoint: bitcoin::OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: bitcoin::Witness::default(),
    }
}

/// Push a non-wallet input (the channel funding being spent by the splice)
/// into the tx context, aligned per-input with prev_outs/ipaths/iuckeys.
/// The signing loop skips it (empty ipath, unrecognized script).
fn add_channel_input(tx_ctx: &mut TestFundingTxContext, funding_out: &TxOut, outpoint: bitcoin::OutPoint) {
    tx_ctx.inputs.push(channel_input_spending(outpoint));
    tx_ctx.prev_outs.push(funding_out.clone());
    tx_ctx.ipaths.push(DerivationPath::from(vec![]));
    tx_ctx.ispnds.push(SpendType::Invalid);
    tx_ctx.iuckeys.push(None);
}

/// Open era A with a plain wallet-funded funding tx and exchange the
/// initial holder commitment (num 0, `next_holder_commit_num` → 1 — the
/// state of the live two_chan channels at splice time: opened, no further
/// history). Returns the funding TxOut for the splice's channel input.
fn open_era_a(node_ctx: &TestNodeContext, chan_ctx: &mut TestChannelContext) -> TxOut {
    let mut tx_ctx = TestFundingTxContext::new();
    let incoming = ERA_A_CHANNEL_VALUE + 2_000_000;
    let fee = 1_000;
    tx_ctx.add_wallet_input(node_ctx, SpendType::P2wpkh, 1, incoming);
    tx_ctx.add_wallet_output(node_ctx, SpendType::P2wpkh, 2, incoming - ERA_A_CHANNEL_VALUE - fee);
    let vout = tx_ctx.add_channel_outpoint(node_ctx, chan_ctx, ERA_A_CHANNEL_VALUE);
    let tx = tx_ctx.to_tx();
    let funding_out = tx.output[vout as usize].clone();
    assert!(
        funding_tx_setup_channel(node_ctx, chan_ctx, &tx, vout).is_none(),
        "era A setup accepted"
    );

    let mut commit_ctx = channel_initial_holder_commitment(node_ctx, chan_ctx);
    let (csig, hsigs) = counterparty_sign_holder_commitment(node_ctx, chan_ctx, &mut commit_ctx);
    validate_holder_commitment(node_ctx, chan_ctx, &commit_ctx, &csig, &hsigs)
        .expect("era-A initial holder commitment validates");

    funding_out
}

/// Exchange an era-A num-1 holder commitment so the channel carries
/// commitment history (`next_holder_commit_num` advances past 1 — the
/// stuck_htlc shape that trips wall 1).
fn establish_era_a_history(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
) {
    let channel_value = chan_ctx.setup.channel_value_sat;
    const FEERATE_PER_KW: u32 = 3755;
    const FEE_SAT: u64 = 3755;
    let mut ctx1 = channel_commitment(
        node_ctx,
        chan_ctx,
        1,
        FEERATE_PER_KW,
        channel_value - FEE_SAT,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = counterparty_sign_holder_commitment(node_ctx, chan_ctx, &mut ctx1);
    validate_holder_commitment(node_ctx, chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");
}

/// Build the era-A → era-B splice state (setup swapped, retiring funding
/// snapshotted, `prev_setup`/`prev_funding_commitment` Some) and return
/// the assembled tx context + tx ready for `sign`.
struct SplicePsbt {
    tx_ctx: TestFundingTxContext,
    tx: Transaction,
}

#[allow(clippy::too_many_arguments)]
fn build_splice(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    era_a_funding_out: &TxOut,
    wallet_input_sat: u64,
    change_sat: u64,
    spend_retiring: bool,
    funding_value_sat: u64,
    wrong_funding_script: bool,
    push_msat: u64,
) -> SplicePsbt {
    let old_outpoint = chan_ctx.setup.funding_outpoint;
    chan_ctx.setup.channel_value_sat = ERA_B_CHANNEL_VALUE;
    chan_ctx.setup.push_value_msat = push_msat;

    let mut tx_ctx = TestFundingTxContext::new();
    if spend_retiring {
        add_channel_input(&mut tx_ctx, era_a_funding_out, old_outpoint);
    }
    tx_ctx.add_wallet_input(node_ctx, SpendType::P2wpkh, 3, wallet_input_sat);
    let vout = if wrong_funding_script {
        // Same position and value, but pays a wallet script instead of the
        // 2-of-2 funding script (empty opath — not claimed as wallet).
        let ndx = tx_ctx.outputs.len();
        tx_ctx.add_unknown_output(node_ctx, SpendType::P2wpkh, 7, funding_value_sat);
        ndx as u32
    } else {
        tx_ctx.add_channel_outpoint(node_ctx, chan_ctx, funding_value_sat)
    };
    tx_ctx.add_wallet_output(node_ctx, SpendType::P2wpkh, 4, change_sat);

    let tx = tx_ctx.to_tx();
    assert!(
        funding_tx_setup_channel(node_ctx, chan_ctx, &tx, vout).is_none(),
        "splice re-setup accepted"
    );
    SplicePsbt { tx_ctx, tx }
}

/// Flip the channel to the fundee role after the splice setup (the live
/// two_chan shape: l2 is chan#1's fundee; opener/fundee roles inherit from
/// the original open, so the era-B setup carries `is_outbound = false`).
fn flip_to_inbound(node_ctx: &TestNodeContext, chan_ctx: &TestChannelContext) {
    node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.setup.is_outbound = false;
            Ok(())
        })
        .expect("role flip");
}

// must-accept rail (RED today: wall 2 `policy-onchain-no-fund-inbound` +
// wall 3 `policy-onchain-no-channel-push`): the fundee of an existing
// channel signs the wallet-input side of a splice psbt that spends the
// retiring funding and re-funds the channel with the fundee's fresh
// contribution carried in push_value — the exact live two_chan shape.
#[test]
fn rail_splice_psbt_inbound_fundee_with_push_signs() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);
    let era_a_funding_out = open_era_a(&node_ctx, &mut chan_ctx);

    // wallet in 200k; funding out 1.1M + change 99k; fee 1k
    let SplicePsbt { tx_ctx, tx } = build_splice(
        &node_ctx,
        &mut chan_ctx,
        &era_a_funding_out,
        200_000,
        99_000,
        true,
        ERA_B_CHANNEL_VALUE,
        false,
        ERA_B_PUSH_MSAT,
    );

    flip_to_inbound(&node_ctx, &chan_ctx);

    let res = tx_ctx.sign(&node_ctx, &tx);
    assert!(
        res.is_ok(),
        "the fundee's splice wallet-input psbt must sign: {:?}",
        res.err()
    );
}

// must-accept rail (RED today: wall 1
// `policy-onchain-initial-commitment-countersigned`): a channel with
// commitment history (stuck_htlc shape) signs the wallet-input side of a
// splice psbt — `next_holder_commit_num > 1` is the NORMAL state of an
// existing channel, not an unvalidated initial commitment.
#[test]
fn rail_splice_psbt_existing_channel_with_history_signs() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);
    let era_a_funding_out = open_era_a(&node_ctx, &mut chan_ctx);
    establish_era_a_history(&node_ctx, &mut chan_ctx);

    // funder-side splice-in, fundee keeps 0: push stays 0 in this rail,
    // history is the wall under test. wallet in 116k; change 15k; fee 1k.
    let SplicePsbt { tx_ctx, tx } = build_splice(
        &node_ctx,
        &mut chan_ctx,
        &era_a_funding_out,
        SPLICE_IN_CONTRIB + 16_000,
        15_000,
        true,
        ERA_B_CHANNEL_VALUE,
        false,
        0,
    );

    let res = tx_ctx.sign(&node_ctx, &tx);
    assert!(
        res.is_ok(),
        "a with-history channel's splice wallet-input psbt must sign: {:?}",
        res.err()
    );
}

// must-refuse rail (RED today — nothing ties the new funding to the era it
// retires): mid-splice, a psbt that does NOT spend the retiring funding
// outpoint must be refused. Without this tie the mid-splice carve-out
// could mint a parallel funding for the same channel while the retiring
// funding stays live.
#[test]
fn rail_splice_psbt_not_spending_retiring_funding_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);
    let era_a_funding_out = open_era_a(&node_ctx, &mut chan_ctx);

    // wallet-only funding of the new era: 1_102_000 in, 1.1M out + 1k
    // change, 1k fee, push 0 — pre-fix this psbt is ACCEPTED (the
    // smuggling gap: nothing ties the new funding to the retiring era).
    // The retiring outpoint is NOT spent.
    let SplicePsbt { tx_ctx, tx } = build_splice(
        &node_ctx,
        &mut chan_ctx,
        &era_a_funding_out,
        ERA_B_CHANNEL_VALUE + 2_000,
        1_000,
        false,
        ERA_B_CHANNEL_VALUE,
        false,
        0,
    );

    let err = tx_ctx
        .sign(&node_ctx, &tx)
        .expect_err("a splice psbt that does not spend the retiring funding must be refused");
    assert!(
        err.message().contains("splice psbt must spend the retiring funding"),
        "refusal must be the retiring-funding tie, got: {}",
        err.message()
    );
}

// kept rail (GREEN today and after — the value match binds mid-splice):
// the splice funding output must still equal the era-B setup's channel
// value.
#[test]
fn rail_splice_psbt_funding_value_mismatch_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);
    let era_a_funding_out = open_era_a(&node_ctx, &mut chan_ctx);

    // setup claims 1.1M but the psbt funds 1.05M — desynced on purpose.
    let SplicePsbt { tx_ctx, tx } = build_splice(
        &node_ctx,
        &mut chan_ctx,
        &era_a_funding_out,
        200_000,
        49_000,
        true,
        ERA_B_CHANNEL_VALUE - 50_000,
        false,
        ERA_B_PUSH_MSAT,
    );

    let err = tx_ctx
        .sign(&node_ctx, &tx)
        .expect_err("a funding output value mismatch must be refused mid-splice");
    assert!(
        err.message().contains("funding output amount mismatch w/ channel"),
        "refusal must be the value match, got: {}",
        err.message()
    );
}

// kept rail (GREEN today and after — the script match binds mid-splice):
// the splice funding output must still pay the channel's 2-of-2 funding
// script.
#[test]
fn rail_splice_psbt_funding_script_mismatch_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);
    let era_a_funding_out = open_era_a(&node_ctx, &mut chan_ctx);

    let SplicePsbt { tx_ctx, tx } = build_splice(
        &node_ctx,
        &mut chan_ctx,
        &era_a_funding_out,
        200_000,
        99_000,
        true,
        ERA_B_CHANNEL_VALUE,
        true,
        ERA_B_PUSH_MSAT,
    );

    let err = tx_ctx
        .sign(&node_ctx, &tx)
        .expect_err("a funding script mismatch must be refused mid-splice");
    assert!(
        err.message().contains("funding script_pubkey mismatch w/ channel"),
        "refusal must be the script match, got: {}",
        err.message()
    );
}

// control rail (GREEN today and after — the fresh-open invariant is
// unweakened): with NO splice in flight (first-ever setup, no retiring
// era), an inbound channel's dual-funding-shaped psbt stays refused — the
// carve-out keys on the mid-splice state, not on the message shape.
#[test]
fn control_fresh_inbound_dual_fund_still_refused() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, ERA_A_CHANNEL_VALUE);

    let mut tx_ctx = TestFundingTxContext::new();
    let incoming = ERA_A_CHANNEL_VALUE + 2_000_000;
    tx_ctx.add_wallet_input(&node_ctx, SpendType::P2wpkh, 5, incoming);
    tx_ctx.add_wallet_output(&node_ctx, SpendType::P2wpkh, 6, 1_000);
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, ERA_A_CHANNEL_VALUE);
    let tx = tx_ctx.to_tx();
    assert!(
        funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &tx, vout).is_none(),
        "first-ever setup accepted"
    );

    let mut commit_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
    let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_ctx);
    validate_holder_commitment(&node_ctx, &chan_ctx, &commit_ctx, &csig, &hsigs)
        .expect("initial holder commitment validates");

    flip_to_inbound(&node_ctx, &chan_ctx);

    let err = tx_ctx
        .sign(&node_ctx, &tx)
        .expect_err("a fresh inbound dual-fund psbt must stay refused");
    assert!(
        err.message().contains("can't sign for inbound channel"),
        "refusal must stay the inbound dual-funding wall, got: {}",
        err.message()
    );
}
