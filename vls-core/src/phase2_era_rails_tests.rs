//! Issue #112 rails: the validate/sign `_phase2` twins carry an explicit
//! funding-era token. Design references (issue #95 research, pinned):
//! - eclair design delta: the wire commit_sig names its funding
//!   (funding_txid TLV) and the state machine never guesses which view a
//!   sig belongs to — a value-based caller must name its era too, never
//!   silently bind to the current setup.
//! - BOLTs #1160 @1528972 L3130: `commitment_signed` MUST set
//!   `funding_txid` to the funding transaction spent by this commitment
//!   transaction.
//!
//! Both rails (campaign doctrine — every carve-out gets both):
//! - era match ACCEPTS: a retiring-era (prev_setup) commitment via
//!   phase2 routes to the old view — keys, valuation, recomposition and
//!   store tags. The era-blind twins recomposed against the CURRENT
//!   setup: the A-funding sighash mismatched and the legit straggler
//!   was refused at key resolution (STATE.md XIX: "era-A sigs fail
//!   key-resolution there").
//! - era mismatch ABORTS THE SPLICE, not the channel: an unknown token
//!   is a failed-precondition rejection with ZERO state mutation — the
//!   #106 class (cross-scale mis-bind: old-era values tagged/valued
//!   against the new funding) is structurally unreachable.

use crate::util::test_utils::{
    channel_commitment, counterparty_sign_holder_commitment, fund_test_channel, test_node_ctx,
    validate_holder_commitment,
};
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint};
use lightning::ln::chan_utils::make_funding_redeemscript;

use crate::channel::ChannelBase;
use crate::mutant_rails_tests::splice_a_to_b;

// The validate twin: an era-A commitment, signed while the channel
// lived in era A, re-presented through the value-based form mid-window
// with its era token. Must route to the prev view and validate; must
// not retag or advance the numbering (num == next-1, and the routed
// view equals the stored tag, so the straggler store gate stays quiet).
#[test]
fn rail_phase2_validate_routes_retiring_era() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let outpoint_a = chan_ctx.setup.funding_outpoint;

    // Era-A commitment #1 built and signed while setup == A (the
    // funding's own scale and parameters).
    let mut ctx1 = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 996_245, 0, vec![], vec![]);
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A commitment #1 validates");
    // next_holder == 2, holder tag == Some(A)

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);
    // Mid-window: setup == B, prev_setup == A.

    let res = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.validate_holder_commitment_tx_phase2(
            outpoint_a,
            1,
            3755,
            996_245,
            0,
            vec![],
            vec![],
            &sig1,
            &hsig1,
        )
    });
    assert!(
        res.is_ok(),
        "the retiring-era straggler must validate via its era token: {:?}",
        res.err()
    );

    // No state drift: num 1 is next-1 and the routed view equals the
    // stored tag, so neither store arm fires and nothing retags.
    let (next, tag) = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok((
                chan.enforcement_state.next_holder_commit_num,
                chan.enforcement_state.holder_commitment_funding,
            ))
        })
        .expect("state read");
    assert_eq!(next, 2, "the straggler validation must not advance the number");
    assert_eq!(tag, Some(outpoint_a), "the holder tag must stay era-A");
}

// The sign twin: an era-A retransmission mid-window with the A token.
// Must succeed (identical info at the same number — the R7.2 retransmit
// contract), return a signature over the A-VIEW recomposition (A
// funding input, A channel value, A-era parameters), and tag the routed
// era — the blind twin tagged the live setup (the mis-bind).
#[test]
fn rail_phase2_sign_routes_retiring_era() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let outpoint_a = chan_ctx.setup.funding_outpoint;

    let remote_point = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.get_per_commitment_point(0))
        .expect("per-commitment point");

    // The initial era-A sign at num 0 (next_cp 0 -> 1).
    let res = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.sign_counterparty_commitment_tx_phase2(
            outpoint_a,
            &remote_point,
            0,
            3755,
            996_245,
            0,
            vec![],
            vec![],
        )
    });
    assert!(res.is_ok(), "era-A num-0 sign: {:?}", res.err());

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    // The era-A retransmission, now carrying its token.
    let (sig, _htlc_sigs) = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.sign_counterparty_commitment_tx_phase2(
                outpoint_a,
                &remote_point,
                0,
                3755,
                996_245,
                0,
                vec![],
                vec![],
            )
        })
        .expect("era-A retransmission must sign (identical info, same number)");

    let tag = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok(chan.enforcement_state.counterparty_commitment_funding)
        })
        .expect("tag read");
    assert_eq!(
        tag,
        Some(outpoint_a),
        "the store tag must follow the routed era, not the live setup"
    );

    // The returned signature covers the retiring-era view: recompose
    // with the A setup and verify against the A funding redeemscript.
    let verified = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            let a_view = chan.prev_setup.clone().expect("prev_setup mid-window");
            let htlcs = crate::channel::Channel::htlcs_info2_to_oic(&[], &[]);
            let recomposed = chan.make_counterparty_commitment_tx_with_setup(
                &a_view,
                &remote_point,
                0,
                3755,
                996_245,
                0,
                htlcs,
            );
            let built = recomposed.trust().built_transaction();
            let redeemscript = make_funding_redeemscript(
                &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                &a_view.counterparty_points.funding_pubkey,
            );
            let sighash = SighashCache::new(&built.transaction)
                .p2wsh_signature_hash(
                    0,
                    &redeemscript,
                    Amount::from_sat(a_view.channel_value_sat),
                    EcdsaSighashType::All,
                )
                .expect("sighash");
            let verifier = bitcoin::secp256k1::Secp256k1::verification_only();
            Ok(verifier
                .verify_ecdsa(
                    &Message::from(sighash),
                    &sig,
                    &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                )
                .is_ok())
        })
        .expect("verify probe");
    assert!(verified, "the returned signature must cover the retiring-era (A) view recomposition");
}

// The abort rail: an unknown funding token is a splice-abort-class
// rejection (failed precondition) on BOTH twins, with zero state
// mutation — no numbering advance, no tag rewrite, no store writes.
#[test]
fn rail_phase2_unknown_era_aborts_without_state_poison() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    let mut ctx1 = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 996_245, 0, vec![], vec![]);
    let (sig1, hsig1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A commitment #1 validates");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    // A B-era num-2 commitment, built and signed against the CURRENT
    // (B) setup: the shape that WOULD fully succeed if the token were
    // ignored — so the refusal can only come from the token check.
    let mut ctx2 = channel_commitment(&node_ctx, &chan_ctx, 2, 3755, 1_091_695, 0, vec![], vec![]);
    let (sig2, hsig2) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx2);

    type Snapshot = (
        u64,
        u64,
        Option<OutPoint>,
        Option<OutPoint>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
    );
    let snap = |node: &crate::node::Node| -> Snapshot {
        node.with_channel(&channel_id, |chan| {
            Ok((
                chan.enforcement_state.next_holder_commit_num,
                chan.enforcement_state.next_counterparty_commit_num,
                chan.enforcement_state.holder_commitment_funding,
                chan.enforcement_state.counterparty_commitment_funding,
                chan.enforcement_state.current_holder_commit_info.as_ref().map(|i| i.total_value()),
                chan.enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .map(|i| i.total_value()),
                chan.enforcement_state
                    .next_holder_commit_info
                    .as_ref()
                    .map(|(i, _)| i.total_value()),
                chan.enforcement_state
                    .prev_funding_commitment
                    .as_ref()
                    .and_then(|s| s.next_holder_info.as_ref().map(|(i, _)| i.total_value())),
            ))
        })
        .expect("snapshot")
    };

    let before = snap(&node_ctx.node);

    let bogus = OutPoint { txid: Txid::from_slice(&[0xAB; 32]).unwrap(), vout: 42 };
    let remote_point = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.get_per_commitment_point(0))
        .expect("per-commitment point");

    let rv = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.validate_holder_commitment_tx_phase2(
            bogus,
            2,
            3755,
            1_091_695,
            0,
            vec![],
            vec![],
            &sig2,
            &hsig2,
        )
    });
    assert!(rv.is_err(), "an unknown era token must be refused");
    assert_eq!(
        rv.unwrap_err().code(),
        crate::util::status::Code::FailedPrecondition,
        "the refusal is splice-abort-class (FailedPrecondition), not channel-fatal"
    );

    // The sign twin with the would-succeed shape (num 0 is the next
    // counterparty number — normal progression if the token resolved).
    let rs = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.sign_counterparty_commitment_tx_phase2(
            bogus,
            &remote_point,
            0,
            3755,
            996_245,
            0,
            vec![],
            vec![],
        )
    });
    assert!(rs.is_err(), "an unknown era token must be refused on sign");

    let after = snap(&node_ctx.node);
    assert_eq!(
        before, after,
        "the aborted twin calls must leave every numbering/tag/store slot untouched"
    );
}
