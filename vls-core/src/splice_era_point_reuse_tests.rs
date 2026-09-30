//! EC-4b battery (playground #268): signer behavior under cross-era
//! per-commitment point reuse.
//!
//! Live evidence (2026-09-28 strict run, ADJUDICATION/EDGE-CASES docs):
//! the splice era's first commitment reuses ERA-1's num-0 per-commitment
//! point byte-for-byte. BOLT-3 derives per-commitment secrets per NUMBER
//! (seed chain), and splicing (BOLTs #1160) restarts commitment
//! numbering per funding era while the channel's basepoints are
//! unchanged — so era-A num-0 and era-B num-0 share point, secret, and
//! revocation pubkey BY DERIVATION. If era-A advanced past num-0, its
//! secret was legitimately revealed to the counterparty: from era B's
//! birth they can derive the revocation key for era-B num-0 without any
//! era-B breach.
//!
//! These rails pin the signer-side facts:
//! - rail_era_num0_point_and_secret_reuse_is_pinned: the reuse property
//!   itself (if derivation ever becomes per-era, this fails and the
//!   adjudication changes with it).
//! - rail_justice_sweep_signs_with_cross_era_secret_today: EMPIRICAL PIN
//!   — the signer signs an era-B num-0-shaped justice sweep presented
//!   with the (identical) era-A num-0 secret. sign_justice_sweep has no
//!   commitment-number, era, or revocation-state gate; its protection is
//!   purely "the host cannot forge a secret it was never given" — which
//!   cross-era reuse legitimately defeats.
//! - rail_justice_sweep_current_era_unrevoked_should_refuse (IGNORED,
//!   documented-RED): the SAFE target — a conservative ambiguity gate
//!   (num-0-shaped sweep while the current era's num-0 is unrevoked AND
//!   a prior era exists = refuse; the straggler-justice tradeoff is the
//!   cost). The design argument lives in the ignore message per the
//!   executable-spec pattern; un-ignoring is the acceptance bar IF the
//!   owner rules the fork should carry the defense.
//! - rail_same_num0_era_a_justice_control: the same construction
//!   pre-splice signs — proving the battery builds valid sweeps (the
//!   pins above are about cross-era semantics, not broken fixtures).

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning::ln::chan_utils;
use lightning::ln::chan_utils::get_revokeable_redeemscript;
use lightning::ln::channel_keys::{DelayedPaymentKey, RevocationBasepoint, RevocationKey};


use crate::channel::{Channel, ChannelBase};
use crate::mutant_rails_tests::splice_a_to_b;
use crate::util::test_utils::key::{make_test_key, make_test_pubkey};
use crate::util::test_utils::{fund_test_channel, make_test_wallet_dest, test_node_ctx};

const FEERATE_PER_KW: u32 = 5_000;
const TO_BROADCASTER: u64 = 1_979_997;
const TO_COUNTERSIGNATORY: u64 = 1_000_000;

struct JusticeSweepParts {
    tx: bitcoin::Transaction,
    input: usize,
    revocation_secret: SecretKey,
    redeemscript: bitcoin::ScriptBuf,
    amount_sat: u64,
    wallet_path: bitcoin::bip32::DerivationPath,
}

/// Build a num-0 counterparty commitment + its justice sweep against the
/// signer's CURRENT per-commitment point, presenting `presented_secret`
/// (the cross-era experiment passes the era-A secret; the control passes
/// the freshly derived one — byte-identical by derivation).
fn build_num0_justice_sweep(
    node_ctx: &crate::util::test_utils::TestNodeContext,
    chan_ctx: &crate::util::test_utils::TestChannelContext,
    presented_secret: SecretKey,
) -> JusticeSweepParts {
    node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            let secp_ctx = Secp256k1::new();
            let per_commitment_point = chan
                .get_per_commitment_point(0)
                .expect("num-0 per-commitment point");

            let htlcs = Channel::htlcs_info2_to_oic(&vec![], &vec![]);
            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                &per_commitment_point,
                0,
                FEERATE_PER_KW,
                TO_COUNTERSIGNATORY,
                TO_BROADCASTER,
                htlcs,
            );
            let built = commitment_tx.trust().built_transaction().clone();
            // No HTLCs: locate the broadcaster's to_local output by value.
            let to_local_outndx = built
                .transaction
                .output
                .iter()
                .position(|o| o.value.to_sat() == TO_BROADCASTER)
                .expect("to_local output present");
            let amount_sat = built.transaction.output[to_local_outndx].value.to_sat();

            let (revocation_base_point, revocation_base_secret) = make_test_key(42);
            let revocation_pubkey = RevocationKey::from_basepoint(
                &secp_ctx,
                &RevocationBasepoint(revocation_base_point),
                &per_commitment_point,
            );
            let revocation_secret = chan_utils::derive_private_revocation_key(
                &secp_ctx,
                &presented_secret,
                &revocation_base_secret,
            );

            let (script_pubkey, wallet_path) =
                make_test_wallet_dest(node_ctx, 19, crate::node::SpendType::P2wpkh);

            let mut tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: built.txid,
                        vout: to_local_outndx as u32,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ZERO,
                    witness: bitcoin::Witness::default(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(amount_sat - 1_000),
                    script_pubkey,
                }],
            };
            tx.input[0].witness = bitcoin::Witness::default();

            let delayed_payment_base = make_test_pubkey(2);
            let delayed_payment_pubkey =
                crate::util::crypto_utils::derive_public_key(
                    &secp_ctx,
                    &per_commitment_point,
                    &delayed_payment_base,
                )
                .expect("delayed_payment_pubkey");
            let redeemscript = get_revokeable_redeemscript(
                &revocation_pubkey,
                chan.setup.holder_selected_contest_delay,
                &DelayedPaymentKey(delayed_payment_pubkey),
            );

            Ok(JusticeSweepParts {
                tx,
                input: 0,
                revocation_secret,
                redeemscript,
                amount_sat,
                wallet_path,
            })
        })
        .expect("sweep parts")
}

/// T1: the reuse property, pinned. Era-A num-0 and era-B num-0 share the
/// per-commitment point AND secret (BOLT-3 per-number derivation meets
/// per-era numbering restart). If this ever fails, the derivation became
/// per-era and the whole EC-4b adjudication changes.
#[test]
fn rail_era_num0_point_and_secret_reuse_is_pinned() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

    // Advance era A past num-0 (validate num-1) so num-0's secret is
    // legitimately revealable — the threat model's premise.
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = crate::util::test_utils::channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = crate::util::test_utils::counterparty_sign_holder_commitment(
        &node_ctx, &chan_ctx, &mut ctx1,
    );
    crate::util::test_utils::validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let (point_a, secret_a) = node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            Ok((
                chan.get_per_commitment_point(0)?,
                chan.get_per_commitment_secret(0)?,
            ))
        })
        .expect("era-A num-0 material");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    let (point_b, secret_b) = node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            Ok((
                chan.get_per_commitment_point(0)?,
                chan.get_per_commitment_secret(0)?,
            ))
        })
        .expect("era-B num-0 material");

    assert_eq!(point_a, point_b, "era-B num-0 point must equal era-A num-0 point (derivation reuse)");
    assert_eq!(
        secret_a.secret_bytes(),
        secret_b.secret_bytes(),
        "era-B num-0 secret must equal era-A num-0 secret"
    );
}

/// T2: EMPIRICAL PIN of the exposure. Post-splice, era-B num-0 is
/// current and unrevoked; the sweep presents the era-A secret
/// (byte-identical to era-B's by derivation). The signer signs — there
/// is no era, number, or revocation-state gate in sign_justice_sweep.
/// This rail PINS current behavior so any change to it is deliberate.
#[test]
fn rail_justice_sweep_signs_with_cross_era_secret_today() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

    // Advance era A past num-0 (validate num-1) so num-0's secret is
    // legitimately revealable — the threat model's premise.
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = crate::util::test_utils::channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = crate::util::test_utils::counterparty_sign_holder_commitment(
        &node_ctx, &chan_ctx, &mut ctx1,
    );
    crate::util::test_utils::validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let era_a_secret = node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.get_per_commitment_secret(0)
        })
        .expect("era-A num-0 secret");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    let parts = build_num0_justice_sweep(&node_ctx, &chan_ctx, era_a_secret);
    let res = node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
        chan.sign_justice_sweep(
            &parts.tx,
            parts.input,
            &parts.revocation_secret,
            &parts.redeemscript,
            parts.amount_sat,
            &parts.wallet_path,
        )
    });
    assert!(
        res.is_ok(),
        "EMPIRICAL PIN: the signer signs the cross-era secret sweep today: {:?}",
        res.err()
    );
}

/// T3: the SAFE target, documented-RED. Un-ignore when (and only when)
/// the fork carries a conservative ambiguity gate: a num-0-shaped
/// justice sweep must be REFUSED while the CURRENT era's num-0 is
/// unrevoked and a prior funding era exists (the secret may have been
/// legitimately revealed in the prior era — BOLT-3 per-number derivation
/// + per-era numbering restart + unchanged basepoints make the revocation
/// keys identical, so possession no longer proves revocation for the
/// current era). Cost of the gate: a legit prev-era num-0 straggler
/// justice sweep post-splice would also refuse — the owner's call
/// whether the fork carries that defense or the exposure is filed at
/// spec level.
#[test]
#[ignore = "EC-4b design fork: cross-era secret reuse makes possession-proofs ambiguous for num-0 post-splice; refusal gate pending owner ruling"]
fn rail_justice_sweep_current_era_unrevoked_should_refuse() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

    // Advance era A past num-0 (validate num-1) so num-0's secret is
    // legitimately revealable — the threat model's premise.
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = crate::util::test_utils::channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = crate::util::test_utils::counterparty_sign_holder_commitment(
        &node_ctx, &chan_ctx, &mut ctx1,
    );
    crate::util::test_utils::validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let era_a_secret = node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.get_per_commitment_secret(0)
        })
        .expect("era-A num-0 secret");

    let _outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    let parts = build_num0_justice_sweep(&node_ctx, &chan_ctx, era_a_secret);
    let res = node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
        chan.sign_justice_sweep(
            &parts.tx,
            parts.input,
            &parts.revocation_secret,
            &parts.redeemscript,
            parts.amount_sat,
            &parts.wallet_path,
        )
    });
    assert!(
        res.is_err(),
        "num-0 justice sweep with a cross-era-revealable secret, current era unrevoked: must refuse"
    );
}

/// T4: control — the identical construction BEFORE any splice signs,
/// proving the fixtures build valid sweeps (the pins above are about
/// cross-era semantics, not broken constructions).
#[test]
fn rail_same_num0_era_a_justice_control() {
    let node_ctx = test_node_ctx(1);
    let chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

    // Advance era A past num-0 (validate num-1) so num-0's secret is
    // legitimately revealable — the threat model's premise.
    let channel_value = chan_ctx.setup.channel_value_sat;
    let mut ctx1 = crate::util::test_utils::channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        channel_value - 3755,
        0,
        vec![],
        vec![],
    );
    let (sig1, hsig1) = crate::util::test_utils::counterparty_sign_holder_commitment(
        &node_ctx, &chan_ctx, &mut ctx1,
    );
    crate::util::test_utils::validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsig1)
        .expect("era-A num-1 holder commitment validates");

    let secret = node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.get_per_commitment_secret(0)
        })
        .expect("num-0 secret");

    let parts = build_num0_justice_sweep(&node_ctx, &chan_ctx, secret);
    let res = node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
        chan.sign_justice_sweep(
            &parts.tx,
            parts.input,
            &parts.revocation_secret,
            &parts.redeemscript,
            parts.amount_sat,
            &parts.wallet_path,
        )
    });
    assert!(res.is_ok(), "same-era control sweep must sign: {:?}", res.err());
}
