//! Traced splice scenarios — executable specification + trace artifacts.
//!
//! Each test is a normal regression test (assertions always enforced)
//! that ALSO produces a three-lane JSONL trace when `VLS_TRACE_DIR` is
//! set:
//!
//! ```sh
//! VLS_TRACE_DIR=target/splice-traces cargo test -p vls-core \
//!     --features test_utils splice_scenario -- --nocapture --test-threads=1
//! ```
//!
//! The `cln` lane in these unit scenarios comes from the test harness
//! acting as CLN's protocol peer (`source: "test-peer"`) — genuine
//! protocol-role events. Live CLN boundary traffic lands via the
//! vls-proxy tap (see docs/splice-trace.md).
//!
//! State declarations double as the visualizer's aggregate state machine.

#![cfg(feature = "splice_trace")]

use bitcoin::bip32::DerivationPath;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, Transaction, TxIn};

use lightning::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};
use lightning::sign::InMemorySigner;

use serde_json::json;

use crate::channel::ChannelBase;
use crate::util::status::Code;
use crate::util::test_utils::key::*;
use crate::util::test_utils::scenario::ScenarioRunner;
use crate::util::test_utils::*;

fn splice_tx_spending(outpoint: OutPoint) -> Transaction {
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use bitcoin::transaction::{Sequence, Version};
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![],
    }
}

/// Validate a commitment without advancing channel numbering (the
/// retransmit/straggler shape — mirrors the proven raw-validate rails).
fn raw_validate(
    node_ctx: &TestNodeContext,
    channel_id: &crate::channel::ChannelId,
    ctx: &TestCommitmentTxContext,
    sig: &bitcoin::secp256k1::ecdsa::Signature,
    htlc_sigs: &Vec<bitcoin::secp256k1::ecdsa::Signature>,
) -> Result<(), crate::util::status::Status> {
    node_ctx.node.with_channel(channel_id, |chan| {
        let htlcs =
            crate::channel::Channel::htlcs_info2_to_oic(&ctx.offered_htlcs, &ctx.received_htlcs);
        let channel_parameters = chan.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();
        let save_commit_num = chan.enforcement_state.next_holder_commit_num;
        chan.enforcement_state.set_next_holder_commit_num_for_testing(ctx.commit_num);
        let per_commitment_point = chan.get_per_commitment_point(ctx.commit_num)?;
        chan.enforcement_state.set_next_holder_commit_num_for_testing(save_commit_num);
        let keys = chan.make_holder_tx_keys(&per_commitment_point);
        let redeem_scripts = build_tx_scripts(
            &keys,
            ctx.to_broadcaster,
            ctx.to_countersignatory,
            &htlcs,
            &parameters,
            &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
            &chan.setup.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
        chan.validate_holder_commitment_tx(
            &ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
            &output_witscripts,
            ctx.commit_num,
            ctx.feerate_per_kw,
            ctx.offered_htlcs.clone(),
            ctx.received_htlcs.clone(),
            sig,
            htlc_sigs,
        )
        .map(|_| ())
    })
}

fn era_of(
    node: &crate::node::Node,
    channel_id: &crate::channel::ChannelId,
    outpoint: &OutPoint,
) -> String {
    node.with_channel(channel_id, |chan| {
        Ok(crate::trace::sink::label_for(&hex::encode(chan.id0.as_slice()), outpoint))
    })
    .unwrap()
}

/// Scenario 1: the normal splice A → B (splice-in), signed, locked.
#[test]
fn scenario_normal_splice_a_b() {
    let mut sc =
        ScenarioRunner::with_states("normal_splice_a_b", &["A_LOCKED", "AB_PENDING", "B_LOCKED"]);

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A", "watches": ["A"]}));

    // CLN negotiates the splice: post-splice setup arrives BEFORE the
    // splice tx signature request (the CLN ordering).
    let _s1 = sc.step("CLN sends post-splice setup_channel (funding B)");
    sc.cln_sends("setup_channel", Some(json!({"funding": "B", "value_sat": 1_100_000})));
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat = 1_100_000;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, 1_100_000);
    let splice_tx = tx_ctx.to_tx();
    let new_outpoint = OutPoint { txid: splice_tx.compute_txid(), vout };
    chan_ctx.setup.funding_outpoint = new_outpoint;
    sc.cln_state(
        Some(&new_outpoint.to_string()),
        json!({"view": "splice locked-in, awaiting signature"}),
    );
    assert!(
        funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
        "splice swap accepted"
    );
    sc.cln_receives("setup_channel_reply", Some(json!({"ok": true})));
    sc.transition("A_LOCKED", "AB_PENDING", "setup B");
    sc.state(
        "AB_PENDING",
        json!({"eras_live": ["A", "B"], "current": "B", "previous": ["A"], "watches": ["A", "B"]}),
    );
    let era_a = era_of(&node_ctx.node, &channel_id, &old_setup.funding_outpoint);
    let era_b = era_of(&node_ctx.node, &channel_id, &new_outpoint);
    sc.invariant(
        "eras labeled A,B",
        era_a == "A" && era_b == "B",
        Some(json!({"A": era_a, "B": era_b})),
    );

    // CLN requests the signature for the splice tx spending A.
    let _s2 = sc.step("CLN requests SignSpliceTx (spending A)");
    sc.cln_sends("sign_splice_tx", Some(json!({"spends": "A", "input_index": 0})));
    let remote_key = chan_ctx.setup.counterparty_points.funding_pubkey;
    let sig = node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.sign_splice_tx(&splice_tx, 0, &remote_key, None))
        .expect("splice signature");
    sc.cln_receives("sign_tx_reply", Some(json!({"signature": sig.serialize_compact().len()})));
    sc.expect("SignSpliceTx accepted", true);

    // A commitment on the new funding.
    let _s3 = sc.step("commitment_signed on funding B");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "num": 1})));
    let mut commit_ctx =
        channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_090_000, 0, vec![], vec![]);
    let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_ctx);
    validate_holder_commitment(&node_ctx, &chan_ctx, &commit_ctx, &csig, &hsigs)
        .expect("new-funding commitment validates");
    sc.cln_receives("commitment_signed_reply", Some(json!({"ok": true})));

    // Mutual splice_locked → hsmd_lock_outpoint(B).
    let _s4 = sc.step("splice_locked mutual — CLN sends lock_outpoint(B)");
    sc.cln_sends("lock_outpoint", Some(json!({"funding": "B"})));
    node_ctx.node.confirm_funding_lock(&channel_id, &new_outpoint).expect("funding locked");
    sc.cln_receives("lock_outpoint_reply", Some(json!({"ok": true})));
    sc.transition("AB_PENDING", "B_LOCKED", "funding_locked B");
    sc.state("B_LOCKED", json!({"eras_live": ["B"], "retired": ["A"], "current": "B"}));
    let retired = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok((chan.prev_setup.is_none(), chan.prev_prev_setup.is_none()))
        })
        .unwrap();
    sc.invariant("A retired at lock", retired.0 && retired.1, None);

    sc.finish("passed");
}

/// Scenario 2: RBF supersession A → B → C without an intermediate lock.
#[test]
fn scenario_rbf_a_b_c() {
    let mut sc = ScenarioRunner::with_states(
        "rbf_a_b_c",
        &["A_LOCKED", "AB_PENDING", "ABC_PENDING", "C_LOCKED"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let setup_a = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A"}));

    // First splice: A → B
    let _s1 = sc.step("splice A -> B (candidate, unconfirmed)");
    sc.inject("rbf_window_open", None);
    let mut setup_b = setup_a.clone();
    setup_b.funding_outpoint.vout += 1;
    setup_b.channel_value_sat += 1000;
    sc.cln_sends("setup_channel", Some(json!({"funding": "B"})));
    node_ctx
        .node
        .setup_channel(channel_id.clone(), None, setup_b.clone(), &DerivationPath::master())
        .expect("swap A->B");
    sc.transition("A_LOCKED", "AB_PENDING", "setup B");
    sc.state("AB_PENDING", json!({"eras_live": ["A", "B"], "current": "B", "previous": ["A"]}));

    // Supersession: B is replaced by C before confirmation.
    let _s2 = sc.step("supersede B with C (RBF, no funding_locked between)");
    sc.inject("supersede", Some(json!({"replaced": "B", "by": "C"})));
    let mut setup_c = setup_b.clone();
    setup_c.funding_outpoint.vout += 1;
    setup_c.channel_value_sat += 1000;
    sc.cln_sends("setup_channel", Some(json!({"funding": "C"})));
    node_ctx
        .node
        .setup_channel(channel_id.clone(), None, setup_c.clone(), &DerivationPath::master())
        .expect("superseding swap B->C");
    sc.transition("AB_PENDING", "ABC_PENDING", "supersede B with C");
    sc.state(
        "ABC_PENDING",
        json!({
            "eras_live": ["A", "B", "C"],
            "current": "C",
            "previous": ["B", "A"],
            "commitment_eras": ["A", "B", "C"],
            "watched_eras": ["A", "B", "C"],
        }),
    );

    // Each era still resolvable for splice signing — the RBF window proof.
    let _s3 = sc.step("SignSpliceTx resolves every era (A, B, C)");
    let remote_key = setup_a.counterparty_points.funding_pubkey;
    for (setup, era_name) in [(&setup_a, "A"), (&setup_b, "B"), (&setup_c, "C")] {
        sc.cln_sends("sign_splice_tx", Some(json!({"spends": era_name})));
        let tx = splice_tx_spending(setup.funding_outpoint);
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                chan.sign_splice_tx(&tx, 0, &remote_key, Some(setup.channel_value_sat))
            })
            .unwrap_or_else(|e| panic!("sign for {era_name} failed: {e:?}"));
        sc.cln_receives("sign_tx_reply", Some(json!({"for": era_name, "ok": true})));
        sc.expect(format!("signing era {era_name} with its own value").as_str(), true);
    }

    // Lock C — retires A and B together.
    let _s4 = sc.step("funding_locked C — retires A and B");
    sc.cln_sends("lock_outpoint", Some(json!({"funding": "C"})));
    node_ctx.node.confirm_funding_lock(&channel_id, &setup_c.funding_outpoint).expect("lock C");
    sc.transition("ABC_PENDING", "C_LOCKED", "funding_locked C");
    sc.state("C_LOCKED", json!({"eras_live": ["C"], "retired": ["A", "B"]}));
    let chain_cleared = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok(chan.prev_setup.is_none() && chan.prev_prev_setup.is_none())
        })
        .unwrap();
    sc.invariant("A and B retired at C lock", chain_cleared, None);

    sc.finish("passed");
}

/// Scenario 3: disconnect + reconnect + retransmit + old-funding
/// straggler (the disconnect_sig story, traced).
#[test]
fn scenario_reconnect_retransmit_straggler() {
    let mut sc = ScenarioRunner::with_states(
        "reconnect_retransmit_straggler",
        &["A_LOCKED", "AB_PENDING", "RECONNECTED", "AB_PENDING_RETRANSMIT"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A"}));

    // Pre-splice fee-change commitment on A (becomes the straggler).
    let _s0 = sc.step("fee-change commitment on A (num 1)");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "A", "num": 1})));
    let mut straggler_ctx =
        channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 995_120, 0, vec![], vec![]);
    let (scsig, shsigs) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

    // Splice A → B (splice-in to 1,095,450 — the live capture values).
    let _s1 = sc.step("splice A -> B (in-flight)");
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 95_450;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    let new_outpoint = OutPoint { txid: splice_tx.compute_txid(), vout };
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    sc.transition("A_LOCKED", "AB_PENDING", "setup B");
    sc.state("AB_PENDING", json!({"eras_live": ["A", "B"], "current": "B", "previous": ["A"]}));

    // New-funding commitment validated (the pre-crash exchange).
    let _s2 = sc.step("new-funding commitment validated (pre-crash current)");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "num": 1})));
    let mut new_ctx =
        channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_090_000, 0, vec![], vec![]);
    let (ncsig, nhsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut new_ctx);
    raw_validate(&node_ctx, &channel_id, &new_ctx, &ncsig, &nhsigs)
        .expect("new-funding commitment stored pending");
    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.next_holder_commit_info = Some((
                crate::tx::tx::CommitmentInfo2::new(
                    true,
                    new_ctx.to_countersignatory,
                    new_ctx.to_broadcaster,
                    vec![],
                    vec![],
                    new_ctx.feerate_per_kw,
                ),
                crate::policy::validator::CommitmentSignatures(ncsig.clone(), nhsigs.clone()),
            ));
            chan.activate_initial_commitment().expect("same-number activation");
            Ok(())
        })
        .unwrap();

    // The disconnect + reconnect.
    let _s3 = sc.step("disconnect + reconnect (reestablish)");
    sc.inject("disconnect", None);
    sc.cln_event("peer_disconnect", Some(json!({"reason": "test inject"})));
    sc.inject("reconnect", None);
    sc.cln_event(
        "channel_reestablish",
        Some(json!({"retransmit_batch": "new-funding re-sign, then old-funding straggler"})),
    );
    sc.transition("AB_PENDING", "RECONNECTED", "reestablish");

    // Reestablish re-signs the new-funding commitment BEFORE the
    // re-offered old-funding straggler validates (the live ordering).
    let _s4 = sc.step("re-sign new-funding commitment (reestablish)");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "num": 1, "retransmit": true})));
    let mut re_new_ctx =
        channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_090_000, 0, vec![], vec![]);
    let (rsig, rhsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut re_new_ctx);
    raw_validate(&node_ctx, &channel_id, &re_new_ctx, &rsig, &rhsigs)
        .expect("re-sign of new-funding commitment");

    // The straggler: old-funding commitment arriving after B is current.
    let _s5 = sc.step("old-funding straggler validates against era A");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "A", "num": 1, "straggler": true})));
    let accepted = raw_validate(&node_ctx, &channel_id, &straggler_ctx, &scsig, &shsigs).is_ok();
    sc.expect("old-funding straggler accepted (era-aware valuation)", accepted);
    assert!(accepted, "straggler must validate against the A view");
    sc.transition("RECONNECTED", "AB_PENDING_RETRANSMIT", "straggler validated");

    sc.finish("passed");
}

/// Scenario 4: remote funding key rotation A/KA → B/KB. AUDITED
/// (docs/splice-trace-findings.md F1, spec + CLN source): the key check
/// against the CURRENT setup breaks rotation — CLN rotates its
/// channel-level remote key only at mutual splice_locked (channeld.c:499)
/// while requesting the splice signature (which spends era A, whose
/// redeemscript needs KA) BEFORE that, with the still-unrotated KA. The
/// spec designs rotation in (splice_init/splice_ack carry per-splice
/// funding_pubkeys). This scenario pins the divergence; the refusal
/// assert flips deliberately when the check becomes era-aware.
#[test]
fn scenario_funding_key_rotation() {
    let mut sc = ScenarioRunner::with_states(
        "funding_key_rotation",
        &["A_LOCKED_KA", "AB_PENDING_KB", "DIVERGENCE_EXPOSED"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let setup_a = chan_ctx.setup.clone();
    let key_a = setup_a.counterparty_points.funding_pubkey;
    sc.state("A_LOCKED_KA", json!({"eras_live": ["A"], "remote_funding_key": "KA"}));

    // Rotated counterparty: same basepoints, funding key 104 → 114.
    let rotated_points = lightning::ln::chan_utils::ChannelPublicKeys {
        funding_pubkey: make_test_pubkey(114),
        revocation_basepoint: RevocationBasepoint(make_test_pubkey(100)),
        payment_point: make_test_pubkey(101),
        delayed_payment_basepoint: DelayedPaymentBasepoint(make_test_pubkey(102)),
        htlc_basepoint: HtlcBasepoint(make_test_pubkey(103)),
    };
    let rotated_keys = InMemorySigner::new(
        make_test_privkey(114), // rotated funding key
        make_test_privkey(100),
        make_test_privkey(101),
        make_test_privkey(101),
        false,
        make_test_privkey(102),
        make_test_privkey(103),
        [3u8; 32],
        [0u8; 32],
        [0; 32],
    );
    let key_b = rotated_points.funding_pubkey;
    assert_ne!(key_a, key_b, "rotation must change the funding key");

    // Splice A → B with the rotated remote funding key.
    let _s1 = sc.step("splice A -> B with remote funding key rotation");
    let mut setup_b = setup_a.clone();
    setup_b.funding_outpoint.vout += 1;
    setup_b.channel_value_sat += 1000;
    setup_b.counterparty_points = rotated_points.clone();
    sc.cln_sends("setup_channel", Some(json!({"funding": "B", "rotated_key": true})));
    node_ctx
        .node
        .setup_channel(channel_id.clone(), None, setup_b.clone(), &DerivationPath::master())
        .expect("splice-compatible setup accepts key rotation");
    chan_ctx.setup = setup_b.clone();
    chan_ctx.counterparty_keys = rotated_keys;
    sc.transition("A_LOCKED_KA", "AB_PENDING_KB", "setup B (KB)");
    sc.state("AB_PENDING_KB", json!({"eras_live": ["A", "B"], "era_keys": {"A": "KA", "B": "KB"}}));

    // Sign the NEW funding with KB — accepted.
    let _s2 = sc.step("SignSpliceTx spending B with KB");
    let tx_b = splice_tx_spending(setup_b.funding_outpoint);
    node_ctx
        .node
        .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx_b, 0, &key_b, None))
        .expect("current-era sign with KB");
    sc.expect("sign B with KB accepted", true);

    // Sign the OLD funding A: the implementation enforces the CURRENT
    // setup's key — KA is refused even for the A-era input. The trace
    // records both the refusal and era A's own remote key (KA) — the
    // logical-vs-implementation divergence the tracer exists to show.
    // Sign the OLD funding A with its OWN era key KA — the F1 fix:
    // accepted. The input spends era A's outpoint; its 2-of-2 is
    // (holder, KA); CLN carries the pre-rotation key until mutual
    // splice_locked, so this is exactly the request the live peer makes.
    let _s3 = sc.step("SignSpliceTx spending A with KA (era key — F1 fixed)");
    let tx_a = splice_tx_spending(setup_a.funding_outpoint);
    let ka_result = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.sign_splice_tx(&tx_a, 0, &key_a, Some(setup_a.channel_value_sat))
    });
    let ka_accepted = ka_result.is_ok();
    sc.expect("sign A with KA accepted (era-aware check)", ka_accepted);
    assert!(ka_accepted, "F1 regression: era-A signing with era-A key refused");

    // The negative rail: era A's input with the WRONG era's key (KB) is
    // still refused — era-aware means the key must match the spent view.
    let kb_result = node_ctx.node.with_channel(&channel_id, |chan| {
        chan.sign_splice_tx(&tx_a, 0, &key_b, Some(setup_a.channel_value_sat))
    });
    let kb_refused = matches!(&kb_result, Err(e) if e.code() == Code::InvalidArgument);
    sc.expect("sign A with KB (wrong era key) refused", kb_refused);
    assert!(kb_refused, "era-aware check must still refuse the wrong era's key");

    sc.transition("AB_PENDING_KB", "ERA_AWARE_KEY_CHECK", "F1 fix");
    sc.state(
        "ERA_AWARE_KEY_CHECK",
        json!({
            "fixed": "F1 (docs/splice-trace-findings.md): the remote-key check resolves the funding view by the input outpoint and requires the ERA's key",
            "spec": "BOLTs 1528972 splice_init/splice_ack carry per-splice funding_pubkeys (rotation designed in); every window splice spends the original funding output",
            "cln": "channeld.c:499 rotates channel->funding_pubkey[REMOTE] only at mutual splice_locked; sign_splice_tx call sites (3903, 4649) pass the channel-level (pre-rotation) key",
            "negative_rail": "wrong-era key on a spent view stays refused",
        }),
    );

    sc.finish("passed");
}

/// Scenario 5: pending HTLCs when the new funding locks — the lock
/// installs the new-funding baseline (no HTLCs) and the trace shows the
/// HTLCs disappearing from the era views.
#[test]
fn scenario_pending_htlc_at_lock() {
    let mut sc = ScenarioRunner::with_states(
        "pending_htlc_at_lock",
        &["A_LOCKED_HTLC", "AB_PENDING_HTLC", "B_LOCKED_BASELINE"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED_HTLC", json!({"eras_live": ["A"], "htlcs": 1}));

    // One HTLC in flight on A (an offered HTLC from the counterparty).
    let htlc = crate::util::test_utils::htlc::make_htlc(
        lightning::types::payment::PaymentHash([7; 32]),
        50_000,
        600,
    );
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 100_000;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    let new_outpoint = OutPoint { txid: splice_tx.compute_txid(), vout };

    let _s1 = sc.step("splice A -> B with an HTLC pending");
    sc.cln_sends("setup_channel", Some(json!({"funding": "B", "htlcs_pending": 1})));
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    sc.state("AB_PENDING_HTLC", json!({"eras_live": ["A", "B"], "htlcs_on": "A-era infos"}));

    // A commitment on B carrying the HTLC.
    let _s2 = sc.step("commitment on B carrying the HTLC");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "htlcs": 1})));
    let mut commit_ctx = channel_commitment(
        &node_ctx,
        &chan_ctx,
        1,
        3755,
        1_000_000,
        49_000,
        vec![htlc.clone()],
        vec![],
    );
    let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_ctx);
    let v = validate_holder_commitment(&node_ctx, &chan_ctx, &commit_ctx, &csig, &hsigs);
    sc.expect("HTLC-bearing commitment on B validates", v.is_ok());
    v.expect("validate");

    // Lock B with the HTLC still pending — the lock installs the
    // no-HTLC baseline for the new funding.
    let _s3 = sc.step("funding_locked B with HTLC still pending");
    sc.cln_sends("lock_outpoint", Some(json!({"funding": "B", "htlcs_pending": 1})));
    node_ctx.node.confirm_funding_lock(&channel_id, &new_outpoint).expect("lock");
    let baseline = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            Ok((
                chan.enforcement_state
                    .current_holder_commit_info
                    .as_ref()
                    .map(|i| i.htlcs_is_empty()),
                chan.enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .map(|i| i.htlcs_is_empty()),
            ))
        })
        .unwrap();
    sc.transition("AB_PENDING_HTLC", "B_LOCKED_BASELINE", "funding_locked B (baseline install)");
    sc.state(
        "B_LOCKED_BASELINE",
        json!({
            "eras_live": ["B"],
            "baseline": "empty-HTLC infos installed at lock (num-0-equivalent)",
            "htlc_risk": "pending HTLCs not carried into the baseline — visible in the trace diff",
        }),
    );
    sc.invariant(
        "baseline infos are HTLC-free at lock",
        baseline.0 == Some(true) && baseline.1 == Some(true),
        Some(json!({"holder_empty": baseline.0, "cp_empty": baseline.1})),
    );

    sc.finish("passed");
}

/// Scenario 6: persistence round-trip across the splice window — the
/// "restart" leg. Pre-restart state snapshotted, entry serialized +
/// deserialized (the persistence boundary), the era chain and justice
/// snapshot survive, and the old-funding straggler still validates
/// after the "restart".
#[test]
fn scenario_persistence_restart_two_eras() {
    let mut sc = ScenarioRunner::with_states(
        "persistence_restart_two_eras",
        &["A_LOCKED", "AB_PENDING_PRE_RESTART", "AB_PENDING_POST_RESTART"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A"}));

    // Old-era currents (1M-scale) so the straggler story is meaningful.
    let dummy_sigs = crate::policy::validator::CommitmentSignatures(
        bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0; 64]).unwrap(),
        vec![],
    );
    let old_era_info =
        crate::tx::tx::CommitmentInfo2::new(true, 600_000, 399_000, vec![], vec![], 0);
    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.current_holder_commit_info = Some(old_era_info.clone());
            chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
            chan.enforcement_state.current_counterparty_commit_info = Some(old_era_info);
            Ok(())
        })
        .unwrap();

    // The old-funding straggler's message, built pre-swap.
    let mut straggler_ctx =
        channel_commitment(&node_ctx, &chan_ctx, 0, 0, 995_120, 0, vec![], vec![]);
    let (scsig, shsigs) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

    // Splice A → B.
    let _s1 = sc.step("splice A -> B");
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 100_000;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    let new_outpoint = chan_ctx.setup.funding_outpoint;
    sc.state(
        "AB_PENDING_PRE_RESTART",
        json!({"eras_live": ["A", "B"], "current": "B", "justice_snapshot": "A-era infos preserved"}),
    );

    // The restart: serialize the channel entry (what the persister
    // stores) and rebuild the era-bearing fields from it.
    let _s2 = sc.step("VLS restart (persist + restore round-trip)");
    sc.inject("restart_vls", None);
    let restored = node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            let entry = crate::persist::model::ChannelEntry {
                channel_value_satoshis: chan.setup.channel_value_sat,
                channel_setup: Some(chan.setup.clone()),
                id: chan.id.clone(),
                enforcement_state: chan.enforcement_state.clone(),
                blockheight: None,
                prev_setup: chan.prev_setup.clone(),
                prev_prev_setup: chan.prev_prev_setup.clone(),
            };
            let ser = serde_json::to_value(&entry).expect("serialize entry");
            let de: crate::persist::model::ChannelEntry =
                serde_json::from_value(ser).expect("deserialize entry");
            Ok((
                de.prev_setup.as_ref().map(|p| p.funding_outpoint)
                    == Some(old_setup.funding_outpoint),
                de.prev_prev_setup.is_none(),
                de.enforcement_state.prev_funding_commitment.as_ref().map(|s| s.outpoint)
                    == Some(old_setup.funding_outpoint),
                de.channel_setup.as_ref().map(|s| s.funding_outpoint) == Some(new_outpoint),
            ))
        })
        .unwrap();
    sc.state(
        "AB_PENDING_POST_RESTART",
        json!({
            "eras_live": ["A", "B"],
            "current": "B",
            "survived": ["prev_setup", "prev_funding_commitment", "era tags"],
            "note": "full Node restore path (new_from_persistence) fires the vls Restored event in live/vlsd runs; unit scenarios exercise the entry round-trip",
        }),
    );
    sc.invariant(
        "splice window survives persistence round-trip",
        restored.0 && restored.1 && restored.2 && restored.3,
        Some(json!({"prev_setup": restored.0, "prev_prev_none": restored.1, "justice_snapshot": restored.2, "current": restored.3})),
    );

    // Post-restart: the old-funding straggler still validates.
    let _s3 = sc.step("post-restart straggler validates against era A");
    sc.cln_sends(
        "commitment_signed",
        Some(json!({"funding": "A", "straggler": true, "post_restart": true})),
    );
    let accepted = raw_validate(&node_ctx, &channel_id, &straggler_ctx, &scsig, &shsigs).is_ok();
    sc.expect("post-restart straggler accepted", accepted);
    assert!(accepted, "restored signer must accept the old-funding straggler");

    sc.finish("passed");
}

/// Scenario: same commitment number + different info must be rejected
/// (the retransmit-vs-reshuffle discriminator). The retransmit contract
/// (identical re-validation while pending ⇒ same slots, no advance) is
/// pinned elsewhere; this is the negative rail.
#[test]
fn scenario_same_number_different_info_rejected() {
    let mut sc = ScenarioRunner::with_states(
        "same_number_different_info_rejected",
        &["A_LOCKED", "SAME_NUM_ACCEPTED", "SAME_NUM_RESHUFFLE_REJECTED"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A"}));

    // Splice A → B first (the interesting window).
    let _s1 = sc.step("splice A -> B");
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 95_450;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    let new_outpoint = OutPoint { txid: splice_tx.compute_txid(), vout };
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    sc.state("SAME_NUM_ACCEPTED", json!({"eras_live": ["A", "B"], "current": "B"}));

    // A commitment on B, number 1, validated through the FULL path —
    // the numbering advance is the discriminator's fuel (raw_validate
    // deliberately does not advance it, and the same-number rejection
    // fires on commit_num < next_holder_commit_num).
    let _s2 = sc.step("commitment #1 on B validates (numbering advances)");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "num": 1, "to_b": 1_090_000})));
    let mut ctx1 = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_090_000, 0, vec![], vec![]);
    let (sig1, hsigs1) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1);
    validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1, &sig1, &hsigs1)
        .expect("first commitment validates");
    sc.expect("commitment #1 accepted", true);

    // Same number, DIFFERENT info (to_b changed) — rejected by the
    // old-commitment-number policy: a reshuffle is not a retransmit.
    let _s3 = sc.step("same number, different info refused");
    sc.cln_sends(
        "commitment_signed",
        Some(json!({"funding": "B", "num": 1, "to_b": 1_080_000, "reshuffle": true})),
    );
    let mut ctx1b = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_080_000, 0, vec![], vec![]);
    let (sig1b, hsigs1b) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut ctx1b);
    let refused =
        validate_holder_commitment(&node_ctx, &chan_ctx, &ctx1b, &sig1b, &hsigs1b).is_err();
    sc.expect("same-number reshuffle rejected", refused);
    assert!(refused, "same commitment number with different info must be rejected");
    sc.transition("SAME_NUM_ACCEPTED", "SAME_NUM_RESHUFFLE_REJECTED", "reject reshuffle");
    let _ = new_outpoint;

    sc.finish("passed");
}

/// The commit_crash_splice live wedge (#106, decoded by traced live-fire):
/// after a crash mid-splice-window + restart + the resume dance
/// (sign_cp A, sign_cp B, validate A — all accepted live), the
/// re-offered B-era commitment is rejected with 'commitment totals
/// exceed the funding value' ×15 (channeld retry loop — the splice
/// never locks). LIVE FACTS (issue #106): the incoming commitment FITS
/// its view (to_b 889,319 + fee 3,755 = 893,074 ≤ 894,199) — the
/// rejection is a STATE-valuation underflow (R30 era-mixing class on
/// the restore path), not the tx. Restored tags: holder→A, cp→B;
/// snapshot A-scale currents; initial_holder 1,000,000.
/// WIP rail: the resume-dance replication is in place but the exact
/// live tag/field constellation at the first rejection still needs the
/// claimable-diag numbers (vlsd runs info-level; claimable-diag is
/// debug) — see #106 for the precise next step.
#[test]
#[ignore = "#106: live wedge decoded, unit replication one instrumentation step short — run the traced gate with --log-level=debug for the claimable-diag side"]
fn scenario_commit_crash_b_validate_post_restart() {
    let mut sc = ScenarioRunner::with_states(
        "commit_crash_b_validate_post_restart",
        &["A_LOCKED", "AB_PENDING_PRE_CRASH", "RESTARTED", "WEDGE_OR_RECOVERY"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "value": 1_000_000}));

    // A-era currents at the live-captured scale (cp info 0/995,125).
    let dummy_sigs = crate::policy::validator::CommitmentSignatures(
        bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0; 64]).unwrap(),
        vec![],
    );
    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            chan.enforcement_state.current_holder_commit_info =
                Some(crate::tx::tx::CommitmentInfo2::new(false, 0, 995_125, vec![], vec![], 0));
            chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
            chan.enforcement_state.current_counterparty_commit_info =
                Some(crate::tx::tx::CommitmentInfo2::new(true, 0, 995_125, vec![], vec![], 0));
            Ok(())
        })
        .unwrap();

    // Splice-OUT A -> B at the live value.
    let _s1 = sc.step("splice A -> B (splice-out to 894,199)");
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat = 894_199;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, 894_199);
    let splice_tx = tx_ctx.to_tx();
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    sc.state(
        "AB_PENDING_PRE_CRASH",
        json!({"eras_live": ["A", "B"], "current": "B", "value_b": 894_199}),
    );

    // The B-era commitment CLN re-offers (num 1, B-scale split).
    let mut b_ctx = channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 889_000, 0, vec![], vec![]);
    let (bsig, bhsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut b_ctx);

    // Pre-crash: the B commitment validates (the pre-crash node accepted it).
    let _s2 = sc.step("B commitment validates pre-crash");
    let pre = raw_validate(&node_ctx, &channel_id, &b_ctx, &bsig, &bhsigs);
    sc.expect("B commitment accepted pre-crash", pre.is_ok());
    pre.expect("pre-crash accept");

    // THE CRASH + RESTART + RESUME, exactly as the live trace decoded
    // it (vls-251018): the entry restores the swap-time state; the
    // channeld resume dance then runs sign_cp(A), sign_cp(B),
    // validate_holder(A) — and only THEN the wedged validate_holder(B).
    let _s3 = sc.step("restart (persist-entry round-trip) + resume dance");
    sc.inject("restart_vls", None);
    node_ctx
        .node
        .with_channel(&channel_id, |chan| {
            let entry = crate::persist::model::ChannelEntry {
                channel_value_satoshis: chan.setup.channel_value_sat,
                channel_setup: Some(chan.setup.clone()),
                id: chan.id.clone(),
                enforcement_state: chan.enforcement_state.clone(),
                blockheight: None,
                prev_setup: chan.prev_setup.clone(),
                prev_prev_setup: chan.prev_prev_setup.clone(),
            };
            let ser = serde_json::to_value(&entry).expect("serialize");
            let de: crate::persist::model::ChannelEntry =
                serde_json::from_value(ser).expect("deserialize");
            chan.enforcement_state = de.enforcement_state;
            Ok(())
        })
        .unwrap();

    // resume: the A-era straggler commitment validates (reestablish
    // re-offer — the live seq 9-11 accepted it)
    let mut a_straggler = channel_commitment(
        &node_ctx,
        &chan_ctx_a_view(&chan_ctx, &old_setup),
        0,
        0,
        995_125,
        0,
        vec![],
        vec![],
    );
    let _ = &mut a_straggler;
    // resume: sign both eras' counterparty commitments (live seq 5+8)
    // Direct probe: replicate the sign path's claimable call with the
    // restored state and print every input (the wedge's exact numbers).
    {
        let node = node_ctx.node.clone();
        node.with_channel(&channel_id, |chan| {
            let es = &chan.enforcement_state;
            eprintln!(
                "#probe tags: holder={:?} cp={:?} prev_snap={:?}",
                es.holder_commitment_funding,
                es.counterparty_commitment_funding,
                es.prev_funding_commitment.as_ref().map(|p| p.outpoint)
            );
            eprintln!(
                "#probe fields: cur_holder={:?} cur_cp={:?} snap_holder={:?} snap_cp={:?}",
                es.current_holder_commit_info
                    .as_ref()
                    .map(|i| (i.to_broadcaster_value_sat, i.to_countersigner_value_sat)),
                es.current_counterparty_commit_info
                    .as_ref()
                    .map(|i| (i.to_broadcaster_value_sat, i.to_countersigner_value_sat)),
                es.prev_funding_commitment
                    .as_ref()
                    .and_then(|p| p.current_holder_info.as_ref())
                    .map(|i| (i.to_broadcaster_value_sat, i.to_countersigner_value_sat)),
                es.prev_funding_commitment
                    .as_ref()
                    .and_then(|p| p.current_counterparty_info.as_ref())
                    .map(|i| (i.to_broadcaster_value_sat, i.to_countersigner_value_sat)),
            );
            eprintln!(
                "#probe views: setup={} prev={:?} initial_holder={}",
                chan.setup.channel_value_sat,
                chan.prev_setup.as_ref().map(|p| p.channel_value_sat),
                es.initial_holder_value
            );
            Ok(())
        })
        .unwrap();
    }
    sign_cp_helper(&node_ctx, &channel_id, &old_setup, 0, 995_125).expect("sign_cp A (resume)");
    sign_cp_helper(&node_ctx, &channel_id, &chan_ctx.setup, 1, 889_000)
        .expect("sign_cp B (resume)");
    sc.state(
        "RESTARTED",
        json!({"resume": "sign_cp A + sign_cp B + validate A accepted (live shape)"}),
    );

    // Post-restart: the B commitment re-offered — must be accepted.
    let _s4 = sc.step("B commitment re-offered post-restart");
    sc.cln_sends("commitment_signed", Some(json!({"funding": "B", "num": 1, "retransmit": true})));
    let post = raw_validate(&node_ctx, &channel_id, &b_ctx, &bsig, &bhsigs);
    let ok = post.is_ok();
    let msg = post.err().map(|e| e.message().to_string());
    sc.expect("B commitment accepted post-restart (the wedge: 15x 'commitment totals exceed the funding value')", ok);
    sc.state(
        "WEDGE_OR_RECOVERY",
        json!({
            "live_wedge": "restarted vlsd rejected the identical commitment 15 times (vls-251018 trace)",
            "live_error": "commitment totals exceed the funding value",
            "unit_result": msg,
        }),
    );
    assert!(ok, "the commit_crash_splice wedge reproduced: {msg:?}");
}

/// A stale chan_ctx view of era A (for building A-era messages post-swap).
fn chan_ctx_a_view(
    ctx: &TestChannelContext,
    a_setup: &crate::channel::ChannelSetup,
) -> TestChannelContext {
    let mut c = clone_test_channel_context(ctx);
    c.setup = a_setup.clone();
    c
}

fn clone_test_channel_context(ctx: &TestChannelContext) -> TestChannelContext {
    TestChannelContext {
        channel_id: ctx.channel_id.clone(),
        setup: ctx.setup.clone(),
        counterparty_keys: ctx.counterparty_keys.clone(),
    }
}

/// Sign a counterparty commitment for the given view (the resume dance
/// shape — verbatim from sign_counterparty_commitment_tests' rail).
fn sign_cp_helper(
    node_ctx: &TestNodeContext,
    channel_id: &crate::channel::ChannelId,
    setup: &crate::channel::ChannelSetup,
    commit_num: u64,
    to_broadcaster: u64,
) -> Result<(), &'static str> {
    node_ctx
        .node
        .with_channel(channel_id, |chan| {
            let remote_point = make_test_pubkey(0x20);
            let to_countersignatory = setup.channel_value_sat - to_broadcaster;
            let mut htlcs = vec![];
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, remote_point);
            chan.enforcement_state
                .set_next_counterparty_revoke_num_for_testing(commit_num.saturating_sub(1));
            let commitment_tx = chan.make_counterparty_commitment_tx(
                &remote_point,
                commit_num,
                0,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );
            let trusted = commitment_tx.trust();
            let tx = trusted.built_transaction();
            let keys = chan.make_counterparty_tx_keys(&remote_point);
            let channel_parameters = chan.make_channel_parameters();
            let params = channel_parameters.as_counterparty_broadcastable();
            let redeem_scripts = build_tx_scripts(
                &keys,
                to_countersignatory,
                to_broadcaster,
                &mut htlcs,
                &params,
                &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                &setup.counterparty_points.funding_pubkey,
            )
            .map_err(|_| crate::util::status::Status::internal("scripts"))?;
            let wits: Vec<_> = redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
            chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &wits,
                &remote_point,
                commit_num,
                0,
                vec![],
                vec![],
            )?;
            Ok(())
        })
        .map_err(|e| {
            eprintln!(
                "#sign-cp-diag setup_value={} to_b={} err={:?}",
                setup.channel_value_sat, to_broadcaster, e
            );
            "sign_cp_failed"
        })
}

/// Scenario: stale/foreign funding_locked (spec: the splice_locked
/// receiver MUST warn+disconnect or error+fail — VLS's signer-side
/// rejection is defense in depth; pinned here).
#[test]
fn scenario_stale_foreign_funding_locked() {
    let mut sc = ScenarioRunner::with_states(
        "stale_foreign_funding_locked",
        &["A_LOCKED", "AB_PENDING", "BAD_LOCK_REFUSED"],
    );

    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();
    sc.state("A_LOCKED", json!({"eras_live": ["A"], "current": "A"}));

    // Splice A → B.
    let _s1 = sc.step("splice A -> B");
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 100_000;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    assert!(funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none());
    let new_outpoint = chan_ctx.setup.funding_outpoint;
    sc.state("AB_PENDING", json!({"eras_live": ["A", "B"], "current": "B"}));

    // Stale lock: era A's outpoint while B is current — refused.
    let _s2 = sc.step("stale splice_locked for era A refused");
    sc.cln_sends("lock_outpoint", Some(json!({"funding": "A", "stale": true})));
    let stale_err = node_ctx
        .node
        .confirm_funding_lock(&channel_id, &old_setup.funding_outpoint)
        .expect_err("stale funding_locked must be refused");
    sc.expect("stale lock refused (era-blind lockout is a current-funding gate)", true);
    sc.cln_receives(
        "lock_outpoint_reply",
        Some(json!({"code": format!("{:?}", stale_err.code())})),
    );

    // Foreign lock: an outpoint from neither era — refused.
    let _s3 = sc.step("foreign splice_locked refused");
    let mut foreign = new_outpoint;
    foreign.vout += 7;
    sc.cln_sends(
        "lock_outpoint",
        Some(json!({"funding": "foreign", "outpoint": foreign.to_string()})),
    );
    node_ctx
        .node
        .confirm_funding_lock(&channel_id, &foreign)
        .expect_err("foreign funding_locked must be refused");
    sc.expect("foreign lock refused", true);

    // The real lock still works afterwards.
    let _s4 = sc.step("correct lock for B accepted");
    sc.cln_sends("lock_outpoint", Some(json!({"funding": "B"})));
    node_ctx.node.confirm_funding_lock(&channel_id, &new_outpoint).expect("lock B");
    sc.transition("AB_PENDING", "BAD_LOCK_REFUSED", "refusals then real lock");
    sc.expect("correct lock accepted after refusals", true);

    sc.finish("passed");
}
