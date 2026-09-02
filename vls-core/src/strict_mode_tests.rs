//! #94 strict-mode unit rails — the strict/permissive delta over the
//! splice-window view-shape enumeration.
//!
//! The 617-test unit suite never exercises the strict arm of the policy
//! filter in the sign paths that the strict ladder proved broken
//! (issue #94, evidence: lightning-playground
//! test-artifacts/vls-splice-gates-20260831/strict85-fails/DECODE.md).
//! These rails pin, in seconds, what the 55-213s gates proved live:
//!
//! - A: `sign_counterparty_commitment_tx` recomposes from the CURRENT
//!   funding view only (channel.rs `make_counterparty_commitment_tx` →
//!   `make_channel_parameters`), so a spec-legal commitment for a
//!   NON-current view (RBF-superseded candidate / reestablish re-sign)
//!   hard-rejects in strict with "recomposed tx mismatch" — while
//!   permissive signs the host tx verbatim (the deployment default,
//!   which is why the soaks are green).
//! - B: `replace_funding_outpoint` updates the listener key and the
//!   funding txids but NOT `MonitorState.funding_outpoint` (the Option
//!   the push decoder matches inputs against, monitor.rs on_transaction_
//!   input) — so after a splice the decoder still gathers a spend of the
//!   RETIRING funding as a closing-tx candidate; a single-input spend
//!   (splice-OUT: the exiting funds are outputs, not wallet inputs — the
//!   multi-input discriminator cannot fire) classifies as a MUTUAL CLOSE
//!   at confirmation depth, and `ensure_funding_buried_and_unspent`
//!   then rejects the NEW funding's commitment 1 with "closed
//!   on-chain" (live: splice_out + the slow gossip run — class B is
//!   block-depth/timing-dependent).
//! - D: the revoke-relative numbering gate
//!   (`num < next_counterparty_revoke_num + delta`) evaluates against
//!   channel-global counters, but BOLTs #1160 splice semantics
//!   legitimately re-present the same commitment number on the new
//!   funding right after the swap (live pair: num=2 vs revoke=1) —
//!   strict rejects it and the proxy retry-loop stalls the node.
//!
//! Rails that are RED today carry the fix contract; the mutated-tx and
//! plain-channel refusal rails must STAY RED through any carve-out
//! (the #94 guardrails).

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::{BlockHash, Transaction};
    use test_log::test;

    use lightning::ln::chan_utils::CommitmentTransaction;
    use lightning::types::payment::PaymentHash;

    use crate::channel::{Channel, ChannelBase, ChannelSetup};
    use crate::chain::tracker::ChainListener;
    use crate::node::{Node, SpendType};
    use crate::policy::onchain_validator::OnchainValidatorFactory;
    use crate::policy::simple_validator::SimpleValidatorFactory;
    use crate::util::INITIAL_COMMITMENT_NUMBER;
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;

    use std::sync::Arc;

    // The remote per-commitment point used for every rail commitment —
    // arbitrary but fixed, matching the numbering state we install.
    const REMOTE_POINT_NDX: u8 = 10;

    /// Build a counterparty-broadcastable commitment for an arbitrary
    /// funding VIEW (the static-test construction, routed through
    /// `make_channel_parameters_with_setup` so the tx belongs to the
    /// given view — current or retiring).
    fn view_counterparty_commitment(
        chan: &Channel,
        view: &ChannelSetup,
        commit_num: u64,
        feerate_per_kw: u32,
        to_broadcaster: u64,
        to_countersignatory: u64,
    ) -> (Transaction, Vec<Vec<u8>>) {
        let remote_point = make_test_pubkey(REMOTE_POINT_NDX);
        let channel_parameters = chan.make_channel_parameters_with_setup(view);
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let keys = chan.make_counterparty_tx_keys(&remote_point);
        let mut htlcs = vec![];

        let commitment_tx = CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commit_num,
            &remote_point,
            to_countersignatory,
            to_broadcaster,
            feerate_per_kw,
            htlcs.clone(),
            &parameters,
            &chan.secp_ctx,
        );

        let redeem_scripts = build_tx_scripts(
            &keys,
            to_countersignatory,
            to_broadcaster,
            &mut htlcs,
            &parameters,
            &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
            &view.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
        (commitment_tx.trust().built_transaction().transaction.clone(), output_witscripts)
    }

    /// Open a splice window on a funded test channel: a tx spending the
    /// current (retiring) funding and creating a new funding output of
    /// `new_value`, fed through `funding_tx_setup_channel` (which
    /// snapshots prev_setup and replaces the monitor's funding outpoint,
    /// node.rs setup_channel splice path). Single-input by default —
    /// the splice-OUT shape whose decode-time misclassification is
    /// class B.
    fn open_splice_window(
        node_ctx: &TestNodeContext,
        chan_ctx: &mut TestChannelContext,
        new_value: u64,
    ) -> Transaction {
        let old_setup = chan_ctx.setup.clone();
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat = new_value;
        let vout =
            tx_ctx.add_channel_outpoint(node_ctx, chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(node_ctx, chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );
        splice_tx
    }

    /// Enable the balance-enforcement rail of the default (strict) test
    /// policy — validate_payment_balance is a no-op when
    /// `enforce_balance` is false, which is the default testnet posture.
    fn strict_enable_balance(node: &Arc<Node>) {
        let mut policy = crate::policy::simple_validator::make_default_simple_policy(
            bitcoin::Network::Testnet,
        );
        policy.enforce_balance = true;
        *node.validator_factory.lock().unwrap() =
            Arc::new(crate::policy::simple_validator::SimpleValidatorFactory::new_with_policy(
                policy,
            ));
    }

    /// Install the OnchainValidator wrapper (strict filter inherited from
    /// the inner SimpleValidatorFactory) — the production shape whose
    /// `ensure_funding_buried_and_unspent` is class B's rejection site.
    /// The default test factory is bare SimpleValidator, which never
    /// runs the burial check.
    fn install_onchain_validator(node: &Arc<Node>) {
        *node.validator_factory.lock().unwrap() =
            Arc::new(OnchainValidatorFactory::new_with_simple_factory(
                SimpleValidatorFactory::new(),
            ));
    }

    // ------------------------------------------------------------------
    // Controls (must be GREEN today and after every fix)
    // ------------------------------------------------------------------

    /// Harness control: strict mode signs the honest CURRENT-view
    /// commitment. If this fails, the rail harness is wrong, not the
    /// code under test.
    #[test]
    fn strict_control_current_view_signs() {
        let node_ctx = test_node_ctx(1);
        let chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                5,
                make_test_pubkey(REMOTE_POINT_NDX),
            );
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(4);

            let view = chan.setup.clone();
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &view, 5, 0, 890_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                5,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("strict must sign the honest current-view commitment");
    }

    /// Window control: with a splice window OPEN, strict mode still
    /// signs the current (new funding) view's commitment — pins that
    /// the A-fix does not regress the simple splice window.
    #[test]
    fn strict_control_window_current_view_signs() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_095_450);
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            assert!(chan.prev_setup.is_some(), "splice window open");
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                5,
                make_test_pubkey(REMOTE_POINT_NDX),
            );
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(4);

            let view = chan.setup.clone();
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &view, 5, 0, 985_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                5,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("strict must sign the current-view commitment mid-window");
    }

    // ------------------------------------------------------------------
    // Class A rails (RED today — the fix contract)
    // ------------------------------------------------------------------

    /// A: a spec-legal commitment for the RETIRING funding view
    /// (RBF-superseded candidate / reestablish re-sign shape) must sign
    /// in strict mode via exact-match recomposition from the routed
    /// view. Today: `make_counterparty_commitment_tx` recomposes from
    /// the CURRENT view only → "recomposed tx mismatch" → strict
    /// reject (live: test_splice_rbf, commit_crash, disconnect_sig).
    #[test]
    fn strict_class_a_retiring_view_commitment_signs() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_095_450);
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            let view = chan.prev_setup.clone().expect("window open");
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                5,
                make_test_pubkey(REMOTE_POINT_NDX),
            );
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(4);

            let (tx, witscripts) =
                view_counterparty_commitment(chan, &view, 5, 0, 890_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                5,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("strict must sign the retiring-view commitment (exact-match from the routed view)");
    }

    /// A guardrail: a MUTATED tx that keeps the retiring view's input
    /// (bad output value) must STAY rejected in strict mode — the
    /// input-check variant was rejected by the mutated-tx rails; the
    /// exact-match recomposition is the security line and must not
    /// admit divergent transactions.
    #[test]
    fn strict_class_a_mutated_retiring_view_still_rejected() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_095_450);
        let channel_id = chan_ctx.channel_id.clone();

        let result = node_ctx.node.with_channel(&channel_id, |chan| {
            let view = chan.prev_setup.clone().expect("window open");
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                5,
                make_test_pubkey(REMOTE_POINT_NDX),
            );
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(4);

            let (mut tx, witscripts) =
                view_counterparty_commitment(chan, &view, 5, 0, 1_999_000, 1_000_000);
            // mutate: inflate the last output value (bad value keeps the
            // funding input valid — the exact shape the input-check
            // variant was rejected for)
            let last = tx.output.len() - 1;
            let bumped = tx.output[last].value + bitcoin::Amount::from_sat(1_000);
            tx.output[last].value = bumped;
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                5,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        });
        // The rejection SITE for mutated current-view txs is pinned by
        // the canonical bad_locktime/bad_sequence/bad_num_inputs rails
        // (sign_counterparty_commitment_tests) — those stay RED through
        // the A-fix. This rail's contract is narrower: a divergent
        // RETIRING-view tx must never be SIGNED, whatever the refusal
        // site (harness decode of mutated old-view txs is not stable
        // enough to pin one).
        assert!(
            result.is_err(),
            "mutated retiring-view tx must stay rejected in strict mode"
        );
    }

    /// Same as `view_counterparty_commitment` but carrying holder-OFFERED
    /// HTLCs in both the built tx and the witscripts (a forwarded HTLC —
    /// without the HTLC output in the recomposition inputs, the
    /// class-A mismatch would mask the class-C balance verdict).
    fn view_counterparty_commitment_forwarded(
        chan: &Channel,
        view: &ChannelSetup,
        commit_num: u64,
        feerate_per_kw: u32,
        to_broadcaster: u64,
        to_countersignatory: u64,
        received: Vec<crate::tx::tx::HTLCInfo2>,
    ) -> (Transaction, Vec<Vec<u8>>) {
        let remote_point = make_test_pubkey(REMOTE_POINT_NDX);
        let channel_parameters = chan.make_channel_parameters_with_setup(view);
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let keys = chan.make_counterparty_tx_keys(&remote_point);
        let htlcs = Channel::htlcs_info2_to_oic(&[], &received);

        let commitment_tx = CommitmentTransaction::new(
            INITIAL_COMMITMENT_NUMBER - commit_num,
            &remote_point,
            to_countersignatory,
            to_broadcaster,
            feerate_per_kw,
            htlcs.clone(),
            &parameters,
            &chan.secp_ctx,
        );

        let redeem_scripts = build_tx_scripts(
            &keys,
            to_countersignatory,
            to_broadcaster,
            &htlcs,
            &parameters,
            &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
            &view.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
        (commitment_tx.trust().built_transaction().transaction.clone(), output_witscripts)
    }

    fn forwarded_htlc() -> crate::tx::tx::HTLCInfo2 {
        crate::tx::tx::HTLCInfo2 {
            value_sat: 10_000,
            payment_hash: PaymentHash([7; 32]),
            cltv_expiry: 2 << 16,
        }
    }

    // ------------------------------------------------------------------
    // Class C rails (RED today — the fix contract)
    // ------------------------------------------------------------------

    /// C RECLASSIFIED (the #94 control evidence): the route_by_old_scid
    /// strict failure is NOT a splice-window gap — the rejection fired
    /// on the ORIGIN channel with NO splice on that node, for a
    /// record-less invoice-less payment (the sendpay shape: sendpay
    /// carries only the hash, so max_to_invoice is 0; records are
    /// created by apply_payments only AFTER a successful validate).
    /// Upstream strict mode rejects first-sight uninvoiced outgoing
    /// DELIBERATELY (node::tests::invoice_test: "fails with strict
    /// validator, but only initially") — this rail pins that the splice
    /// window does NOT relax it, and the permissive default (the
    /// deployment posture, 12/12 x7 soaks) signs it.
    #[test]
    fn strict_class_c_first_sight_uninvoiced_rejected_even_mid_window() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_100_000);
        let channel_id = chan_ctx.channel_id.clone();

        strict_enable_balance(&node_ctx.node);

        let result = node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(0x10));
            chan.enforcement_state.current_holder_commit_info = Some(crate::tx::tx::CommitmentInfo2::new(
                true, 1_050_000, 50_000, vec![], vec![], 3755,
            ));
            chan.enforcement_state.holder_commitment_funding =
                Some(chan.setup.funding_outpoint);

            let received = vec![forwarded_htlc()];
            let (tx, witscripts) = view_counterparty_commitment_forwarded(
                chan,
                &chan.setup.clone(),
                1,
                3755,
                1_086_245,
                0,
                received.clone(),
            );
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                3755,
                vec![],
                received,
            )
            .map(|_| ())
        });
        let err = result.expect_err("upstream strict contract: first-sight uninvoiced is rejected");
        assert!(
            err.message().contains("unbalanced"),
            "boundary pin must reject via the balance rule, got: {}",
            err.message()
        );
    }

    // ------------------------------------------------------------------
    // Class B rails (RED today — the fix contract)
    // ------------------------------------------------------------------

    /// Minimal provider for the B rail: only `get_transaction_parameters`
    /// is consulted on the mutual-close classification path
    /// (decode_commitment_number); the commitment-point methods belong
    /// to the unilateral path, which this rail never takes.
    struct RailProvider {
        parameters: lightning::ln::chan_utils::ChannelTransactionParameters,
    }
    impl crate::CommitmentPointProvider for RailProvider {
        fn get_holder_commitment_point(&self, _n: u64) -> PublicKey {
            unimplemented!("not on the mutual-close path")
        }
        fn get_counterparty_commitment_point(&self, _n: u64) -> Option<PublicKey> {
            unimplemented!("not on the mutual-close path")
        }
        fn get_transaction_parameters(&self) -> lightning::ln::chan_utils::ChannelTransactionParameters {
            self.parameters.clone()
        }
        fn get_spendable_htlc_indices(
            &self,
            _tx: &Transaction,
            _n: u64,
        ) -> Result<Vec<u32>, crate::util::status::Status> {
            unimplemented!("not on the mutual-close path")
        }
        fn clone_box(&self) -> Box<dyn crate::CommitmentPointProvider> {
            Box::new(RailProvider { parameters: self.parameters.clone() })
        }
    }

    impl crate::SendSync for RailProvider {}

    /// B: after a splice-OUT confirms and buries, signing the NEW
    /// funding's commitment must succeed — the retired funding's spend
    /// is a splice, not a close. Today: the monitor's state keeps
    /// `funding_outpoint` = the OLD funding (replace_funding_outpoint
    /// never updates MonitorState's copy), the single-input splice
    /// classifies as a mutual close at depth, and
    /// ensure_funding_buried_and_unspent rejects commitment 1 (live:
    /// test_splice_out + the slow gossip run).
    #[test]
    fn strict_class_b_spliceout_post_burial_new_view_signs() {
        let node_ctx = test_node_ctx(1);

        // Manual funding flow (the fund_test_channel tail, but keeping
        // the funding tx): production has F0 long-confirmed before the
        // splice — the monitor's decode matches the splice input
        // against the CONFIRMED funding outpoint, which is what
        // misclassifies the single-input splice-out as a close.
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 1_000_000);
        let mut ftx_ctx = TestFundingTxContext::new();
        ftx_ctx.add_wallet_input(&node_ctx, SpendType::P2wpkh, 1, 3_000_000);
        ftx_ctx.add_wallet_output(&node_ctx, SpendType::P2wpkh, 1, 1_999_000);
        let fvout = ftx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, 1_000_000);
        let funding_tx = ftx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &funding_tx, fvout).is_none(),
            "funding accepted"
        );
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            let monitor = chan.monitor.as_monitor(Box::new(RailProvider {
                parameters: chan.make_channel_parameters(),
            }));
            monitor.on_add_block(&[], &BlockHash::all_zeros());
            monitor.on_add_block(&[funding_tx.clone()], &BlockHash::all_zeros());
            Ok(())
        })
        .expect("confirm F0");

        let splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 900_000);
        let new_outpoint = chan_ctx.setup.funding_outpoint;

        install_onchain_validator(&node_ctx.node);

        // Confirm the splice tx and bury it (OnchainPolicy
        // min_funding_depth is 1 in the unit default; prod is 6 — the
        // shape is depth-dependent, the mechanism is not).
        node_ctx.node.with_channel(&channel_id, |chan| {
            let monitor = chan.monitor.as_monitor(Box::new(RailProvider {
                parameters: chan.make_channel_parameters(),
            }));
            monitor.on_add_block(&[splice_tx.clone()], &BlockHash::all_zeros());
            monitor.on_add_block(&[], &BlockHash::all_zeros());
            Ok(())
        })
        .expect("feed blocks");

        // funding_locked closes the splice window — the live ordering
        // at burial (both flip together; the live error fired exactly
        // here).
        node_ctx.node
            .with_channel(&channel_id, |chan| {
                chan.confirm_funding_locked(&new_outpoint).map(|_| ())
            })
            .expect("funding locked");

        let chain_state = node_ctx.node
            .with_channel(&channel_id, |chan| Ok(chan.get_chain_state()))
            .expect("chain state");
        assert!(
            !chain_state.splice_pending,
            "window must be closed at funding_locked (the live rejection shape)"
        );

        node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(REMOTE_POINT_NDX));

            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 0, 790_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("strict must sign the new funding's commitment 1 after splice-out burial");
    }

    // ------------------------------------------------------------------
    // Class B negative rails — the mut94 campaign (2026-09-02) proved
    // the positive rail is equivalent on ALL SIX survivors of
    // ensure_funding_buried_and_unspent (body→Ok(()), `delete !`,
    // `&&`→`||`, and the depth-boundary trio). These rows pin the
    // rejection side.
    // ------------------------------------------------------------------

    /// B-neg 1: post-lock, UNBURIED new funding (depth 0) must get the
    /// temporary not-buried rejection — the designed retry loop (the
    /// quiet-VM 0ms rbf stall IS this temporary loop, not a policy
    /// bug). Kills the body-gutting and `delete !` survivors.
    #[test]
    fn strict_class_b_neg_unburied_post_lock_rejects() {
        let node_ctx = test_node_ctx(1);

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 1_000_000);
        let mut ftx_ctx = TestFundingTxContext::new();
        ftx_ctx.add_wallet_input(&node_ctx, SpendType::P2wpkh, 1, 3_000_000);
        ftx_ctx.add_wallet_output(&node_ctx, SpendType::P2wpkh, 1, 1_999_000);
        let fvout = ftx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, 1_000_000);
        let funding_tx = ftx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &funding_tx, fvout).is_none(),
            "funding accepted"
        );
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            let monitor = chan.monitor.as_monitor(Box::new(RailProvider {
                parameters: chan.make_channel_parameters(),
            }));
            monitor.on_add_block(&[], &BlockHash::all_zeros());
            monitor.on_add_block(&[funding_tx.clone()], &BlockHash::all_zeros());
            Ok(())
        })
        .expect("confirm F0");

        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 900_000);

        // funding_locked closes the window while the splice output is
        // still UNCONFIRMED (depth 0) — the pre-burial live shape.
        node_ctx.node
            .with_channel(&channel_id, |chan| {
                chan.confirm_funding_locked(&chan_ctx.setup.funding_outpoint).map(|_| ())
            })
            .expect("funding locked");

        install_onchain_validator(&node_ctx.node);

        let result = node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(REMOTE_POINT_NDX));
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 0, 790_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                0,
                vec![],
                vec![],
            )
        });
        let err = result
            .err()
            .expect("unburied post-lock commitment must be temporarily rejected");
        assert!(
            err.message().contains("not buried"),
            "expected the not-buried temporary rejection, got: {}",
            err.message()
        );
    }

    /// B-neg 2: DURING the splice window the unconfirmed splice output
    /// IS the protocol's commit target — the burial check must not
    /// fire (the fork's splice_pending carve-out). Kills `&&`→`||`
    /// (which would run the checks in-window and reject at depth 0).
    #[test]
    fn strict_class_b_neg_in_window_unconfirmed_signs() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_100_000);
        let channel_id = chan_ctx.channel_id.clone();
        install_onchain_validator(&node_ctx.node);

        node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(REMOTE_POINT_NDX));
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 3755, 1_084_473, 0);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                3755,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("in-window commitment against the unconfirmed splice output must sign");
    }

    /// B-neg 3: a foreign (non-splice) spend of the funding classifies
    /// as a close; once closing_depth > 0 the commitment must get the
    /// "closed on-chain" policy rejection. Kills the `>`→`==` and
    /// `>`→`<` boundary survivors (1==0 / 1<0 are false → they'd sign).
    #[test]
    fn strict_class_b_neg_closed_funding_rejects() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 1_000_000);
        let mut ftx_ctx = TestFundingTxContext::new();
        ftx_ctx.add_wallet_input(&node_ctx, SpendType::P2wpkh, 1, 3_000_000);
        ftx_ctx.add_wallet_output(&node_ctx, SpendType::P2wpkh, 1, 1_999_000);
        let fvout = ftx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, 1_000_000);
        let funding_tx = ftx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &funding_tx, fvout).is_none(),
            "funding accepted"
        );
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            let monitor = chan.monitor.as_monitor(Box::new(RailProvider {
                parameters: chan.make_channel_parameters(),
            }));
            monitor.on_add_block(&[], &BlockHash::all_zeros());
            monitor.on_add_block(&[funding_tx.clone()], &BlockHash::all_zeros());
            Ok(())
        })
        .expect("confirm F0");

        // A FOREIGN single-input spend of the funding outpoint (not the
        // channel's splice — no splice window was opened): the monitor
        // classifies it as a close; one more block grows closing_depth.
        let mut close_ctx = TestFundingTxContext::new();
        close_ctx.inputs.push(bitcoin::TxIn {
            previous_output: chan_ctx.setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        close_ctx.add_wallet_output(&node_ctx, SpendType::P2wpkh, 1, 990_000);
        let close_tx = close_ctx.to_tx();
        node_ctx.node.with_channel(&channel_id, |chan| {
            let monitor = chan.monitor.as_monitor(Box::new(RailProvider {
                parameters: chan.make_channel_parameters(),
            }));
            monitor.on_add_block(&[close_tx], &BlockHash::all_zeros());
            monitor.on_add_block(&[], &BlockHash::all_zeros());
            Ok(())
        })
        .expect("feed close spend");

        install_onchain_validator(&node_ctx.node);

        let result = node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(REMOTE_POINT_NDX));
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 0, 790_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                0,
                vec![],
                vec![],
            )
        });
        let err = result
            .err()
            .expect("commitment on a closed funding must be rejected");
        assert!(
            err.message().contains("closed on-chain"),
            "expected the closed-on-chain rejection, got: {}",
            err.message()
        );
    }

    /// B-neg 4 (the commit-0 boundary): commitment 0 is the initial
    /// commitment — no burial requirement applies to it. Pins
    /// `commit_num > 0` against the mut94 `>=` survivor (0 >= 0 runs
    /// the checks at commitment 0 → would reject this unconfirmed-
    /// funding sign that the real code accepts).
    #[test]
    fn strict_class_b_neg_commit0_unburied_signs() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let channel_id = chan_ctx.channel_id.clone();
        install_onchain_validator(&node_ctx.node);

        node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(0, make_test_pubkey(REMOTE_POINT_NDX));
            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 0, 0, 999_000, 0);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                0,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("commitment 0 needs no burial — the checks must not run at the initial commitment");
    }

    // ------------------------------------------------------------------
    // Class D rails (RED today — the fix contract)
    // ------------------------------------------------------------------

    /// D: the BOLTs #1160 same-number re-sign — after the swap, the
    /// counterparty re-presents commitment 1 on the NEW funding while
    /// the channel-global counters read next=2 / revoke=1. The
    /// revoke-relative gate must accept it (the new funding's
    /// commitment 1 is the first commitment of its own era). Today the
    /// gate rejects it (live: test_splice_stuck_htlc / two_chan —
    /// deterministic 902s stalls on the quiet VM).
    #[test]
    fn strict_class_d_splice_same_number_resign_signs() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let old_outpoint = chan_ctx.setup.funding_outpoint;
        let _splice_tx = open_splice_window(&node_ctx, &mut chan_ctx, 1_100_000);
        let channel_id = chan_ctx.channel_id.clone();

        node_ctx.node.with_channel(&channel_id, |chan| {
            // the live pair: commitment 1 already validated on the OLD
            // funding (next=2, its tag on the old outpoint), one revoke
            // processed (revoke=1)
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(2, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(1);
            chan.enforcement_state.counterparty_commitment_funding = Some(old_outpoint);

            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 3755, 1_084_473, 0);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                3755,
                vec![],
                vec![],
            )
            .map(|_| ())
        })
        .expect("strict must accept the post-splice same-number re-sign on the new funding");
    }

    /// D guardrail: the SAME counter pair on a PLAIN channel (no
    /// funding change) must STAY rejected — the splice-window carve-out
    /// must not widen what strict refuses for ordinary channels.
    #[test]
    fn strict_class_d_plain_channel_pair_still_rejected() {
        let node_ctx = test_node_ctx(1);
        let chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let channel_id = chan_ctx.channel_id.clone();

        let result = node_ctx.node.with_channel(&channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(2, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(1);

            let (tx, witscripts) =
                view_counterparty_commitment(chan, &chan.setup.clone(), 1, 0, 890_000, 100_000);
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &make_test_pubkey(REMOTE_POINT_NDX),
                1,
                0,
                vec![],
                vec![],
            )
            .map(|_| ())
        });
        let err = result.expect_err("plain-channel num=2/revoke=1 must stay rejected in strict mode");
        assert!(
            err.message().contains("too small relative to next_counterparty_revoke_num"),
            "guardrail must reject via the numbering gate, got: {}",
            err.message()
        );
    }
}
