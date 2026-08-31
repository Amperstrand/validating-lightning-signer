#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::transaction::Version;
    use bitcoin::{self, Transaction};
    use test_log::test;

    use crate::channel::{Channel, ChannelBase};
    use crate::policy::validator::CommitmentSignatures;
    use crate::tx::tx::CommitmentInfo2;
    use crate::util::status::Status;
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;

    // The disconnect_sig live wedge (Round 30, 2026-08-31 capture): during
    // the splice window the NEW-funding commitment is validated and
    // activated to current, then the peer's resume batch re-delivers the
    // OLD-funding fee-change commitment (the pre-splice fee sync — a
    // spec-legal straggler). claimable_balances valued the channel-scoped
    // current infos (NEW-funding scale) against before_setup = prev_setup
    // (the OLD, smaller funding) → checked_sub underflow → spurious
    // "commitment totals exceed the funding value" → channeld retry-locked
    // (the splice never locked). Values mirror the live capture: old
    // funding 1,000,000; splice-IN to 1,095,450; straggler num=1
    // to_b=995,120 fee 3755; new current to_b=1,090,000.
    #[test]
    fn old_funding_fee_straggler_after_new_funding_current() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

        let old_setup = chan_ctx.setup.clone();
        let channel_id = chan_ctx.channel_id.clone();

        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 995_120, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat += 95_450;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        let mut new_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 1_090_000, 0, vec![], vec![]);
        let (ncsig, nhsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut new_ctx);

        let raw_validate = |ctx: &TestCommitmentTxContext,
                            sig: &Signature,
                            htlc_sigs: &Vec<Signature>|
         -> Result<(), Status> {
            node_ctx.node.with_channel(&channel_id, |chan| {
                let htlcs = Channel::htlcs_info2_to_oic(&ctx.offered_htlcs, &ctx.received_htlcs);
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
        };

        raw_validate(&new_ctx, &ncsig, &nhsigs)
            .expect("new-funding commitment stored pending (the pre-crash validation)");
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                chan.enforcement_state.next_holder_commit_info = Some((
                    CommitmentInfo2::new(
                        true,
                        new_ctx.to_countersignatory,
                        new_ctx.to_broadcaster,
                        vec![],
                        vec![],
                        new_ctx.feerate_per_kw,
                    ),
                    CommitmentSignatures(ncsig.clone(), nhsigs.clone()),
                ));
                chan.activate_initial_commitment()
                    .expect("same-number activation (the pre-crash current)");
                assert!(
                    chan.enforcement_state.current_holder_commit_info.is_some(),
                    "new-funding info is now CURRENT"
                );
                Ok(())
            })
            .expect("activate");

        let err = raw_validate(&straggler_ctx, &scsig, &shsigs).err();
        assert!(
            err.is_none(),
            "old-funding straggler after new-funding current must be accepted, got {:?}",
            err.map(|e| e.message().to_string())
        );
    }

    // The LIVE order variant (Round 30 diag2, req429): the new-funding
    // signs happen BEFORE the swap, so the swap-time snapshot captures
    // already-NEW-scale currents — the snapshot itself is cross-funding
    // data for balance purposes (cur=1,095,120 against the 1M view).
    // The straggler validation must still pass: an underflowing snapshot
    // valuation means "no usable before-state for this funding" (the
    // initial-value fallback), never a rejection.
    #[test]
    fn old_funding_straggler_with_cross_funding_snapshot() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);

        let old_setup = chan_ctx.setup.clone();
        let channel_id = chan_ctx.channel_id.clone();

        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 3755, 995_120, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat += 95_450;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // The live-order snapshot: NEW-scale currents were captured by
        // the swap (they were rebuilt by the new-funding signs first)
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let mut snap =
                    chan.enforcement_state.prev_funding_commitment.take().expect("window open");
                snap.current_holder_info =
                    Some(CommitmentInfo2::new(true, 0, 1_090_000, vec![], vec![], 3755));
                snap.current_counterparty_info =
                    Some(CommitmentInfo2::new(true, 0, 1_090_000, vec![], vec![], 3755));
                chan.enforcement_state.prev_funding_commitment = Some(snap);
                Ok(())
            })
            .expect("seed cross-funding snapshot");

        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let htlcs = Channel::htlcs_info2_to_oic(
                    &straggler_ctx.offered_htlcs,
                    &straggler_ctx.received_htlcs,
                );
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_holder_broadcastable();
                let save_commit_num = chan.enforcement_state.next_holder_commit_num;
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(straggler_ctx.commit_num);
                let per_commitment_point =
                    chan.get_per_commitment_point(straggler_ctx.commit_num)?;
                chan.enforcement_state.set_next_holder_commit_num_for_testing(save_commit_num);
                let keys = chan.make_holder_tx_keys(&per_commitment_point);
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    straggler_ctx.to_broadcaster,
                    straggler_ctx.to_countersignatory,
                    &htlcs,
                    &parameters,
                    &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                    &chan.setup.counterparty_points.funding_pubkey,
                )
                .expect("scripts");
                let output_witscripts: Vec<_> =
                    redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
                chan.validate_holder_commitment_tx(
                    &straggler_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
                    &output_witscripts,
                    straggler_ctx.commit_num,
                    straggler_ctx.feerate_per_kw,
                    straggler_ctx.offered_htlcs.clone(),
                    straggler_ctx.received_htlcs.clone(),
                    &scsig,
                    &shsigs,
                )
                .map(|_| ())
            })
            .expect("straggler accepted despite the cross-funding snapshot");
    }
}
