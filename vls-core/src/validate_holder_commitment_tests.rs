#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::transaction::Version;
    use bitcoin::{self, Amount, Transaction};
    use lightning::ln::chan_utils::TxCreationKeys;
    use lightning::ln::channel_keys::DelayedPaymentKey;
    use lightning::types::payment::PaymentHash;

    use log::*;
    use test_log::test;

    use crate::channel::{Channel, ChannelBase, CommitmentType};
    use crate::node::SpendType;
    use crate::policy::error::policy_error;
    use crate::policy::validator::ChainState;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;

    use paste::paste;

    #[test]
    fn validate_holder_commitment_with_htlcs() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);

        let offered_htlcs = vec![
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([1; 32]),
                cltv_expiry: 1 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([2; 32]),
                cltv_expiry: 2 << 16,
            },
        ];
        let received_htlcs = vec![
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([3; 32]),
                cltv_expiry: 3 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([4; 32]),
                cltv_expiry: 4 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([5; 32]),
                cltv_expiry: 5 << 16,
            },
        ];
        let sum_htlc = 50_000;

        let commit_num = 1;
        let feerate_per_kw = 1100;
        let fees = 20_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - sum_htlc - fees;

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");
    }

    // DISCONNECT-SIG SEMANTIC RAIL (RED-first, the 2026-08-31 gate decode):
    // on reestablish channeld RE-SIGNS the new-funding commitment BEFORE
    // the re-offered old-funding straggler is validated. The sign tail
    // stores the signed info as channel-level current_counterparty (era-
    // blind) — then the straggler's claimable before-side values NEW-era
    // currents against the OLD funding view: "commitment totals exceed
    // the funding value", the exact live rejection that wedged
    // disconnect_sig (vlsd req 78/99/104, view 1M vs new-scale currents).
    #[test]
    fn straggler_after_new_funding_resign() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let old_setup = chan_ctx.setup.clone();
        let channel_id = chan_ctx.channel_id.clone();

        // the OLD-funding straggler's message, built pre-swap
        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 0, 0, 995_120, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        // the old era's currents
        let dummy_sigs = crate::policy::validator::CommitmentSignatures(
            Signature::from_compact(&[0; 64]).unwrap(),
            vec![],
        );
        // old-era currents (1M-scale: the seeded helper is 3M-scale and
        // would overflow every 1M view)
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
            .expect("seed");

        // the splice swap (+100k -> 1.1M new funding)
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat += 100_000;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // THE RE-SIGN of the new-funding commitment (the reestablish
        // SignRemoteCommitmentTx — happens BEFORE the straggler arrives)
        let resign_point = node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                chan.enforcement_state
                    .set_next_counterparty_commit_num_for_testing(1, make_test_pubkey(0x11));
                chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(0);
                let remote_per_commitment_point = make_test_pubkey(10);
                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_per_commitment_point,
                    1,
                    1100,
                    550_000,
                    549_000,
                    vec![],
                );
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let keys = chan.make_counterparty_tx_keys(&remote_per_commitment_point);
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    549_000,
                    550_000,
                    &mut vec![],
                    &parameters,
                    &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                    &chan.setup.counterparty_points.funding_pubkey,
                )
                .expect("scripts");
                let output_witscripts: Vec<_> =
                    redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
                let trusted = commitment_tx.trust();
                let tx = trusted.built_transaction().transaction.clone();
                chan.sign_counterparty_commitment_tx(
                    &tx,
                    &output_witscripts,
                    &remote_per_commitment_point,
                    1,
                    1100,
                    vec![],
                    vec![],
                )
                .expect("re-sign of the new-funding commitment");
                Ok(remote_per_commitment_point)
            })
            .expect("resign");

        // THE STRAGGLER, arriving AFTER the re-sign (the live ordering):
        // must still be ACCEPTED — the old-funding view with its OWN era's
        // currents, not the just-signed new-era info.
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
        raw_validate(&straggler_ctx, &scsig, &shsigs)
            .expect("straggler accepted after a new-funding re-sign (era-matched before-side)");
    }

    // DISCONNECT-TIER RESTORE RAIL: the splice window's signer state
    // (the prev_funding_commitment snapshot, the funding tags, the prev
    // setups) must survive a persist round-trip AND a restored signer
    // must still ACCEPT the re-offered old-funding straggler — the
    // disconnect_sig decode (2026-08-31): the restarted signer rejected
    // l2's re-offered old-funding commitment with "commitment totals
    // exceed the funding value" (new-funding-scale stored currents
    // valued against the 1M view), wedging the lock handshake.
    #[test]
    fn splice_window_state_survives_persist_roundtrip() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
        let old_setup = chan_ctx.setup.clone();
        let channel_id = chan_ctx.channel_id.clone();

        // the OLD-funding straggler's message, built pre-swap
        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 0, 0, 995_120, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        // the old era's currents + the splice swap
        let dummy_sigs = crate::policy::validator::CommitmentSignatures(
            Signature::from_compact(&[0; 64]).unwrap(),
            vec![],
        );
        // old-era currents (1M-scale: the seeded helper is 3M-scale and
        // would overflow every 1M view)
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
            .expect("seed");

        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat += 100_000;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // the new-funding commitment validated (the pre-kill exchange)
        let mut new_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 1100, 500_000, 599_000, vec![], vec![]);
        let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut new_ctx);
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
        raw_validate(&new_ctx, &csig, &hsigs)
            .expect("new-funding commitment stored (pre-kill exchange)");

        // THE PERSIST ROUND-TRIP: the whole splice-window state through
        // serde (the vlsd DB / proxy replay's transport form)
        let (rt_state, rt_prev_setup, rt_prev_prev) = node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                fn roundtrip<T>(v: &T) -> T
                where
                    T: serde::Serialize + serde::de::DeserializeOwned,
                {
                    serde_json::to_string(v)
                        .and_then(|s| serde_json::from_str(&s))
                        .expect("persist round-trip")
                }
                let entry_state = roundtrip(&chan.enforcement_state);
                let rt_prev = chan.prev_setup.as_ref().map(roundtrip);
                let rt_prev_prev = chan.prev_prev_setup.as_ref().map(roundtrip);
                Ok((entry_state, rt_prev, rt_prev_prev))
            })
            .expect("extract");

        assert!(
            rt_state.prev_funding_commitment.is_some(),
            "the justice snapshot must round-trip (the disconnect_sig rejection's missing piece)"
        );
        assert!(
            rt_state.holder_commitment_funding.is_some()
                || rt_state.counterparty_commitment_funding.is_some(),
            "the funding tags must round-trip"
        );

        // INSTALL the restored state (simulate the fresh signer loading
        // the round-tripped entries: wipe in-memory, reload from the
        // round-tripped copies)
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                chan.enforcement_state = rt_state;
                chan.prev_setup = rt_prev_setup;
                chan.prev_prev_setup = rt_prev_prev;
                Ok(())
            })
            .expect("install restored state");

        // THE RESTORED-SIGNER STRAGGLER: the re-offered old-funding
        // commitment must still be ACCEPTED (valued against its own
        // 1M view, not the new-funding currents)
        raw_validate(&straggler_ctx, &scsig, &shsigs)
            .expect("restored signer accepts the re-offered old-funding straggler");
    }

    // R10.4 RETRANSMIT RAIL (disconnect-tier prep): the SAME new-funding
    // splice commitment validated a SECOND time while still pending (the
    // post-restart retransmit — BOLTs #1160: "MUST reuse the same
    // commitment number") must be accepted with no error, leave the
    // slots holding the identical content, and NOT advance the
    // numbering. Idempotent storage, not consumption.
    #[test]
    fn splice_commitment_retransmit_same_pending() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 3_000_000);
        let old_setup = chan_ctx.setup.clone();
        let channel_id = chan_ctx.channel_id.clone();

        // the OLD funding's commitment state (the justice window the
        // snapshot must carry — same seeding as the slots tests)
        let dummy_sigs = crate::policy::validator::CommitmentSignatures(
            Signature::from_compact(&[0; 64]).unwrap(),
            vec![],
        );
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                chan.enforcement_state.current_holder_commit_info =
                    Some(make_test_commitment_info());
                chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
                chan.enforcement_state.current_counterparty_commit_info =
                    Some(make_test_commitment_info());
                Ok(())
            })
            .expect("seed old-funding state");

        // the splice swap (new funding spending the old outpoint)
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat -= 100_000;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // the new-funding same-number commitment (num=1)
        let mut new_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 1100, 1_500_000, 1_399_000, vec![], vec![]);
        let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut new_ctx);

        let num_before = node_ctx
            .node
            .with_channel(&channel_id, |chan| Ok(chan.enforcement_state.next_holder_commit_num))
            .expect("num before");

        // the RAW validate (no helper tail — its num>0 branch REVOKES,
        // which the retransmit scenario has NOT reached yet: the peer
        // re-sends because it has not seen our reply, so the pending is
        // still unconsumed on the second arrival)
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

        raw_validate(&new_ctx, &csig, &hsigs).expect("stored pending (first arrival)");
        raw_validate(&new_ctx, &csig, &hsigs)
            .expect("retransmit accepted (identical, still pending)");

        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let slot = chan
                    .enforcement_state
                    .next_holder_commit_info
                    .as_ref()
                    .expect("channel slot non-empty after retransmit");
                assert_eq!(
                    slot.0.to_countersigner_value_sat, 1_399_000,
                    "slot still holds the same new-funding pending"
                );
                assert_eq!(
                    chan.enforcement_state.next_holder_commit_num, num_before,
                    "retransmit must not advance the numbering"
                );
                let prev = chan
                    .enforcement_state
                    .prev_funding_commitment
                    .as_ref()
                    .expect("window still open");
                assert!(
                    prev.current_holder_info.is_some() && prev.current_counterparty_info.is_some(),
                    "old funding's justice snapshot survives the retransmit"
                );
                Ok(())
            })
            .expect("asserts");
    }

    // THE SLOTS LEG 2 ACCEPTANCE TEST (GREEN): the interleave — a
    // new-funding commitment pending, then an old-funding straggler —
    // both retained (the record holds the straggler; the channel slot
    // keeps the new funding's pending). The view-parameterization stack
    // (the recompose helper, the sighash, the builder, the storage gate)
    // routes the old-funding tx through its own view end-to-end.
    #[test]
    fn splice_window_straggler_retains_new_funding_pending() {
        // The interleave: during the splice window, a new-funding commitment
        // is stored, then an old-funding straggler arrives — BOTH pendings
        // must be retained (the channel slot holds the new; the record holds
        // the straggler). The current OR-branch clobbers the channel slot.
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 3_000_000);

        let old_setup = chan_ctx.setup.clone();
        let old_keys = chan_ctx.counterparty_keys.clone();
        let channel_id = chan_ctx.channel_id.clone();

        // THE STRAGGLER'S MESSAGE built BEFORE the splice (channel_commitment
        // uses the LIVE channel state, so it must be built while the old
        // funding is current — it then spends the old outpoint; it gets
        // VALIDATED after the new-funding commitment, the interleave)
        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 0, 0, 2_999_000, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        // THE SPLICE: a new funding tx whose input spends the old channel
        // outpoint (the setup path derives only the txid — no sigs needed)
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: old_setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat -= 100_000;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // THE NEW-FUNDING COMMITMENT (num=1, the same-number re-sign)
        let mut new_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 1, 1100, 1_500_000, 1_399_000, vec![], vec![]);
        let (csig, hsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut new_ctx);
        // the RAW validate (no helper tail): the new-funding commitment must
        // stay PENDING (stored, not revoked) — the interleave state the
        // straggler arrives into
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let htlcs =
                    Channel::htlcs_info2_to_oic(&new_ctx.offered_htlcs, &new_ctx.received_htlcs);
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_holder_broadcastable();
                let save_commit_num = chan.enforcement_state.next_holder_commit_num;
                chan.enforcement_state.set_next_holder_commit_num_for_testing(new_ctx.commit_num);
                let per_commitment_point = chan.get_per_commitment_point(new_ctx.commit_num)?;
                chan.enforcement_state.set_next_holder_commit_num_for_testing(save_commit_num);
                let keys = chan.make_holder_tx_keys(&per_commitment_point);
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    new_ctx.to_broadcaster,
                    new_ctx.to_countersignatory,
                    &htlcs,
                    &parameters,
                    &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                    &chan.setup.counterparty_points.funding_pubkey,
                )
                .expect("scripts");
                let output_witscripts: Vec<_> =
                    redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();
                chan.validate_holder_commitment_tx(
                    &new_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
                    &output_witscripts,
                    new_ctx.commit_num,
                    new_ctx.feerate_per_kw,
                    new_ctx.offered_htlcs.clone(),
                    new_ctx.received_htlcs.clone(),
                    &csig,
                    &hsigs,
                )
            })
            .expect("new-funding commitment stored pending");

        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                assert!(
                    chan.prev_setup.is_some(),
                    "DIAGNOSTIC: prev_setup is None — the new-channel path ran, not the splice"
                );
                let prev_out = chan.prev_setup.as_ref().unwrap().funding_outpoint;
                let spends_old = straggler_ctx
                    .tx
                    .as_ref()
                    .map(|t| {
                        t.trust()
                            .built_transaction()
                            .transaction
                            .input
                            .iter()
                            .any(|i| i.previous_output == prev_out)
                    })
                    .unwrap_or(false);
                assert!(
                    spends_old,
                    "DIAGNOSTIC: the straggler tx does not spend the prev outpoint"
                );
                Ok(())
            })
            .expect("diagnostics");
        // the RAW validate for the straggler too — the helper's num==0 tail
        // would activate (consuming the slot); the interleave's post-state
        // must keep both pendings untouched for the assertions
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
            })
            .expect("straggler accepted (raw)");

        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let prev =
                    chan.enforcement_state.prev_funding_commitment.as_ref().expect("window open");
                assert!(prev.next_holder_info.is_some(), "straggler retained in the record");
                let slot = chan
                    .enforcement_state
                    .next_holder_commit_info
                    .as_ref()
                    .expect("channel slot non-empty");
                assert_eq!(
                    slot.0.to_countersigner_value_sat, 1_399_000,
                    "channel slot still holds the NEW-funding pending (not clobbered)"
                );
                Ok(())
            })
            .expect("asserts");
    }

    #[test]
    fn activate_initial_commitment_test() {
        let channel_amount = 3_000_000;
        let stype = SpendType::P2wpkh;
        let incoming = channel_amount + 2_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);
        let tx = tx_ctx.to_tx();

        funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (commit_sig, htlc_sigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        let htlcs = Channel::htlcs_info2_to_oic(
            &commit_tx_ctx.offered_htlcs,
            &commit_tx_ctx.received_htlcs,
        );

        let _ = node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();
            let parameters = channel_parameters.as_holder_broadcastable();

            let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
            let keys = chan.make_holder_tx_keys(&per_commitment_point);

            let redeem_scripts = build_tx_scripts(
                &keys,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                &htlcs,
                &parameters,
                &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
            )
            .expect("scripts");
            let output_witscripts: Vec<_> =
                redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();

            // Call before validate fails
            assert_invalid_argument_err!(
                chan.activate_initial_commitment(),
                "activate_initial_commitment called before validation of the initial commitment"
            );

            chan.validate_holder_commitment_tx(
                &commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
                &output_witscripts,
                commit_tx_ctx.commit_num,
                commit_tx_ctx.feerate_per_kw,
                commit_tx_ctx.offered_htlcs.clone(),
                commit_tx_ctx.received_htlcs.clone(),
                &commit_sig,
                &htlc_sigs,
            )?;

            // Call right after validate succeeds
            assert_status_ok!(chan.activate_initial_commitment());

            // Call later fails
            assert_invalid_argument_err!(
                chan.activate_initial_commitment(),
                "activate_initial_commitment called with next_holder_commit_num 1"
            );

            Ok(())
        });
    }

    // policy-revoke-new-commitment-signed
    #[test]
    fn validate_holder_commitment_with_bad_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let commit_num = 2;
        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        // Force the channel to commit_num 2 to build the bogus commitment ...
        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, commit_num);

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, 1);

        assert_failed_precondition_err!(
            validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs,),
            "policy failure: get_per_commitment_point: commitment_number 3 invalid when next_holder_commit_num is 1"
        );
    }

    // policy-commitment-holder-not-revoked
    #[test]
    fn validate_holder_commitment_with_revoked_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        // Start by validating holder commitment #10 (which revokes #9)
        let commit_num = 10;
        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, commit_num);

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs.clone(),
            received_htlcs.clone(),
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let revoked_commit_num = commit_num - 1;

        // Now attempt to holder sign holder commitment #9
        let commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            revoked_commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );

        assert_failed_precondition_err!(
            sign_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 10 != 11"
        );
    }

    #[test]
    fn validate_holder_commitment_with_same_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let commit_num = 1;
        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        // You can do it again w/ same commit num.
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");
    }

    const HOLD_COMMIT_NUM: u64 = 43;

    #[allow(dead_code)]
    struct TxBuilderMutationState<'a> {
        commit_tx_ctx: &'a mut TestCommitmentTxContext,
    }

    #[allow(dead_code)]
    struct KeysMutationState<'a> {
        keys: &'a mut TxCreationKeys,
    }

    #[allow(dead_code)]
    struct ValidationMutationState<'a> {
        opt_anchors: bool,
        chan: &'a mut Channel,
        cstate: &'a mut ChainState,
        commit_tx_ctx: &'a mut TestCommitmentTxContext,
        tx: &'a mut Transaction,
        witscripts: &'a mut Vec<Vec<u8>>,
        commit_sig: &'a mut Signature,
        htlc_sigs: &'a mut Vec<Signature>,
    }

    #[allow(dead_code)]
    struct ValidationState<'a> {
        chan: &'a Channel,
    }

    fn validate_holder_commitment_with_mutators_common<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let to_broadcaster = 1_979_997;
        let to_countersignatory = 1_000_000;
        let feerate_per_kw = 1200;
        let htlc1 =
            HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

        let htlc2 =
            HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

        let htlc3 = HTLCInfo2 {
            value_sat: 10_003,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
        };
        let offered_htlcs = vec![htlc1];
        let received_htlcs = vec![htlc2, htlc3];

        let mut commit_tx_ctx0 = TestCommitmentTxContext {
            commit_num: HOLD_COMMIT_NUM,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs: offered_htlcs.clone(),
            received_htlcs: received_htlcs.clone(),
            tx: None,
        };

        mutate_tx_builder(&mut TxBuilderMutationState { commit_tx_ctx: &mut commit_tx_ctx0 });

        commit_tx_ctx0 = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx0.commit_num,
            commit_tx_ctx0.feerate_per_kw,
            commit_tx_ctx0.to_broadcaster,
            commit_tx_ctx0.to_countersignatory,
            commit_tx_ctx0.offered_htlcs.clone(),
            commit_tx_ctx0.received_htlcs.clone(),
        );

        let (commit_sig0, htlc_sigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx0);

        node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
            let mut commit_tx_ctx = commit_tx_ctx0.clone();
            let mut commit_sig = commit_sig0.clone();
            let mut htlc_sigs = htlc_sigs0.clone();

            let channel_parameters = chan.make_channel_parameters();
            let parameters = channel_parameters.as_holder_broadcastable();
            let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;

            let mut keys = chan.make_holder_tx_keys(&per_commitment_point);

            mutate_keys(&mut KeysMutationState { keys: &mut keys });

            let htlcs = Channel::htlcs_info2_to_oic(
                &commit_tx_ctx.offered_htlcs,
                &commit_tx_ctx.received_htlcs,
            );
            let redeem_scripts = build_tx_scripts(
                &keys,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                &htlcs,
                &parameters,
                &chan.keys.pubkeys(&chan.secp_ctx).funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
            )
            .expect("scripts");
            let mut output_witscripts =
                redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();

            let mut tx =
                commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction.clone();

            let mut cstate = make_test_chain_state();

            mutate_validation_input(&mut ValidationMutationState {
                opt_anchors: commitment_type == CommitmentType::AnchorsZeroFeeHtlc,
                chan: chan,
                cstate: &mut cstate,
                commit_tx_ctx: &mut commit_tx_ctx,
                tx: &mut tx,
                witscripts: &mut output_witscripts,
                commit_sig: &mut commit_sig,
                htlc_sigs: &mut htlc_sigs,
            });

            for offered_htlc in commit_tx_ctx.offered_htlcs.clone() {
                node_ctx.node.add_keysend(
                    make_test_pubkey(1),
                    offered_htlc.payment_hash,
                    offered_htlc.value_sat * 1000,
                )?;
            }

            // Validate the holder_commitment, but defer error returns till after we've had
            // a chance to validate the channel state for side-effects
            let mut deferred_rv = chan.validate_holder_commitment_tx(
                &tx,
                &output_witscripts,
                commit_tx_ctx.commit_num,
                commit_tx_ctx.feerate_per_kw,
                commit_tx_ctx.offered_htlcs.clone(),
                commit_tx_ctx.received_htlcs.clone(),
                &commit_sig,
                &htlc_sigs,
            );
            if deferred_rv.is_ok() {
                if commit_tx_ctx.commit_num == 0 {
                    deferred_rv = chan.activate_initial_commitment().map(|_| ());
                }
            }

            if deferred_rv.is_ok() {
                // It's ok to re-revoke prior commitment's ([#502])
                debug!("re-revoking a previously revoked commitment");
                chan.revoke_previous_holder_commitment(commit_tx_ctx.commit_num - 1)?;

                debug!("revoking the previous holder commitment");
                chan.revoke_previous_holder_commitment(commit_tx_ctx.commit_num)?;

                debug!("revoking it again to check idempotency");
                chan.revoke_previous_holder_commitment(commit_tx_ctx.commit_num)?;
            }
            validate_channel_state(&ValidationState { chan });
            deferred_rv?;
            Ok(())
        })
    }

    fn validate_holder_commitment_with_mutators<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node_ctx, chan_ctx) = setup_funded_channel_with_setup(
            setup,
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    fn validate_holder_commitment_retry_with_mutators<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node_ctx, chan_ctx) = setup_funded_channel_with_setup(
            setup,
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        // Start with successful validation w/o mutations
        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            |_tms| {},
            |_kms| {},
            |_vms| {},
            |vs| {
                // Channel state should advance.
                assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            },
        )?;

        // Retry with mutations
        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_status_ok!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_status_ok!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $tms, $kms, $vms, $vs)
                    );
                }
            }
        };
    }

    macro_rules! generate_status_ok_retry_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_status_ok!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_status_ok!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $tms, $kms, $vms, $vs)
                    );
                }
            }
        };
    }

    #[allow(dead_code)]
    struct ErrMsgContext {
        opt_anchors: bool,
    }

    const ERR_MSG_CONTEXT_STATIC: ErrMsgContext = ErrMsgContext { opt_anchors: false };
    const ERR_MSG_CONTEXT_ANCHORS: ErrMsgContext = ErrMsgContext { opt_anchors: true };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_retry_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_retry_with_mutated_tx {
        ($name: ident, $tms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_retry_variations!(
                $name,
                $tms,
                |_| {},
                |_| {},
                $vs,
                $errmsg
            );
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_keys {
        ($name: ident, $kms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!(
                $name,
                |_| {},
                $kms,
                |_| {},
                $vs,
                $errmsg
            );
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_validation_input {
        ($name: ident, $vms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!(
                $name,
                |_| {},
                |_| {},
                $vms,
                $vs,
                $errmsg
            );
        };
    }

    generate_status_ok_variations!(success, |_tms| {}, |_kms| {}, |_vms| {}, |vs| {
        // Channel state should advance.
        assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
    });

    // policy-commitment-retry-same
    generate_status_ok_retry_variations!(can_retry, |_tms| {}, |_kms| {}, |_vms| {}, |vs| {
        // Channel state should advance.
        assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
    });

    // policy-revoke-not-closed
    // It's ok to retry a validate_holder_commitment after it has been signed.
    generate_status_ok_retry_variations!(
        can_retry_after_signed,
        |_tms| {},
        |_kms| {},
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should stay advanced
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        }
    );

    // policy-revoke-not-closed
    // It's not ok to advance after a prior has been signed
    generate_failed_precondition_error_with_mutated_validation_input!(
        not_after_signed,
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: channel is closing"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_to_holder,
        |tms| {
            tms.commit_tx_ctx.to_broadcaster -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_to_counterparty,
        |tms| {
            tms.commit_tx_ctx.to_countersignatory -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_offered_htlc,
        |tms| {
            tms.commit_tx_ctx.offered_htlcs[0].value_sat -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_received_htlc,
        |tms| {
            tms.commit_tx_ctx.received_htlcs[0].value_sat -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_commit_sig,
        |vms| {
            *vms.commit_sig = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: commit sig verify failed: signature failed verification"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_htlc_sig,
        |vms| {
            vms.htlc_sigs[0] = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: \
             commit sig verify failed for htlc 0: signature failed verification"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        not_ahead,
        |vms| {
            // Set the channel's next_holder_commit_num ahead two, past the retry ...
            vms.chan.enforcement_state.set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM + 2);
        },
        |vs| {
            // Channel state should stay where we advanced it.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 2);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             can't validate revoked commitment_number 43, next_holder_commit_num is 45"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        not_behind,
        |vms| {
            // Set the channel's next_holder_commit_num ahead two behind 1, in the past ...
            vms.chan.enforcement_state.set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM - 1);
        },
        |vs| {
            // Channel state should stay where we set it.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM - 1);
        },
        |_| {
            "policy failure: revoke_previous_holder_commitment: \
             new_current_commitment == next_holder_commit_num 42 \
             but next_holder_commit_info.is_none"
        }
    );

    // policy-revoke-not-closed
    generate_failed_precondition_error_with_mutated_validation_input!(
        not_closed,
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: channel is closing"
    );

    // policy-revoke-not-closed
    generate_status_ok_retry_variations!(
        // It's ok to validate existing when closed (ie: retry after mutual close)
        closed_ok_on_previous,
        |_tms| {},
        |_kms| {},
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        }
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-version
    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_version,
        |vms| {
            vms.tx.version = Version::non_standard(3);
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: decode_commitment_tx: bad commitment version: 3"
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-broadcaster-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_delayed_pubkey,
        |kms| {
            kms.keys.broadcaster_delayed_payment_key = DelayedPaymentKey(make_test_pubkey(42));
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| {
            format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: script pubkey doesn't match inner script: OP_0 OP_PUSHBYTES_32 a838650404f18b3bdac3ff705fd16d9c221b4ffe46ea675f5ede586b63ae2b63 != OP_0 OP_PUSHBYTES_32 e8c680c7abd47830f5657a0f0ccd46bf3392bb472ba50e98be0ec46a88f982d3",
            if ectx.opt_anchors { 6 } else { 4 }
        )
        }
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-holder
    generate_failed_precondition_error_with_mutated_validation_input!(
        multiple_to_holder,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let ndx = basendx + 4;
            vms.tx.output.push(vms.tx.output[ndx].clone());
            vms.witscripts.push(vms.witscripts[ndx].clone());
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: more than one to_broadcaster output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-counterparty
    generate_failed_precondition_error_with_mutated_validation_input!(
        multiple_to_counterparty,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let ndx = basendx + 3;
            vms.tx.output.push(vms.tx.output[ndx].clone());
            vms.witscripts.push(vms.witscripts[ndx].clone());
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: more than one to_countersigner output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_to_holder,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let delta = Amount::from_sat(1_979_900);
            vms.tx.output[basendx + 3].value += delta;
            vms.tx.output[basendx + 4].value -= delta;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_broadcaster_value_sat 97 less than dust limit 354"
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_to_counterparty,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let delta = Amount::from_sat(999_900);
            vms.tx.output[basendx + 3].value -= delta;
            vms.tx.output[basendx + 4].value += delta;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_countersigner_value_sat 100 less than dust limit 354"
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_offered_htlc,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            vms.commit_tx_ctx.offered_htlcs[0].value_sat = 300;
            vms.tx.output[basendx].value = Amount::from_sat(300);
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             offered htlc.value_sat 300 less than dust limit {}",
            if ectx.opt_anchors { 354 } else { 1125 }
        )
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_received_htlc,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            vms.commit_tx_ctx.received_htlcs[0].value_sat = 300;
            vms.tx.output[basendx + 1].value = Amount::from_sat(300);
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             received htlc.value_sat 300 less than dust limit {}",
            if ectx.opt_anchors { 354 } else { 1173 }
        )
    );

    #[test]
    fn channel_state_counterparty_commit_and_revoke_test() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 3_000_000);
        synthesize_setup_channel(
            &node_ctx,
            &mut chan_ctx,
            bitcoin::OutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
            HOLD_COMMIT_NUM,
        );
        node_ctx
            .node
            .with_channel(&chan_ctx.channel_id, |chan| {
                let validator = chan.validator();
                let state = &mut chan.enforcement_state;

                // We'll need a placeholder; actual values not checked here ...
                let commit_info = make_test_commitment_info();

                // confirm initial state
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 0);
                // commit 0: unitialized <- next_revoke, <- next_commit

                // can't set next_commit to 0 (what would current point be?)
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        0,
                        make_test_pubkey(0x08),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-other",
                    "set_next_counterparty_commit_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_commit_num, 0);

                // can't set next_revoke to 0 either
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "policy-other",
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 1
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone(),
                    false,
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);
                // commit 0: current <- next_revoke
                // commit 1: next    <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone(),
                    false,
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);

                // can't skip next_commit forward
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: invalid progression: 1 to 3"
                );
                assert_eq!(state.next_counterparty_commit_num, 1);

                // can't skip next_revoke forward
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 1),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: \
                     1 too large relative to next_counterparty_commit_num 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 2
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    2,
                    make_test_pubkey(0x12),
                    commit_info.clone(),
                    false,
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: unrevoked <- next_revoke
                // commit 1: current
                // commit 2: next    <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    2,
                    make_test_pubkey(0x12),
                    commit_info.clone(),
                    false,
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't commit old thing
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        1,
                        make_test_pubkey(0x10),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't (ever) set next_revoke to 0
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "policy-other",
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 2),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: 2 too large relative to \
                     next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // REVOKE commit 0
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: revoked
                // commit 1: current   <- next_revoke
                // commit 2: next      <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't retry the previous commit anymore
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: 2 too small relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't skip commit ahead
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        4,
                        make_test_pubkey(0x16),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: invalid progression: 2 to 4"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't revoke backwards
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "policy-other",
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 2),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: 2 too large \
                     relative to next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // ADVANCE next_commit to 3
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    3,
                    make_test_pubkey(0x14),
                    commit_info.clone(),
                    false,
                ));
                // commit 0: revoked
                // commit 1: unrevoked <- next_revoke
                // commit 2: current
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // retries ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    3,
                    make_test_pubkey(0x14),
                    commit_info.clone(),
                    false,
                ));
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can still retry the old revoke (they may not have seen our commit).
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 3),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't commit behind
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: 2 too small relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // REVOKE commit 1
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 2));
                // commit 1: revoked
                // commit 2: current   <- next_revoke
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // revoke retries ok
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 2));
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't revoke backwards
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 1),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // can't revoke ahead until next commit
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 3),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // commit retry not ok anymore
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: 3 too small relative to \
                     next_counterparty_revoke_num 2"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't skip commit ahead
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        5,
                        make_test_pubkey(0x18),
                        commit_info.clone(),
                        false,
                    ),
                    "policy-commitment-previous-revoked",
                    "set_next_counterparty_commit_num: invalid progression: 3 to 5"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // ADVANCE next_commit to 4
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    4,
                    make_test_pubkey(0x16),
                    commit_info.clone(),
                    false,
                ));
                // commit 2: unrevoked <- next_revoke
                // commit 3: current
                // commit 4: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 4);

                Ok(())
            })
            .expect("success");
    }

    #[test]
    fn post_lock_straggler_rejected() {
        // F2's replay rail: funding_locked closes the splice window
        // (prev_setup cleared) — an old-funding commitment arriving after
        // the lock is REJECTED. The straggler acceptance is window-scoped.
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = fund_test_channel(&node_ctx, 3_000_000);
        let channel_id = chan_ctx.channel_id.clone();

        // the straggler's message built BEFORE the splice (the old funding)
        let mut straggler_ctx =
            channel_commitment(&node_ctx, &chan_ctx, 0, 0, 2_999_000, 0, vec![], vec![]);
        let (scsig, shsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

        // the splice
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.inputs.push(bitcoin::TxIn {
            previous_output: chan_ctx.setup.funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        });
        chan_ctx.setup.channel_value_sat -= 100_000;
        let vout =
            tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
        let splice_tx = tx_ctx.to_tx();
        assert!(
            funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &splice_tx, vout).is_none(),
            "splice accepted"
        );

        // the lock closes the window
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let outpoint = chan.setup.funding_outpoint;
                chan.confirm_funding_locked(&outpoint)
            })
            .expect("lock");

        // the straggler post-lock: REJECTED (the window is closed)
        node_ctx
            .node
            .with_channel(&channel_id, |chan| {
                let htlcs = Channel::htlcs_info2_to_oic(
                    &straggler_ctx.offered_htlcs,
                    &straggler_ctx.received_htlcs,
                );
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_holder_broadcastable();
                let save = chan.enforcement_state.next_holder_commit_num;
                chan.enforcement_state.set_next_holder_commit_num_for_testing(0);
                let per_commitment_point = chan.get_per_commitment_point(0)?;
                chan.enforcement_state.set_next_holder_commit_num_for_testing(save);
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
                    redeem_scripts.iter().map(|sc| sc.as_bytes().to_vec()).collect();
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
            })
            .expect_err("the post-lock straggler must be rejected (the window is closed)");
    }
}
