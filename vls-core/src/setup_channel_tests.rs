#[cfg(test)]
mod tests {
    use crate::channel::ChannelId;
    use crate::policy::validator::CommitmentSignatures;
    use bitcoin;
    use bitcoin::bip32::DerivationPath;
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use bitcoin::blockdata::transaction::Sequence;
    use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn};
    use bitcoin::blockdata::witness::Witness;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use bitcoin::ScriptBuf;
    use lightning::ln::chan_utils::ChannelPublicKeys;
    use test_log::test;
    use vls_common::to_derivation_path;

    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (ScriptBuf::from(hex!($hex))));

    fn check_basepoints(basepoints: &ChannelPublicKeys) {
        let points = [
            basepoints.funding_pubkey,
            basepoints.revocation_basepoint.to_public_key(),
            basepoints.payment_point,
            basepoints.delayed_payment_basepoint.to_public_key(),
            basepoints.htlc_basepoint.to_public_key(),
        ]
        .iter()
        .map(|p| hex::encode(p.serialize().to_vec()))
        .collect::<Vec<_>>();

        assert_eq!(
            points,
            vec![
                "038ad68f4825b5b9db24e274d79b26887b46a70b8a16a720d69e363c858cd7907e",
                "02662e5e76a56a9dca49130bfd6990d9fc71501c4b7d799d253bbd365b72ac72d8",
                "03ee671ff5bf6450b8b3cad584b49a68265978f9b2bd5f7ff144eb6972dd6bd35a",
                "022e399383d20b0157178d8927a102829ddedd12cea977527afce1d374dbedd553",
                "02e25506cc6c4b9f888d682487d3b8d969a56e13b623da743d9c9d56c763931c49"
            ]
        );
    }

    #[test]
    fn setup_channel_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_channel(&channel_id, |c| {
            let params = c.make_channel_parameters();
            assert!(params.is_outbound_from_holder);
            assert_eq!(params.holder_selected_contest_delay, 6);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn setup_channel_not_exist_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());
        let status: Result<_, Status> = node.setup_channel(
            channel_id_x.clone(),
            None,
            make_test_channel_setup(),
            &DerivationPath::master(),
        );
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel does not exist: {}", &channel_id_x));
    }

    #[test]
    fn get_channel_basepoints_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let basepoints =
            node.with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints())).unwrap();

        check_basepoints(&basepoints);
    }

    #[test]
    fn setup_channel_dual_channelid_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");

        // Issue setup_channel w/ an alternate id.
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());
        node.setup_channel(
            channel_id.clone(),
            Some(channel_id_x.clone()),
            make_test_channel_setup(),
            &DerivationPath::master(),
        )
        .expect("setup_channel");

        // Original channel_id should work with_channel.
        let val = node.with_channel(&channel_id, |_chan| Ok(42)).expect("u32");
        assert_eq!(val, 42);

        // Alternate channel_id should work with_channel.
        let val_x = node.with_channel(&channel_id_x, |_chan| Ok(43)).expect("u32");
        assert_eq!(val_x, 43);
    }

    #[test]
    fn with_channel_not_exist_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let channel_id_x = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

        let status: Result<(), Status> = node.with_channel(&channel_id_x, |_chan| Ok(()));
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "no such channel: 0200000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn channel_stub_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");

        // with_channel should return not ready.
        let result: Result<(), Status> = node.with_channel(&channel_id, |_chan| {
            assert!(false); // shouldn't get here
            Ok(())
        });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel not ready: {}", TEST_CHANNEL_ID[0]),);

        let _: Result<(), Status> = node.with_channel_base(&channel_id, |base| {
            // get_per_commitment_point for the first commitment should work.
            let result = base.get_per_commitment_point(0);
            assert!(result.is_ok());

            // get_per_commitment_point for the second commitment should also work ([#245])
            let result = base.get_per_commitment_point(1);
            assert!(result.is_ok());

            // get_per_commitment_point for the third commitment should also work — LDK 0.2
            // eagerly fetches commitment point N+1 during funding_created/funding_signed
            // handling (see HolderCommitmentPoint::advance), which fires while we're still
            // in stub state.
            let result = base.get_per_commitment_point(2);
            assert!(result.is_ok());

            // get_per_commitment_point should not work beyond the third
            assert_failed_precondition_err!(
                base.get_per_commitment_point(3),
                "policy failure: channel stub can only return point for commitment number zero, one, or two"
            );

            // get_per_commitment_secret never works for a stub.
            assert_failed_precondition_err!(
                base.get_per_commitment_secret(0),
                "policy failure: channel stub cannot release commitment secret"
            );

            // get_per_commitment_secret_or_none always returns None for a stub
            assert_eq!(base.get_per_commitment_secret_or_none(0), None);

            Ok(())
        });

        let basepoints =
            node.with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints())).unwrap();
        // get_channel_basepoints should work.
        check_basepoints(&basepoints);

        // check_future_secret should work.
        let n: u64 = 10;
        let suggested = SecretKey::from_slice(
            hex_decode("2f87fef68f2bafdb3c6425921894af44da9a984075c70c7ba31ccd551b3585db")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let correct = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n, &suggested))
            .unwrap();
        assert_eq!(correct, true);

        let notcorrect = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n + 1, &suggested))
            .unwrap();
        assert_eq!(notcorrect, false);
    }

    #[ignore] // Ignore this test while we allow extra NewChannel calls.
    #[test]
    fn node_new_channel_already_exists_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // Try and create the channel again.
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let result = node.new_channel_with_id(channel_id, &node);
        let err = result.err().unwrap();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("channel already exists: {}", TEST_CHANNEL_ID[0]));
    }

    #[test]
    fn setup_channel_splice_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // A different setup for a Ready channel is CLN's post-splice
        // re-setup: a new funding outpoint with a new value.
        let mut setup1 = make_test_channel_setup();
        setup1.channel_value_sat += 1;
        setup1.funding_outpoint.vout += 1;
        let result =
            node.setup_channel(channel_id, None, setup1.clone(), &DerivationPath::master());
        let chan = result.expect("splice re-setup accepted");
        assert_eq!(chan.setup, setup1);
        assert!(chan.prev_setup.is_some(), "previous funding recorded");
    }

    #[test]
    fn setup_for_tx_funding_view_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // R10 both rails: a tx spending the CURRENT funding matches the
        // current setup; after a splice, a tx spending the PREVIOUS
        // funding matches the previous setup; anything else falls back
        // to the current view — the recomposition check downstream is
        // the guard (upstream parity for mutated-input probes).
        node.with_channel(&channel_id, |chan| {
            let empty_tx = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            };
            let v =
                chan.setup_for_tx(&empty_tx).expect("no-input tx falls back to the current view");
            assert_eq!(v.funding_outpoint, chan.setup.funding_outpoint);
            Ok(())
        })
        .expect("no-input case");

        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        let prev_outpoint = node
            .with_channel(&channel_id, |chan| Ok(chan.setup.funding_outpoint))
            .expect("cur outpoint");
        node.setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("splice swap");

        node.with_channel(&channel_id, |chan| {
            let build = |outpoint: OutPoint| Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }],
                output: vec![],
            };
            let v = chan.setup_for_tx(&build(chan.setup.funding_outpoint)).expect("current view");
            assert_eq!(v.funding_outpoint, chan.setup.funding_outpoint);
            let v = chan.setup_for_tx(&build(prev_outpoint)).expect("prev view");
            assert_eq!(v.funding_outpoint, prev_outpoint);
            // unknown funding input falls back to the current view — the
            // recomposition check downstream is the guard (upstream's
            // FailedPrecondition on mismatched recomposed txs)
            let v = chan.setup_for_tx(&build(OutPoint::null())).expect("fallback to current view");
            assert_eq!(v.funding_outpoint, chan.setup.funding_outpoint);
            Ok(())
        })
        .expect("views");
    }

    #[test]
    fn out_splice_value_arithmetic_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let base_value =
            node.with_channel(&channel_id, |chan| Ok(chan.setup.channel_value_sat)).expect("value");

        // R19.3 out-splice rail: the new funding may carry a REDUCED
        // channel_value (funds leave via the splice tx)
        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat = base_value - 100_000;
        setup2.funding_outpoint.vout += 1;
        let chan = node
            .setup_channel(channel_id.clone(), None, setup2.clone(), &DerivationPath::master())
            .expect("out-splice accepted");
        assert_eq!(chan.setup.channel_value_sat, base_value - 100_000);

        // wrapped-convention rail: CLN's splice re-setup encodes the
        // fundee-relative balance, negative on splice-outs, as a wrapped
        // near-u64::MAX push (observed live: 2^64-105801) — accepted;
        // the commitment validation checks the real balance split
        let mut wrapped = make_test_channel_setup();
        wrapped.channel_value_sat = base_value - 100_000;
        wrapped.funding_outpoint.vout += 3;
        wrapped.push_value_msat = u64::MAX - 105_801;
        node.setup_channel(channel_id.clone(), None, wrapped, &DerivationPath::master())
            .expect("wrapped (negative-relative) push accepted");

        // refusal rail: push_value exceeding the reduced value underflows
        // the balance split and is rejected by the setup validation
        let mut bad = make_test_channel_setup();
        bad.channel_value_sat = base_value - 100_000;
        bad.funding_outpoint.vout += 2;
        bad.push_value_msat = bad.channel_value_sat * 1000 + 1;
        assert!(
            node.setup_channel(channel_id, None, bad, &DerivationPath::master()).is_err(),
            "underflowing push rejected"
        );
    }

    #[test]
    fn funding_locked_idempotency_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        let chan = node
            .setup_channel(channel_id.clone(), None, setup2.clone(), &DerivationPath::master())
            .expect("splice swap");

        // R19.3 supersession rail: the lock is idempotent for the
        // confirmed funding and rejects a mismatched outpoint
        node.with_channel(&channel_id, |c| {
            c.confirm_funding_locked(&chan.setup.funding_outpoint).expect("lock");
            c.confirm_funding_locked(&chan.setup.funding_outpoint).expect("lock idempotent");
            let mut foreign = chan.setup.funding_outpoint;
            foreign.vout += 7;
            assert!(c.confirm_funding_locked(&foreign).is_err(), "foreign outpoint rejected");
            Ok(())
        })
        .expect("lock rails");
    }

    #[test]
    fn prev_funding_snapshot_lifecycle_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // R10.4/F1: the splice swap snapshots the retiring funding's
        // commitment state (the justice window) BEFORE the new funding's
        // flow rebuilds the channel-scoped fields
        let dummy_sigs = CommitmentSignatures(Signature::from_compact(&[0; 64]).unwrap(), vec![]);
        node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.current_holder_commit_info = Some(make_test_commitment_info());
            chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
            chan.enforcement_state.current_counterparty_commit_info =
                Some(make_test_commitment_info());
            Ok(chan.setup.funding_outpoint)
        })
        .expect("seed state");
        let old_outpoint = node
            .with_channel(&channel_id, |chan| Ok(chan.setup.funding_outpoint))
            .expect("old outpoint");

        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        let chan = node
            .setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("splice swap");

        // the snapshot holds the OLD funding's data...
        let snap = node
            .with_channel(&channel_id, |c| Ok(c.enforcement_state.prev_funding_commitment.clone()))
            .expect("snapshot")
            .expect("snapshot exists after swap");
        assert_eq!(snap.outpoint, old_outpoint);
        assert!(snap.current_holder_info.is_some(), "old holder info preserved");
        assert!(
            snap.current_counterparty_info.is_some(),
            "old counterparty info preserved (the rbf-stale fix)"
        );
        assert!(node
            .with_channel(&channel_id, |c| {
                Ok(c.enforcement_state.current_counterparty_commit_info.is_none())
            })
            .expect("counterparty moved"));
        // ...and the channel-scoped current was moved out (rebuilt by the new flow)
        assert!(node
            .with_channel(&channel_id, |c| {
                Ok(c.enforcement_state.current_holder_commit_info.is_none())
            })
            .expect("moved"));

        // the lock retires the snapshot (the splice tx spent the old funding)
        node.with_channel(&channel_id, |c| {
            c.confirm_funding_locked(&chan.setup.funding_outpoint).expect("lock");
            assert!(c.enforcement_state.prev_funding_commitment.is_none(), "retired at lock");
            Ok(())
        })
        .expect("retire");
    }

    #[test]
    fn splice_retires_old_tracker_listener() {
        // The fresh-vlsd restart crash (the rbo3 decode): the splice
        // path added the new funding's tracker listener without
        // retiring the old entry — the persisted map carried both, and
        // the node restore panicked with "some chain tracker listeners
        // were not restored". One channel = exactly one entry, keyed by
        // the CURRENT funding.
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let old_outpoint = node
            .with_channel(&channel_id, |chan| Ok(chan.setup.funding_outpoint))
            .expect("old outpoint");

        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        node.setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("splice swap");

        let keys: Vec<_> = node.get_tracker().listeners.keys().cloned().collect();
        assert!(!keys.contains(&old_outpoint), "old listener retired, got {:?}", keys);
        assert_eq!(keys.len(), 1, "exactly one listener entry, got {:?}", keys);
    }

    #[test]
    fn divergent_views_never_panic() {
        // R17.2 sketch 4: interleaved divergent access to both funding
        // views after the swap — view routing for both outpoints plus
        // the fallback shapes, the same-number re-sign mid-interleave,
        // then routing again — invariant: no panic, the numbering never
        // changes, the snapshot stays intact.
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let dummy_sigs = CommitmentSignatures(Signature::from_compact(&[0; 64]).unwrap(), vec![]);

        node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.current_holder_commit_info = Some(make_test_commitment_info());
            chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
            chan.enforcement_state.current_counterparty_commit_info =
                Some(make_test_commitment_info());
            chan.enforcement_state.set_next_holder_commit_num_for_testing(1);
            Ok(())
        })
        .expect("seed");

        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        node.setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("swap");

        node.with_channel(&channel_id, |chan| {
            let prev_outpoint =
                chan.enforcement_state.prev_funding_commitment.as_ref().expect("snapshot").outpoint;
            let cur_outpoint = chan.setup.funding_outpoint;
            assert_ne!(prev_outpoint, cur_outpoint);

            let build = |outpoint: OutPoint| Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }],
                output: vec![],
            };

            let v = chan.setup_for_tx(&build(cur_outpoint)).expect("current view");
            assert_eq!(v.funding_outpoint, cur_outpoint);
            let v = chan.setup_for_tx(&build(prev_outpoint)).expect("prev view");
            assert_eq!(v.funding_outpoint, prev_outpoint);
            let v = chan.setup_for_tx(&build(OutPoint::null())).expect("fallback view");
            assert_eq!(v.funding_outpoint, cur_outpoint);

            chan.enforcement_state.next_holder_commit_info =
                Some((make_test_commitment_info(), dummy_sigs.clone()));
            chan.activate_initial_commitment().expect("same-number re-sign");
            assert_eq!(
                chan.enforcement_state.next_holder_commit_num, 1,
                "numbering never advances on the interleave"
            );

            let snap =
                chan.enforcement_state.prev_funding_commitment.as_ref().expect("snapshot survives");
            assert!(snap.current_holder_info.is_some());
            assert!(snap.current_counterparty_info.is_some());

            let v = chan
                .setup_for_tx(&build(prev_outpoint))
                .expect("prev view still routed post-re-sign");
            assert_eq!(v.funding_outpoint, prev_outpoint);
            Ok(())
        })
        .expect("no panic, invariants held");
    }

    #[test]
    fn both_fundings_views_signable_post_swap() {
        // R17.2 sketch 3 (composite): after the splice swap, BOTH
        // funding views remain usable — the OLD funding's snapshot
        // record intact (justice), the NEW funding's same-number
        // re-sign rebuilding the channel-scoped state WITHOUT
        // advancing the numbering (reorgs/re-signs are not
        // commitments).
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let dummy_sigs = CommitmentSignatures(Signature::from_compact(&[0; 64]).unwrap(), vec![]);

        // the OLD funding's commitment state + a channel with history
        node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.current_holder_commit_info = Some(make_test_commitment_info());
            chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
            chan.enforcement_state.current_counterparty_commit_info =
                Some(make_test_commitment_info());
            chan.enforcement_state.set_next_holder_commit_num_for_testing(1);
            Ok(())
        })
        .expect("seed");

        // the splice swap
        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        node.setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("swap");

        // the NEW funding's same-number re-sign
        node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.next_holder_commit_info =
                Some((make_test_commitment_info(), dummy_sigs.clone()));
            chan.activate_initial_commitment().expect("same-number re-sign");
            // the numbering did NOT advance (1 -> 1, replace-in-place)
            assert_eq!(
                chan.enforcement_state.next_holder_commit_num, 1,
                "re-sign does not advance numbering"
            );
            // the channel-scoped state was rebuilt for the new funding
            assert!(chan.enforcement_state.current_holder_commit_info.is_some());
            // the OLD funding's record is intact (the justice window)
            let snap = chan
                .enforcement_state
                .prev_funding_commitment
                .as_ref()
                .expect("snapshot survives the re-sign");
            assert!(snap.current_holder_info.is_some(), "old holder info");
            assert!(snap.current_counterparty_info.is_some(), "old counterparty info");
            Ok(())
        })
        .expect("composite invariants");
    }

    #[test]
    fn setup_channel_splice_replay_idempotent() {
        // R7 receive-side row 1 (the resume/retransmit contract): CLN
        // re-drives the splice negotiation after a disconnect, which
        // re-sends the SAME hsmd_setup_channel — the replay must be
        // idempotent: accepted, with NO second snapshot (prev chain
        // unchanged) and no tracker churn.
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let orig = make_test_channel_setup();

        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        node.setup_channel(channel_id.clone(), None, setup2.clone(), &DerivationPath::master())
            .expect("splice swap");

        let (prev_before, prevprev_before, keys_before) = node
            .with_channel(&channel_id, |chan| {
                Ok((
                    chan.prev_setup.clone(),
                    chan.prev_prev_setup.clone(),
                    node.get_tracker().listeners.keys().cloned().collect::<Vec<_>>(),
                ))
            })
            .expect("state after first swap");
        assert_eq!(prev_before, Some(orig.clone()), "first swap recorded the original as prev");

        let chan = node
            .setup_channel(channel_id.clone(), None, setup2.clone(), &DerivationPath::master())
            .expect("splice replay accepted");
        assert_eq!(chan.setup, setup2);

        let (prev_after, prevprev_after, keys_after) = node
            .with_channel(&channel_id, |chan| {
                Ok((
                    chan.prev_setup.clone(),
                    chan.prev_prev_setup.clone(),
                    node.get_tracker().listeners.keys().cloned().collect::<Vec<_>>(),
                ))
            })
            .expect("state after replay");
        assert_eq!(
            prev_after,
            Some(orig),
            "replay does NOT re-snapshot (prev stays the original funding)"
        );
        assert_eq!(prevprev_after, prevprev_before, "replay does not deepen the prev chain");
        assert_eq!(keys_after, keys_before, "replay does not churn tracker listeners");
    }

    #[test]
    fn tx_aborted_candidate_superseded_by_next_splice() {
        // R8.3 supersession: a tx_abort'd (never confirmed) candidate is
        // REPLACED by the next splice's setup — no funding_locked in
        // between. The prev chain keeps every window funding's view
        // reachable (two-deep: original in prev_prev, the replaced
        // candidate in prev), and both remain signable.
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup_a = make_test_channel_setup();
        let base = setup_a.channel_value_sat;

        let mut setup_b = make_test_channel_setup();
        setup_b.funding_outpoint.vout += 1;
        setup_b.channel_value_sat = base + 1000;
        let mut setup_c = make_test_channel_setup();
        setup_c.funding_outpoint.vout += 2;
        setup_c.channel_value_sat = base + 2000;

        node.setup_channel(channel_id.clone(), None, setup_b, &DerivationPath::master())
            .expect("first swap (the candidate that will be tx_abort'd)");
        let chan = node
            .setup_channel(channel_id.clone(), None, setup_c.clone(), &DerivationPath::master())
            .expect("superseding swap accepted");
        assert_eq!(chan.setup, setup_c);
        assert_eq!(
            chan.prev_prev_setup.map(|s| s.funding_outpoint),
            Some(setup_a.funding_outpoint),
            "original funding preserved at two-deep"
        );
        assert!(chan.prev_setup.is_some(), "the replaced candidate is retained in the prev chain");

        // both retired views stay routable and signable
        node.with_channel(&channel_id, |chan| {
            let build = |outpoint: OutPoint| Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }],
                output: vec![],
            };
            let v = chan.setup_for_tx(&build(setup_a.funding_outpoint)).expect("orig view");
            assert_eq!(v.funding_outpoint, setup_a.funding_outpoint);
            let remote_key = setup_a.counterparty_points.funding_pubkey;
            chan.sign_splice_tx(&build(setup_a.funding_outpoint), 0, &remote_key, Some(base))
                .expect("orig funding still signable through the chain");
            Ok(())
        })
        .expect("supersession invariants");
    }

    #[test]
    fn setup_channel_incompatible_splice_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // Same funding outpoint with a different value is not a splice.
        let mut setup1 = make_test_channel_setup();
        setup1.channel_value_sat += 1;
        let result = node.setup_channel(channel_id, None, setup1, &DerivationPath::master());
        assert!(result.is_err());
    }

    #[test]
    fn setup_channel_unknown_holder_shutdown_script() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        let holder_shutdown_key_path = DerivationPath::master();
        let result = node.setup_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_failed_precondition_err!(
            result,
            "policy failure: validate_setup_channel: \
             holder_shutdown_script is not in wallet or allowlist"
        );
    }

    #[test]
    fn setup_channel_holder_shutdown_script_in_allowlist() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565"));
        node.add_allowlist(&vec!["tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string()])
            .expect("added allowlist");
        let holder_shutdown_key_path = DerivationPath::master();
        let result = node.setup_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_status_ok!(result);
    }

    #[test]
    fn setup_channel_holder_shutdown_script_in_wallet() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        node.new_channel_with_id(channel_id.clone(), &node).expect("new_channel");
        let mut setup = make_test_channel_setup();
        setup.holder_shutdown_script =
            Some(hex_script!("0014b76dd61e41b5ef052af21cda3260888c070bb9af"));
        let holder_shutdown_key_path = to_derivation_path(&[7u32]);
        let result = node.setup_channel(channel_id, None, setup.clone(), &holder_shutdown_key_path);
        assert_status_ok!(result);
    }
    #[test]
    fn activate_initial_commitment_same_num_splice_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        // Same-number (0) re-activation with a freshly-stored pending
        // commitment is the legal splice transition (BOLTs #1160 L1847);
        // a replay after the pending is consumed, or activation on an
        // advanced chain (num > 1), is rejected.
        let dummy_sigs = CommitmentSignatures(Signature::from_compact(&[0; 64]).unwrap(), vec![]);
        node.with_channel(&channel_id, |chan| {
            chan.enforcement_state.next_holder_commit_info =
                Some((make_test_commitment_info(), dummy_sigs.clone()));
            chan.activate_initial_commitment().expect("num-0 re-activation");
            assert!(chan.activate_initial_commitment().is_err(), "replay rejected");
            Ok(())
        })
        .expect("with_channel");

        // the splice swap creates the same-number window (the snapshot)
        let mut setup2 = make_test_channel_setup();
        setup2.channel_value_sat += 1;
        setup2.funding_outpoint.vout += 1;
        node.setup_channel(channel_id.clone(), None, setup2, &DerivationPath::master())
            .expect("splice swap");

        node.with_channel(&channel_id, |chan| {
            // same-number splice re-activation with a fresh pending (the
            // window is open): the current info is replaced in place, the
            // number does not advance
            chan.enforcement_state.next_holder_commit_info =
                Some((make_test_commitment_info(), dummy_sigs.clone()));
            chan.activate_initial_commitment().expect("splice re-activation");
            chan.enforcement_state.set_next_holder_commit_num_for_testing(2);
            chan.enforcement_state.next_holder_commit_info =
                Some((make_test_commitment_info(), dummy_sigs.clone()));
            assert!(chan.activate_initial_commitment().is_err(), "advanced chain rejected");
            Ok(())
        })
        .expect("with_channel");
    }
}
