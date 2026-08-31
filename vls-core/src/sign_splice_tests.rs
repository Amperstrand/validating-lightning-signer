#[cfg(test)]
mod tests {
    use bitcoin::bip32::DerivationPath;
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn};
    use bitcoin::blockdata::witness::Witness;
    use bitcoin::transaction::{Sequence, Version};
    use bitcoin::ScriptBuf;
    use test_log::test;

    use crate::util::status::Code;
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;

    fn splice_tx_spending(outpoint: OutPoint) -> Transaction {
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![],
        }
    }

    // R7 receive-side row 2 (the reestablish retransmit contract):
    // a SignSpliceTx REPLAY for the same inflight tx must return a
    // signature again. sign_splice_tx is stateless and the nonce is
    // RFC6979-deterministic, so the replay is byte-identical — pin
    // both properties (the disconnect_sig resume re-requests the
    // signature it already had pre-crash).
    #[test]
    fn sign_splice_tx_replay_deterministic() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup = make_test_channel_setup();
        let remote_key = setup.counterparty_points.funding_pubkey;
        let tx = splice_tx_spending(setup.funding_outpoint);

        let sig1 = node
            .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx, 0, &remote_key, None))
            .expect("first sign");
        let sig2 = node
            .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx, 0, &remote_key, None))
            .expect("replay sign");
        assert_eq!(
            sig1.serialize_compact(),
            sig2.serialize_compact(),
            "replayed SignSpliceTx returns the identical signature"
        );
    }

    // The funding-view chain (the RBF two-deep shape, dc5b77e7): after
    // TWO swaps without funding_locked (an aborted candidate replaced
    // by the next splice — R8.3 supersession), signing resolves EACH
    // outpoint against its OWN view's channel value. The wrong-value
    // refusals are the resolution proof: a mismatch error on outpoint X
    // with value V proves X resolved to a view whose value != V.
    #[test]
    fn sign_splice_tx_resolves_prev_chain() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup_a = make_test_channel_setup();
        let base = setup_a.channel_value_sat;

        let mut setup_b = setup_a.clone();
        setup_b.funding_outpoint.vout += 1;
        setup_b.channel_value_sat = base + 1000;
        let mut setup_c = setup_b.clone();
        setup_c.funding_outpoint.vout += 1;
        setup_c.channel_value_sat = base + 2000;

        node.setup_channel(channel_id.clone(), None, setup_b.clone(), &DerivationPath::master())
            .expect("swap A->B");
        node.setup_channel(channel_id.clone(), None, setup_c.clone(), &DerivationPath::master())
            .expect("superseding swap B->C (no funding_locked between)");

        let remote_key = setup_a.counterparty_points.funding_pubkey;
        for (outpoint, view_value) in [
            (setup_a.funding_outpoint, base),        // prev_prev (the original)
            (setup_b.funding_outpoint, base + 1000), // prev (the replaced candidate)
            (setup_c.funding_outpoint, base + 2000), // current
        ] {
            let tx = splice_tx_spending(outpoint);
            node.with_channel(&channel_id, |chan| {
                // resolution with the view's own value signs cleanly
                chan.sign_splice_tx(&tx, 0, &remote_key, Some(view_value))
            })
            .unwrap_or_else(|e| panic!("sign for {:?} failed: {:?}", outpoint, e));
            // ...and a foreign value is refused — proving WHICH view
            // the outpoint resolved to
            let err = node
                .with_channel(&channel_id, |chan| {
                    chan.sign_splice_tx(&tx, 0, &remote_key, Some(view_value + 1))
                })
                .expect_err("value mismatch must be refused");
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(err.message(), "splice input value is not the channel value");
        }
    }

    // refusal rail: an input that is none of the chain's funding
    // outpoints is not a splice of this channel
    #[test]
    fn sign_splice_tx_wrong_outpoint_refused() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup = make_test_channel_setup();
        let remote_key = setup.counterparty_points.funding_pubkey;
        let mut foreign = setup.funding_outpoint;
        foreign.vout += 7;
        let tx = splice_tx_spending(foreign);

        let err = node
            .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx, 0, &remote_key, None))
            .expect_err("foreign outpoint must be refused");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "splice input is not the channel funding outpoint");
    }

    // refusal rail (R21 F3's unit twin): a malformed/mismatched remote
    // funding key is an error return, never a panic
    #[test]
    fn sign_splice_tx_wrong_remote_key_refused() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup = make_test_channel_setup();
        let wrong_key = make_test_pubkey(42);
        let tx = splice_tx_spending(setup.funding_outpoint);

        let err = node
            .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx, 0, &wrong_key, None))
            .expect_err("wrong remote key must be refused");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "remote funding key mismatch");
    }

    // refusal rail: input index past the tx's inputs
    #[test]
    fn sign_splice_tx_input_index_out_of_range() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let setup = make_test_channel_setup();
        let remote_key = setup.counterparty_points.funding_pubkey;
        let tx = splice_tx_spending(setup.funding_outpoint);

        let err = node
            .with_channel(&channel_id, |chan| chan.sign_splice_tx(&tx, 3, &remote_key, None))
            .expect_err("out-of-range input index must be refused");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "splice input index out of range");
    }
}
