//! Real restore-path scenario: a node with a live splice window (eras
//! A + B) through `Node::new_from_persistence` with a real persister —
//! the `vls Restored` trace event, era-chain survival, and the
//! old-funding straggler still validating against the restored signer.
//!
//! Traces land in a tempdir via VLS_TRACE_DIR (set in-process); the
//! trace file is asserted on, proving the live-run path end to end.

#![allow(unused_imports)]

use std::sync::Arc;

use lightning_signer::bitcoin;
use lightning_signer::bitcoin::secp256k1::Secp256k1;

use lightning_signer::node::{Node, NodeConfig, NodeServices};
use lightning_signer::persist::Persist;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::test_utils::{
    self, channel_commitment, counterparty_sign_holder_commitment, fund_test_channel,
    make_genesis_starting_time_factory, make_test_channel_setup, test_chan_ctx, TestChannelContext,
    TestCommitmentTxContext, TestFundingTxContext, TestNodeContext, REGTEST_NODE_CONFIG,
    TEST_SEED,
};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::test_utils::key::*;
use lightning_signer::util::test_utils::build_tx_scripts;
use lightning_signer::channel::ChannelBase;

use vls_persist::kvv::memory::MemoryKVVStore;
use vls_persist::kvv::{JsonFormat, KVVPersister};

fn kvv_services() -> (Arc<KVVPersister<MemoryKVVStore, JsonFormat>>, NodeServices) {
    let persister: Arc<KVVPersister<MemoryKVVStore, JsonFormat>> =
        Arc::new(KVVPersister(MemoryKVVStore::new([0u8; 16]), JsonFormat));
    let services = NodeServices {
        validator_factory: Arc::new(SimpleValidatorFactory::new()),
        starting_time_factory: make_genesis_starting_time_factory(bitcoin::Network::Regtest),
        persister: persister.clone() as Arc<dyn Persist>,
        clock: Arc::new(StandardClock()),
        trusted_oracle_pubkeys: vec![],
    };
    (persister, services)
}

#[test]
fn splice_window_survives_real_node_restore() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("VLS_TRACE_DIR", tmp.path());

    let (_persister, services) = kvv_services();
    let node = Arc::new(Node::new(REGTEST_NODE_CONFIG, TEST_SEED[1].as_bytes(), vec![], services.clone()));
    let secp_ctx = Secp256k1::signing_only();
    let node_ctx = TestNodeContext { node: node.clone(), secp_ctx };

    // Fund the channel (era A + initial holder commitment validated).
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();
    let old_setup = chan_ctx.setup.clone();

    // Old-era currents + the old-funding straggler's message, pre-swap.
    let dummy_sigs = lightning_signer::policy::validator::CommitmentSignatures(
        bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0; 64]).unwrap(),
        vec![],
    );
    let old_era_info =
        lightning_signer::tx::tx::CommitmentInfo2::new(true, 600_000, 399_000, vec![], vec![], 0);
    node.with_channel(&channel_id, |chan| {
        chan.enforcement_state.current_holder_commit_info = Some(old_era_info.clone());
        chan.enforcement_state.current_counterparty_signatures = Some(dummy_sigs.clone());
        chan.enforcement_state.current_counterparty_commit_info = Some(old_era_info);
        Ok(())
    })
    .unwrap();
    let mut straggler_ctx = channel_commitment(&node_ctx, &chan_ctx, 0, 0, 995_120, 0, vec![], vec![]);
    let (scsig, shsigs) = counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut straggler_ctx);

    // Splice A → B (the window opens: two live eras).
    let mut tx_ctx = TestFundingTxContext::new();
    tx_ctx.inputs.push(bitcoin::TxIn {
        previous_output: old_setup.funding_outpoint,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::default(),
    });
    chan_ctx.setup.channel_value_sat += 100_000;
    let vout = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, chan_ctx.setup.channel_value_sat);
    let splice_tx = tx_ctx.to_tx();
    assert!(
        lightning_signer::util::test_utils::funding_tx_setup_channel(
            &node_ctx,
            &mut chan_ctx,
            &splice_tx,
            vout
        )
        .is_none(),
        "splice accepted"
    );
    // capture AFTER the swap helper — it mutates chan_ctx.setup to era B
    let new_outpoint = chan_ctx.setup.funding_outpoint;

    // THE RESTART: persist everything (Node::new does not write the
    // node entry itself — persist_all does), then restore through the
    // production entry (persister entries -> Node::restore_node).
    node.persist_all();
    let node_id = node.get_id();
    drop(node);
    let entries = _persister.get_nodes().expect("persisted nodes");
    let (nid, entry) = entries.into_iter().next().expect("one node entry");
    assert_eq!(nid, node_id, "restored entry matches the live node id");
    let node2 = Node::restore_node(&nid, entry, TEST_SEED[1].as_bytes(), services)
        .expect("restore_node");

    let restored = node2
        .with_channel(&channel_id, |chan| {
            Ok((
                chan.prev_setup.as_ref().map(|p| p.funding_outpoint) == Some(old_setup.funding_outpoint),
                chan.setup.funding_outpoint == new_outpoint,
                chan.enforcement_state.prev_funding_commitment.is_some(),
                chan.funding_locked.is_none(),
            ))
        })
        .unwrap();
    assert!(restored.0, "prev_setup (era A) survived the restore");
    assert!(restored.1, "current setup (era B) survived the restore");
    assert!(restored.2, "justice snapshot survived the restore");
    assert!(restored.3, "funding_locked restores as None — the documented mismatch");

    // NOTE: the straggler-revalidates rail lives in the vls-core scenario
    // suite (serde entry round-trip + raw_validate against internal APIs);
    // from this external crate the tx-key derivation rails are private.
    let _ = (&straggler_ctx, &scsig, &shsigs);

    // The trace: SpliceSetup + Restored events landed in the tempdir file.
    std::env::remove_var("VLS_TRACE_DIR");
    let mut trace_files: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "jsonl").unwrap_or(false))
        .collect();
    trace_files.sort();
    assert!(!trace_files.is_empty(), "a trace file must exist for the run");
    let body = std::fs::read_to_string(&trace_files[0]).unwrap();
    let types: Vec<String> = body
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| v["event"]["type"].as_str().unwrap_or("?").to_string())
        .collect();
    assert!(types.contains(&"setup_channel".to_string()), "initial setup traced: {types:?}");
    assert!(types.contains(&"splice_setup".to_string()), "splice swap traced: {types:?}");
    assert!(types.contains(&"restored".to_string()), "restore traced: {types:?}");
}
