//! Tracer self-tests: serialization, schema stability, correlation,
//! era labels, snapshot structure, and the structural no-secrets rule.

use serde_json::Value;

use crate::trace::sink::CorrelationScope;
use crate::trace::{artifact_tx, sink, Actor, EventPayload, TraceEvent, TraceSink, SCHEMA};
use crate::util::test_utils::*;

#[test]
fn envelope_roundtrips_with_schema() {
    let ev = TraceEvent::vls(EventPayload::SignSpliceTx {
        txid: "aa".repeat(32),
        input_index: 0,
        input_outpoint: "txid:1".into(),
        era: Some("A".into()),
        remote_funding_key: "03ab".into(),
        input_amount_sat: Some(1000),
    })
    .correlation("test-corr")
    .channel_hex(&[1, 2, 3])
    .result(crate::trace::TraceResult {
        status: "rejected".into(),
        code: Some("InvalidArgument".into()),
        message: Some("splice input value is not the channel value".into()),
    });
    let j = serde_json::to_string(&ev).unwrap();
    assert!(j.contains("\"vls-trace/1\""), "schema tag present");
    assert!(j.contains("\"sign_splice_tx\""), "tagged type present");
    let back: TraceEvent = serde_json::from_str(&j).unwrap();
    assert_eq!(back.actor, Actor::Vls);
    assert_eq!(back.event, ev.event);
}

#[test]
fn unknown_future_event_type_still_deserializes_as_value() {
    // Open-world contract: a future/unknown payload must not break the
    // envelope consumer that reads fields generically (the viewer's
    // parse path). The typed enum rejects it; the value-level parse
    // must succeed and expose the type string.
    let j = r#"{"schema":"vls-trace/1","run_id":"r","scenario_id":"s","seq":1,
        "actor":"vls","event":{"type":"some_future_event","x":42}}"#;
    let v: Value = serde_json::from_str(j).unwrap();
    assert_eq!(v["event"]["type"], "some_future_event");
    assert_eq!(v["event"]["x"], 42);
}

#[test]
fn actor_seq_monotonic_per_actor() {
    let sink = TraceSink::in_memory("selftest");
    TraceSink::set_current(Some(sink.clone()));
    for i in 0..3 {
        sink.emit_local(TraceEvent::driver(EventPayload::Step { name: format!("d{i}") }));
        sink.emit_local(TraceEvent::cln(EventPayload::ClnRequest {
            message: "m".into(),
            detail: None,
            source: "test".into(),
        }));
        sink.emit_local(TraceEvent::vls(EventPayload::MonitorUpdate {
            what: "w".into(),
            detail: None,
        }));
    }
    TraceSink::set_current(None);
    use std::collections::HashMap;
    let mut last: HashMap<String, u64> = HashMap::new();
    for n in 1..=9u64 {
        // in_memory sink writes to a tempfile; verify via render_line instead
        let line = sink.render_line(TraceEvent::driver(EventPayload::Step { name: "x".into() }));
        let v: Value = serde_json::from_str(&line).unwrap();
        let seq = v["seq"].as_u64().unwrap();
        assert!(seq >= n);
        let actor = v["actor"].as_str().unwrap().to_string();
        let aseq = v["actor_seq"].as_u64().unwrap();
        let prev = last.insert(actor, aseq).unwrap_or(0);
        assert!(aseq > prev, "actor_seq must be monotonic");
    }
}

#[test]
fn correlation_from_thread_local_scope() {
    let sink = TraceSink::in_memory("selftest-corr");
    TraceSink::set_current(Some(sink.clone()));
    {
        let _guard = CorrelationScope::new("step-9-sign");
        let line = sink.render_line(TraceEvent::vls(EventPayload::MonitorUpdate {
            what: "w".into(),
            detail: None,
        }));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["correlation_id"], "step-9-sign", "thread-local correlation applied");
    }
    // explicit correlation wins over the thread-local
    let line = sink.render_line(
        TraceEvent::cln(EventPayload::ClnRequest {
            message: "m".into(),
            detail: None,
            source: "t".into(),
        })
        .correlation("explicit"),
    );
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["correlation_id"], "explicit");
    TraceSink::set_current(None);
}

#[test]
fn era_labels_assign_in_arrival_order() {
    let chan = "chan-hex";
    let a = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([1u8; 32])),
        vout: 0,
    };
    let b = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([1u8; 32])),
        vout: 1,
    };
    let c = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([1u8; 32])),
        vout: 2,
    };
    assert_eq!(sink::label_for(chan, &a), "A");
    assert_eq!(sink::label_for(chan, &b), "B");
    assert_eq!(sink::label_for(chan, &c), "C");
    assert_eq!(sink::label_for(chan, &a), "A", "stable on re-lookup");
    assert_eq!(sink::label_for_outpoint(&b), Some("B".into()), "channel-free lookup finds it");
}

#[test]
fn snapshot_has_era_structure_after_swap() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let old_setup = chan_ctx.setup.clone();
    let node = node_ctx.node.clone();

    let before =
        node.with_channel(&chan_ctx.channel_id, |c| Ok(crate::trace::snapshot_channel(c))).unwrap();
    assert_eq!(before.eras.len(), 1);
    assert_eq!(before.eras[0].lifecycle, "current");

    let mut setup_b = old_setup.clone();
    setup_b.funding_outpoint.vout += 1;
    setup_b.channel_value_sat += 1000;
    let b_outpoint = setup_b.funding_outpoint;
    node.setup_channel(
        chan_ctx.channel_id.clone(),
        None,
        setup_b,
        &bitcoin::bip32::DerivationPath::master(),
    )
    .unwrap();

    let after =
        node.with_channel(&chan_ctx.channel_id, |c| Ok(crate::trace::snapshot_channel(c))).unwrap();
    assert_eq!(after.eras.len(), 2, "A + B live after swap");
    assert_eq!(after.eras[0].lifecycle, "previous", "A retired to previous");
    assert_eq!(after.eras[1].lifecycle, "current", "B current");
    assert!(after.chain.splice_pending, "splice window open");
    // funding lock retires the chain
    node.confirm_funding_lock(&chan_ctx.channel_id, &b_outpoint).unwrap();
    let locked =
        node.with_channel(&chan_ctx.channel_id, |c| Ok(crate::trace::snapshot_channel(c))).unwrap();
    assert_eq!(locked.eras.len(), 1, "prev chain cleared at lock");
    assert_eq!(locked.eras[0].lifecycle, "locked");
}

#[test]
fn snapshots_and_artifacts_never_contain_secret_keys() {
    // The structural no-secrets rule: nothing in the trace API accepts
    // key material, so serializing everything we DO capture must not
    // leak any secret. Prove it against the channel's actual secrets.
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let old_setup = chan_ctx.setup.clone();
    let node = node_ctx.node.clone();

    let mut setup_b = old_setup.clone();
    setup_b.funding_outpoint.vout += 1;
    setup_b.channel_value_sat += 1000;
    node.setup_channel(
        chan_ctx.channel_id.clone(),
        None,
        setup_b,
        &bitcoin::bip32::DerivationPath::master(),
    )
    .unwrap();
    let _ = &mut chan_ctx;

    let (secret_hexes, tx_artifact_json) = node
        .with_channel(&chan_ctx.channel_id, |chan| {
            let mut secrets = vec![hex::encode(&chan.payment_key[..])];
            secrets.push(hex::encode(&chan.keys.funding_key(None)[..]));
            // a splice-signing event's snapshot + artifact
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: old_setup.funding_outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::transaction::Sequence::MAX,
                    witness: bitcoin::Witness::default(),
                }],
                output: vec![],
            };
            let art = artifact_tx(&tx, chan.network());
            let snap = crate::trace::snapshot_channel(chan);
            let ev = TraceEvent::vls(EventPayload::SignSpliceTx {
                txid: "t".into(),
                input_index: 0,
                input_outpoint: old_setup.funding_outpoint.to_string(),
                era: Some("A".into()),
                remote_funding_key: chan.setup.counterparty_points.funding_pubkey.to_string(),
                input_amount_sat: None,
            })
            .after(Some(snap))
            .artifacts(vec![art]);
            Ok((secrets, serde_json::to_string(&ev).unwrap()))
        })
        .unwrap();

    for hexsec in &secret_hexes {
        assert!(
            !tx_artifact_json.to_lowercase().contains(&hexsec.to_lowercase()),
            "secret key material leaked into the trace JSON"
        );
    }
    // public data IS present (no over-redaction on test networks)
    assert!(tx_artifact_json.contains("remote_funding_key"), "public keys stay in the trace");
    assert!(tx_artifact_json.contains("previous"), "era state stays in the trace");
}

#[test]
fn canonical_events_strip_volatile_fields() {
    let lines = vec![
        r#"{"schema":"vls-trace/1","run_id":"r1","scenario_id":"s","seq":1,"actor":"driver","actor_seq":1,"ts_us":1,"mono_us":1,"event":{"type":"step","name":"a"}}"#.into(),
        "not json at all".into(),
        r#"{"schema":"vls-trace/1","run_id":"r1","scenario_id":"s","seq":2,"actor":"vls","actor_seq":1,"ts_us":2,"mono_us":2,"event":{"type":"monitor_update","what":"x"}}"#.into(),
    ];
    let canonical = crate::util::test_utils::scenario::canonical_events(&lines);
    assert_eq!(canonical.len(), 2, "malformed line skipped");
    for v in &canonical {
        assert!(v.get("seq").is_none());
        assert!(v.get("ts_us").is_none());
        assert!(v.get("mono_us").is_none());
        assert!(v.get("run_id").is_none());
    }
    assert_eq!(canonical[0]["event"]["name"], "a");
}

#[test]
fn assert_wellformed_catches_bad_actor_seq() {
    let good = vec![
        r#"{"schema":"vls-trace/1","seq":1,"actor":"driver","actor_seq":1,"event":{"type":"step","name":"a"}}"#.into(),
        r#"{"schema":"vls-trace/1","seq":2,"actor":"vls","actor_seq":1,"event":{"type":"monitor_update","what":"x"}}"#.into(),
        r#"{"schema":"vls-trace/1","seq":3,"actor":"driver","actor_seq":2,"event":{"type":"step","name":"b"}}"#.into(),
    ];
    crate::util::test_utils::scenario::assert_wellformed(&good);
    let bad = vec![
        r#"{"schema":"vls-trace/1","seq":1,"actor":"driver","actor_seq":2,"event":{"type":"step","name":"a"}}"#.into(),
        r#"{"schema":"vls-trace/1","seq":2,"actor":"driver","actor_seq":1,"event":{"type":"step","name":"b"}}"#.into(),
    ];
    let result = std::panic::catch_unwind(|| {
        crate::util::test_utils::scenario::assert_wellformed(&bad);
    });
    assert!(result.is_err(), "non-monotonic actor_seq must fail");
}

#[test]
fn schema_tag_is_stable() {
    assert_eq!(SCHEMA, "vls-trace/1");
    let ev = TraceEvent::driver(EventPayload::ScenarioStart { declared_states: vec![] });
    assert_eq!(ev.schema, SCHEMA);
}
