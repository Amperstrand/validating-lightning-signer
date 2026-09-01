"""Trace-system self-tests (no pyln, no CLN, no network).

Covers: envelope serialization + schema versioning, secret refusal,
provenance/level stamping, level filtering of attachments, malformed
and partial streams, merge ordering + content-addressed artifacts,
renderer determinism, Perfetto structural validity, and the ClnObserver
normalization against recorded listpeerchannels shapes.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ptrace.cln_observer import normalize_channel  # noqa: E402
from ptrace.llm import render  # noqa: E402
from ptrace.merge import assemble  # noqa: E402
from ptrace.perfetto import export_chrome_trace, validate_chrome_trace  # noqa: E402
from ptrace.schema import (  # noqa: E402
    LEGACY_SCHEMA,
    SCHEMA,
    TraceWriter,
    check_no_secrets,
    payload_meta,
    read_events,
)


def make_writer(tmpdir, actor="driver", name="w", **kw):
    return TraceWriter(os.path.join(tmpdir, name + ".jsonl"), actor, **kw)


def synth_stream(tmpdir, name="vls-4242", instance="l1"):
    """A realistic three-lane miniature: driver + cln + vls events."""
    w = TraceWriter(os.path.join(tmpdir, name + ".jsonl"), "vls",
                    actor_instance=instance, scenario_id="unit_stream",
                    level="extra")  # extra keeps raw artifacts (content-addressing path)
    chan = "ab" * 32
    w.emit({"type": "setup_channel", "outpoint": "f0:0", "value_sat": 1_000_000,
            "push_msat": 0, "remote_funding_key": "02aa"},
           channel_id=chan, after={"channel_id": chan, "eras": [
               {"label": "A", "outpoint": "f0:0", "value_sat": 1_000_000,
                "lifecycle": "current"}]})
    w.emit({"type": "splice_setup", "from_outpoint": "f0:0", "to_outpoint": "f1:0",
            "value_sat": 1_100_000, "push_msat": 0, "remote_funding_key": "02aa",
            "prev_chain_depth": 1},
           channel_id=chan,
           after={"channel_id": chan, "eras": [
               {"label": "A", "outpoint": "f0:0", "lifecycle": "previous"},
               {"label": "B", "outpoint": "f1:0", "lifecycle": "current"}]},
           result={"status": "accepted"})
    w.emit({"type": "sign_splice_tx", "txid": "f1" * 32, "input_index": 0,
            "input_outpoint": "f0:0", "era": "A", "remote_funding_key": "02aa"},
           channel_id=chan,
           artifacts=[{"kind": "tx", "raw": "deadbeef" * 200, "decoded": {"txid": "f1" * 32}}],
           result={"status": "rejected", "code": "InvalidArgument",
                   "message": "splice input is not the channel value"})
    w.close()
    return w.path


class TestSchema(unittest.TestCase):
    def test_envelope_carries_schema_and_stamps(self):
        with tempfile.TemporaryDirectory() as td:
            w = make_writer(td)
            env = w.emit({"type": "step", "name": "splice_init"})
            self.assertEqual(env["schema"], SCHEMA)
            self.assertEqual(env["schema"], "lightning-trace/1")
            self.assertEqual(env["provenance"], "observed")
            self.assertEqual(env["level"], "core")
            self.assertGreater(env["seq"], 0)
            w.close()
            events, dropped = read_events(w.path)
            self.assertEqual((len(events), dropped), (1, 0))

    def test_expected_provenance_for_assertions(self):
        self.assertEqual(payload_meta({"type": "expect"})[1], "expected")
        self.assertEqual(payload_meta({"type": "invariant"})[1], "expected")
        self.assertEqual(payload_meta({"type": "state_declared"})[1], "expected")
        self.assertEqual(payload_meta({"type": "cln_state"})[1], "observed")
        self.assertEqual(payload_meta({"type": "sign_splice_tx"})[1], "observed")

    def test_secret_shaped_payload_keys_refused(self):
        with self.assertRaises(ValueError):
            check_no_secrets({"type": "step", "hsm_secret": "x"})
        with self.assertRaises(ValueError):
            check_no_secrets({"type": "step", "funding_privkey": "x"})
        check_no_secrets({"type": "step", "remote_funding_key": "02aa"})  # public ok

    def test_writer_refuses_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            w = make_writer(td)
            with self.assertRaises(ValueError):
                w.emit({"type": "inject", "action": "x", "seed": "deadbeef"})
            w.close()

    def test_level_filtering_attachments(self):
        with tempfile.TemporaryDirectory() as td:
            snap = {"eras": [{"label": "A"}]}
            art = [{"kind": "tx", "raw": "aa" * 32, "decoded": {"txid": "t"}}]
            core = TraceWriter(os.path.join(td, "core.jsonl"), "vls", level="core")
            base = TraceWriter(os.path.join(td, "base.jsonl"), "vls", level="base")
            extra = TraceWriter(os.path.join(td, "extra.jsonl"), "vls", level="extra")
            for w in (core, base, extra):
                w.emit({"type": "sign_splice_tx", "txid": "t", "input_index": 0,
                        "input_outpoint": "f:0", "remote_funding_key": "02"},
                       before=snap, after=snap, artifacts=list(art))
                w.close()
            ce, _ = read_events(os.path.join(td, "core.jsonl"))
            be, _ = read_events(os.path.join(td, "base.jsonl"))
            ee, _ = read_events(os.path.join(td, "extra.jsonl"))
            self.assertNotIn("before", ce[0]); self.assertNotIn("artifacts", ce[0])
            self.assertIn("before", be[0])
            self.assertNotIn("raw", be[0]["artifacts"][0])  # raw stripped at base
            self.assertEqual(ee[0]["artifacts"][0]["raw"], "aa" * 32)

    def test_base_level_events_filtered_at_core(self):
        with tempfile.TemporaryDirectory() as td:
            w = TraceWriter(os.path.join(td, "c.jsonl"), "cln", level="core")
            env = w.emit({"type": "cln_state", "source": "cln-rpc",
                          "current_funding": "f:0", "detail": {}})
            self.assertIsNone(env)  # base-level payload suppressed at core
            w.close()

    def test_malformed_and_partial_streams(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "broken.jsonl")
            with open(p, "w") as fh:
                fh.write(json.dumps({"schema": SCHEMA, "actor": "vls",
                                     "event": {"type": "step", "name": "ok"}}) + "\n")
                fh.write("{not json\n")
                fh.write('{"schema":"other/1","event":{}}\n')
                fh.write('{"schema": "%s"' % SCHEMA)  # truncated mid-line
            events, dropped = read_events(p)
            self.assertEqual(len(events), 1)
            self.assertEqual(dropped, 3)

    def test_legacy_vls_trace_lines_still_parse(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "legacy.jsonl")
            with open(p, "w") as fh:
                fh.write(json.dumps({
                    "schema": LEGACY_SCHEMA, "run_id": "r", "scenario_id": "s",
                    "seq": 1, "actor": "vls", "actor_seq": 1, "ts_us": 1,
                    "event": {"type": "monitor_update", "what": "x"}}) + "\n")
            events, dropped = read_events(p)
            self.assertEqual((len(events), dropped), (1, 0))

    def test_unknown_future_event_open_world(self):
        self.assertEqual(payload_meta({"type": "wire_splice_gossip_v9"}),
                         ("base", "observed"))  # unknown = base/observed, still parses


class TestMerge(unittest.TestCase):
    def test_merge_orders_by_time_then_actor_rank(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "lanes")
            os.makedirs(d)
            # vls event happens "first" by wall clock but vls ranks last
            with open(os.path.join(d, "vls-9.jsonl"), "w") as fh:
                fh.write(json.dumps({"schema": SCHEMA, "actor": "vls", "ts_us": 100,
                                     "actor_seq": 1, "event": {"type": "step", "name": "v"}}) + "\n")
            with open(os.path.join(d, "cln-tap-8.jsonl"), "w") as fh:
                fh.write(json.dumps({"schema": SCHEMA, "actor": "cln", "ts_us": 200,
                                     "actor_seq": 1, "event": {"type": "step", "name": "c"}}) + "\n")
                fh.write(json.dumps({"schema": SCHEMA, "actor": "cln", "ts_us": 150,
                                     "actor_seq": 2, "event": {"type": "step", "name": "c2"}}) + "\n")
            with open(os.path.join(d, "driver-7.jsonl"), "w") as fh:
                fh.write(json.dumps({"schema": SCHEMA, "actor": "driver", "ts_us": 100,
                                     "actor_seq": 1, "event": {"type": "step", "name": "d"}}) + "\n")
            out = assemble(d, os.path.join(td, "run"), command="pytest ...",
                           vls_src=None, cln_src=None)
            with open(os.path.join(out, "trace.jsonl")) as fh:
                merged = [json.loads(l) for l in fh]
            # same ts (100): driver ranks before vls
            self.assertEqual([e["event"]["name"] for e in merged], ["d", "v", "c2", "c"])
            self.assertEqual([e["seq"] for e in merged], [1, 2, 3, 4])
            lanes = os.listdir(os.path.join(out, "actors"))
            self.assertIn("vls-p9.jsonl", lanes)
            self.assertIn("cln-p8.jsonl", lanes)
            self.assertIn("driver.jsonl", lanes)
            man = json.load(open(os.path.join(out, "manifest.json")))
            self.assertEqual(man["counts"]["events"], 4)
            self.assertEqual(man["command"], "pytest ...")

    def test_artifacts_content_addressed_and_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            raw = "deadbeef" * 200  # matches synth_stream; > inline limit
            p = synth_stream(td)
            out = assemble(os.path.dirname(p), os.path.join(td, "run"))
            with open(os.path.join(out, "trace.jsonl")) as fh:
                merged = [json.loads(l) for l in fh]
            arts = [a for e in merged for a in e.get("artifacts", [])]
            self.assertTrue(arts)
            art = arts[0]
            self.assertTrue(art.get("sha256"))
            self.assertEqual(art.get("raw", ""), "")  # big raw replaced by reference
            refs = os.listdir(os.path.join(out, "artifacts"))
            self.assertTrue(any(art["sha256"] in f for f in refs))
            with open(os.path.join(out, "artifacts", refs[0])) as fh:
                self.assertEqual(fh.read(), raw)

    def test_partial_lane_missing_files_tolerated(self):
        with tempfile.TemporaryDirectory() as td:
            # only a driver lane; no cln/vls files at all
            d = os.path.join(td, "lanes")
            os.makedirs(d)
            with open(os.path.join(d, "driver-1.jsonl"), "w") as fh:
                fh.write(json.dumps({"schema": SCHEMA, "actor": "driver", "ts_us": 5,
                                     "actor_seq": 1, "event": {"type": "scenario_start"}}) + "\n")
            out = assemble(d, os.path.join(td, "run"))
            self.assertTrue(os.path.exists(os.path.join(out, "trace.jsonl")))
            self.assertTrue(os.path.exists(os.path.join(out, "exports", "perfetto.json")))


class TestRender(unittest.TestCase):
    def test_deterministic_and_information_dense(self):
        with tempfile.TemporaryDirectory() as td:
            p = synth_stream(td)
            events, _ = read_events(p)
            r1, r2 = render(events), render(events)
            self.assertEqual(r1, r2)
            self.assertIn("sign_splice_tx", r1)
            self.assertIn("era=A", r1)
            self.assertIn("InvalidArgument", r1)
            self.assertIn("A[previous", r1)  # era lifecycle visible
            self.assertIn("derived", r1)  # footer honestly labeled

    def test_render_handles_minimal_and_empty(self):
        self.assertIn("0 events", render([]))
        r = render([{"schema": SCHEMA, "actor": "cln", "ts_us": 1, "actor_seq": 1,
                     "event": {"type": "cln_state", "detail": {"state": "CHANNELD_NORMAL"}},
                     "provenance": "observed", "level": "base"}])
        self.assertIn("CHANNELD_NORMAL", r)


class TestPerfetto(unittest.TestCase):
    def test_export_validates(self):
        with tempfile.TemporaryDirectory() as td:
            p = synth_stream(td)
            events, _ = read_events(p)
            doc = export_chrome_trace(events)
            problems = validate_chrome_trace(doc)
            self.assertEqual(problems, [])
            names = [e["name"] for e in doc["traceEvents"]]
            self.assertIn("setup_channel", names)

    def test_flow_arrows_for_correlated_cross_actor_events(self):
        evs = [
            {"schema": SCHEMA, "actor": "driver", "actor_instance": None, "ts_us": 10,
             "actor_seq": 1, "correlation_id": "rpc-x", "event": {"type": "step", "name": "s"}},
            {"schema": SCHEMA, "actor": "cln", "actor_instance": "l1", "ts_us": 20,
             "actor_seq": 1, "correlation_id": "rpc-x", "event": {"type": "cln_request", "message": "SignSpliceTx"}},
            {"schema": SCHEMA, "actor": "vls", "actor_instance": "l1", "ts_us": 30,
             "actor_seq": 1, "correlation_id": "rpc-x", "event": {"type": "sign_splice_tx", "txid": "t"}},
        ]
        doc = export_chrome_trace(evs)
        problems = validate_chrome_trace(doc)
        self.assertEqual(problems, [])
        flows = [e for e in doc["traceEvents"] if e.get("cat") == "flow"]
        self.assertEqual(len(flows), 3)  # 1 start + 2 termini

    def test_request_response_slice(self):
        evs = [
            {"schema": SCHEMA, "actor": "cln", "actor_instance": "l1", "ts_us": 100,
             "actor_seq": 1, "correlation_id": "c1", "event": {"type": "cln_request", "message": "SignCommitmentTx"}},
            {"schema": SCHEMA, "actor": "cln", "actor_instance": "l1", "ts_us": 350,
             "actor_seq": 2, "correlation_id": "c1", "event": {"type": "cln_response", "message": "Signature"}},
        ]
        doc = export_chrome_trace(evs)
        slices = [e for e in doc["traceEvents"] if e.get("ph") == "X"]
        self.assertEqual(len(slices), 1)
        self.assertEqual(slices[0]["dur"], 250)
        self.assertIn("SignCommitmentTx", slices[0]["name"])


class TestClnObserver(unittest.TestCase):
    def test_normalize_listpeerchannels_splice_window(self):
        # recorded shape (CLN v26.06 regtest, mid-splice)
        ch = {
            "channel_id": "cd" * 32, "state": "CHANNELD_AWAITING_SPLICE",
            "peer_id": "03ff", "funding_txid": "ab" * 32, "funding_outnum": 0,
            "total_msat": "1000000000msat", "our_amount_msat": "500000000msat",
            "inflights": [{
                "channel_id": "cd" * 32, "feerate": 1500,
                "total_funding_msat": "1100000000msat",
                "funding_fee_msat": "10000000sat",
                "last_tx": "0200000001abcdef",
            }],
        }
        d = normalize_channel(ch)
        self.assertEqual(d["state"], "CHANNELD_AWAITING_SPLICE")
        self.assertEqual(d["funding_outpoint"], "%s:0" % ("ab" * 32))
        self.assertEqual(d["total_msat"], 1000000000)
        self.assertEqual(d["inflights"][0]["total_funding_msat"], 1100000000)
        self.assertTrue(d["inflights"][0]["last_tx_fp"].startswith("sha256:"))
        self.assertNotIn("last_tx", d["inflights"][0])  # raw hex not copied

    def test_normalize_minimal_channel(self):
        d = normalize_channel({"channel_id": "aa", "state": "CHANNELD_NORMAL"})
        self.assertEqual(d, {"channel_id": "aa", "state": "CHANNELD_NORMAL"})

    def test_observer_snapshot_emits_and_survives_rpc_errors(self):
        with tempfile.TemporaryDirectory() as td:
            w = make_writer(td, name="cln", actor="cln")
            from ptrace.cln_observer import ClnObserver

            obs = ClnObserver(w, "l1")
            good_rpc = lambda m, p=None: {"channels": [
                {"channel_id": "aa", "state": "CHANNELD_NORMAL",
                 "funding_txid": "bb", "funding_outnum": 1}]}
            emitted = obs.snapshot(good_rpc, "before splice_init")
            self.assertEqual(len(emitted), 1)
            self.assertEqual(emitted[0]["event"]["detail"]["state"], "CHANNELD_NORMAL")
            self.assertEqual(emitted[0]["actor_instance"], "l1")

            def bad_rpc(m, p=None):
                raise RuntimeError("connection refused")

            emitted = obs.snapshot(bad_rpc, "after restart_cln")
            self.assertEqual(emitted, [])  # error becomes a cln_event, not a crash
            w.close()
            events, dropped = read_events(w.path)
            types = [e["event"]["type"] for e in events]
            self.assertIn("cln_state", types)
            self.assertIn("cln_event", types)


class TestCli(unittest.TestCase):
    def test_cli_merge_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "lanes")
            os.makedirs(d)
            synth_stream(td, name="vls-11")
            root = os.path.dirname(os.path.abspath(__file__))
            cli = os.path.join(root, "..", "ptrace", "cli.py")
            out = subprocess.run(
                [sys.executable, cli, "merge", d, "--out", os.path.join(td, "run"),
                 "--command", "unit"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("run dir:", out.stdout)
            for f in ("trace.jsonl", "trace.llm.md", "manifest.json",
                      "results.json", "exports/perfetto.json"):
                self.assertTrue(os.path.exists(os.path.join(td, "run", f)), f)


if __name__ == "__main__":
    unittest.main(verbosity=2)
