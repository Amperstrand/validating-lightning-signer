"""Perfetto / Chrome Trace JSON exporter.

Generic timeline for free: one process per lane (driver, cln:l1,
vls:l1...), instants for point events, duration slices for
correlation-matched request/response pairs, and flow arrows for
cross-actor causal groups (shared correlation_id).

Lightning-specific semantics stay in the custom viewer; this export
answers "when, in what order, how long" — open the output at
https://ui.perfetto.dev "Open with legacy JSON".
"""

from __future__ import annotations

import zlib
from typing import Dict, List

from .schema import actor_rank

_PHASES = {"B", "E", "X", "i", "s", "t", "f", "M", "C"}


def _flow_id(correlation: str) -> int:
    # stable, collision-light id for a correlation string
    return zlib.crc32(correlation.encode()) & 0x7FFFFFFF


def export_chrome_trace(events: List[Dict]) -> Dict:
    """events (merged order) -> Chrome Trace JSON dict."""
    lanes: Dict[tuple, int] = {}  # (actor, instance) -> pid

    def pid_of(actor: str, inst) -> int:
        key = (actor, inst)
        if key not in lanes:
            base = (actor_rank(actor) + 1) * 100
            lanes[key] = base + len([k for k in lanes if k[0] == actor]) + 1
        return lanes[key]

    out: List[Dict] = []
    t0 = events[0].get("ts_us", 0) if events else 0

    # process metadata
    def meta_event(pid: int, name: str) -> Dict:
        return {"name": "process_name", "ph": "M", "pid": pid, "tid": 0,
                "args": {"name": name}}

    seen_meta = set()

    def ensure_meta(actor: str, inst, pid: int) -> None:
        name = actor.upper() + (":" + str(inst) if inst else "")
        if name not in seen_meta:
            seen_meta.add(name)
            out.append(meta_event(pid, name))

    # correlation analysis: request->response slices + cross-actor flows
    by_corr: Dict[str, List[Dict]] = {}
    for ev in events:
        corr = ev.get("correlation_id")
        if corr:
            by_corr.setdefault(corr, []).append(ev)

    slice_spans = {}  # (lane pid, corr) -> (ts_start, ts_end, name)
    flow_emitted = {}  # corr -> (first pid emitted)
    for corr, evs in by_corr.items():
        # request/response slice on the cln lane (proxy-tap pairs)
        reqs = [e for e in evs if (e.get("event") or {}).get("type") == "cln_request"]
        resps = [e for e in evs if (e.get("event") or {}).get("type") == "cln_response"]
        if reqs and resps:
            r0, s0 = reqs[0], resps[-1]
            pid = pid_of(r0.get("actor", "cln"), r0.get("actor_instance"))
            slice_spans[(pid, corr)] = (
                r0.get("ts_us", t0), s0.get("ts_us", t0),
                (r0.get("event") or {}).get("message", corr),
            )
        # cross-actor flow arrows (driver -> cln -> vls ...)
        actor_seq = []
        for e in evs:
            key = (e.get("actor"), e.get("actor_instance"))
            if key not in [a for a, _ in actor_seq]:
                actor_seq.append((key, e))
        if len(actor_seq) >= 2:
            fid = _flow_id(corr)
            first_pid = pid_of(*actor_seq[0][0])
            out.append({
                "name": "corr:%s" % corr[:40], "cat": "flow", "ph": "s",
                "pid": first_pid, "tid": 1, "ts": actor_seq[0][1].get("ts_us", t0),
                "id": fid, "args": {},
            })
            for key, e in actor_seq[1:]:
                pid = pid_of(*key)
                out.append({
                    "name": "corr:%s" % corr[:40], "cat": "flow", "ph": "t",
                    "pid": pid, "tid": 1, "ts": e.get("ts_us", t0),
                    "id": fid, "args": {},
                })

    # slices first (so instant overlay reads on top)
    for (pid, corr), (ts_a, ts_b, name) in sorted(slice_spans.items(), key=lambda kv: kv[1][0]):
        dur = max(ts_b - ts_a, 0)
        out.append({
            "name": "hsmd:%s" % name, "cat": "slice", "ph": "X",
            "pid": pid, "tid": 1, "ts": ts_a, "dur": dur,
            "args": {"correlation_id": corr},
        })

    for ev in events:
        actor = ev.get("actor", "?")
        inst = ev.get("actor_instance")
        pid = pid_of(actor, inst)
        ensure_meta(actor, inst, pid)
        payload = ev.get("event") or {}
        args = {
            "type": payload.get("type"),
            "provenance": ev.get("provenance"),
            "level": ev.get("level"),
        }
        for k in ("era", "commitment_number", "matched", "action", "name", "expect", "outcome"):
            if payload.get(k) is not None:
                args[k] = payload[k]
        if ev.get("result"):
            args["result"] = ev["result"].get("status")
            if ev["result"].get("code"):
                args["code"] = ev["result"]["code"]
        out.append({
            "name": str(payload.get("type", "event")),
            "cat": actor,
            "ph": "i",
            "s": "t",
            "pid": pid,
            "tid": 1,
            "ts": ev.get("ts_us", t0),
            "args": args,
        })

    return {"traceEvents": out}


def validate_chrome_trace(doc: Dict) -> List[str]:
    """Structural validation; returns list of problems (empty = valid)."""
    problems = []
    events = doc.get("traceEvents")
    if not isinstance(events, list):
        return ["missing traceEvents list"]
    has_terminate = False
    for i, ev in enumerate(events):
        if ev.get("ph") == "M":
            continue
        ph = ev.get("ph")
        if ph not in _PHASES:
            problems.append("event %d: bad phase %r" % (i, ph))
        if not isinstance(ev.get("ts"), int):
            problems.append("event %d: non-integer ts" % i)
        if not isinstance(ev.get("pid"), int):
            problems.append("event %d: non-integer pid" % i)
    # flow balance: every start (s) must have a step/finish (t/f) with same id
    starts = {}
    terms = set()
    for ev in events:
        if ev.get("cat") == "flow":
            if ev.get("ph") == "s":
                starts[ev.get("id")] = starts.get(ev.get("id"), 0) + 1
            elif ev.get("ph") in ("t", "f"):
                terms.add(ev.get("id"))
    for fid in starts:
        if fid not in terms:
            problems.append("flow id %r has start but no terminus" % fid)
    return problems
