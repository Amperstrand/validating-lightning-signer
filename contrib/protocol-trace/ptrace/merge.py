"""Run-directory assembler — one self-describing directory per execution.

    trace-runs/<run-id>/
        manifest.json        versions, env, repro command, source files
        trace.jsonl          merged, causally-ordered canonical trace
        trace.llm.md         deterministic LLM-oriented rendering
        results.json         scenario outcomes + invariant failures
        actors/<lane>.jsonl  per-actor(-instance) lane files
        artifacts/           content-addressed raw artifacts
        exports/perfetto.json  Chrome Trace JSON (generic timeline)

Merge order: wall clock first, then actor rank (driver < cln < vls),
then per-actor sequence — a causal *partial order* fallback for the
clock-skew case, never a claim that clocks are synchronized. Global
``seq`` is reassigned after the sort; per-actor ``actor_seq`` is kept.

Raw artifacts are content-addressed (``artifacts/sha256-<h>.<ext>``)
and de-duplicated; inline ``raw`` is kept only when short, replaced by
the ``sha256`` reference otherwise (the viewer fetches on demand).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from typing import Dict, List, Optional

from .schema import SCHEMA, LEGACY_SCHEMA, actor_rank, read_events

_ART_EXT = {"tx": "hex", "psbt": "psbt", "message": "txt", "other": "bin"}
_INLINE_RAW_LIMIT = 600  # bytes of raw kept inline; above -> sha256 ref only


def _git_describe(path: Optional[str]) -> Optional[str]:
    if not path or not os.path.isdir(path):
        return None
    try:
        out = subprocess.run(
            ["git", "-C", path, "describe", "--always", "--dirty", "--tags"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _lane_name(ev: Dict, fname: str) -> str:
    actor = ev.get("actor", "?")
    inst = ev.get("actor_instance")
    if inst:
        return "%s-%s" % (actor, inst)
    # derive from the source filename (vls-<pid>, cln-tap-<pid>, driver-<pid>)
    base = os.path.basename(fname).rsplit(".", 1)[0]
    if base.startswith("driver-"):
        return "driver"
    for prefix in ("cln-tap-", "vls-"):
        if base.startswith(prefix) and len(base) > len(prefix):
            return actor + "-p" + base[len(prefix):]
    return actor


def load_lanes(trace_dir: str) -> tuple:
    """All *.jsonl lanes in a trace dir -> (events-with-source, dropped, files)."""
    events: List[Dict] = []
    dropped = 0
    files = {}
    if not os.path.isdir(trace_dir):
        return events, dropped, files
    for fname in sorted(os.listdir(trace_dir)):
        if not fname.endswith(".jsonl"):
            continue
        path = os.path.join(trace_dir, fname)
        lane_events, lane_dropped = read_events(path)
        files[fname] = {"events": len(lane_events), "dropped": lane_dropped}
        dropped += lane_dropped
        for ev in lane_events:
            ev["_src"] = fname
        events.extend(lane_events)
    return events, dropped, files


def merge_order(ev: Dict) -> tuple:
    return (
        ev.get("ts_us") or 0,
        actor_rank(ev.get("actor", "?")),
        ev.get("actor_seq") or 0,
        str(ev.get("_src", "")),
    )


def extract_artifacts(events: List[Dict], out_dir: str) -> int:
    """Content-address artifacts; returns number of unique files written."""
    arts_dir = os.path.join(out_dir, "artifacts")
    os.makedirs(arts_dir, exist_ok=True)
    seen = {}
    count = 0
    for ev in events:
        arts = ev.get("artifacts")
        if not arts:
            continue
        for art in arts:
            raw = art.get("raw") or ""
            if raw:
                h = hashlib.sha256(raw.encode()).hexdigest()
                art["sha256"] = h
                if h not in seen:
                    ext = _ART_EXT.get(art.get("kind", "other"), "bin")
                    path = os.path.join(arts_dir, "sha256-%s.%s" % (h, ext))
                    if not os.path.exists(path):
                        with open(path, "w") as fh:
                            fh.write(raw)
                    # extensionless twin: the viewer's stable fetch path
                    twin = os.path.join(arts_dir, "sha256-%s" % h)
                    if not os.path.exists(twin):
                        with open(twin, "w") as fh:
                            fh.write(raw)
                    seen[h] = path
                    count += 1
                if len(raw) > _INLINE_RAW_LIMIT:
                    art["raw"] = ""  # viewer fetches via sha256
    return count


def assemble(
    trace_dir: str,
    out_dir: Optional[str] = None,
    *,
    vls_src: Optional[str] = None,
    cln_src: Optional[str] = None,
    command: Optional[str] = None,
    run_id: Optional[str] = None,
) -> str:
    """Assemble the run directory; returns its path."""
    out_dir = out_dir or os.path.join(
        os.path.dirname(os.path.abspath(trace_dir.rstrip("/"))),
        "trace-runs",
        run_id or time.strftime("%Y%m%d-%H%M%S"),
    )
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "actors"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "exports"), exist_ok=True)

    events, dropped, files = load_lanes(trace_dir)
    events.sort(key=merge_order)
    for i, ev in enumerate(events, 1):
        ev["seq"] = i

    art_count = extract_artifacts(events, out_dir)

    # merged canonical trace (strip the _src helper key)
    with open(os.path.join(out_dir, "trace.jsonl"), "w") as fh:
        for ev in events:
            clean = {k: v for k, v in ev.items() if k != "_src"}
            fh.write(json.dumps(clean, separators=(",", ":")) + "\n")

    # per-lane files
    lanes: Dict[str, List[Dict]] = {}
    for ev in events:
        lanes.setdefault(_lane_name(ev, ev.get("_src", "")), []).append(ev)
    lane_names = {}
    for lane, evs in sorted(lanes.items()):
        lane_names[lane] = len(evs)
        with open(os.path.join(out_dir, "actors", "%s.jsonl" % lane), "w") as fh:
            for ev in evs:
                clean = {k: v for k, v in ev.items() if k != "_src"}
                fh.write(json.dumps(clean, separators=(",", ":")) + "\n")

    # manifest
    node_map = {}
    meta_path = os.path.join(trace_dir, "driver-meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as fh:
                node_map = json.load(fh).get("nodes", {})
        except ValueError:
            node_map = {}
    # process-file names (vls-<pid>, cln-tap-<pid>) are lane identities,
    # not scenario ids — keep only meaningful scenario labels
    scenario_ids = sorted(
        {
            str(ev.get("scenario_id"))
            for ev in events
            if ev.get("scenario_id")
            and not re.match(r"^(vls|cln-tap|driver)-\d+$", str(ev.get("scenario_id")))
        }
    )
    schemas = sorted({str(ev.get("schema")) for ev in events if ev.get("schema")})
    level_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    for ev in events:
        level_counts[ev.get("level", "?")] = level_counts.get(ev.get("level", "?"), 0) + 1
        a = ev.get("actor", "?")
        actor_counts[a] = actor_counts.get(a, 0) + 1
    manifest = {
        "schema": SCHEMA,
        "schemas_seen": schemas,
        "legacy_lines_present": LEGACY_SCHEMA in schemas,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "run_id": run_id or next((ev.get("run_id") for ev in events if ev.get("run_id")), None),
        "scenario_ids": scenario_ids,
        "tool": "ptrace merge (contrib/protocol-trace)",
        "versions": {
            "vls": _git_describe(vls_src or os.environ.get("VLS_SRC")),
            "cln": _git_describe(cln_src or os.environ.get("PTRACE_CLN_SRC")),
            "ptrace": __import__("ptrace").__version__,
        },
        "env": {
            k: os.environ.get(k)
            for k in (
                "VLS_MODE", "VLS_PERMISSIVE", "VLS_TRACE_LEVEL",
                "VLS_TRACE_SCENARIO", "TEST_NETWORK",
            )
            if os.environ.get(k) is not None
        },
        "command": command or os.environ.get("PTRACE_COMMAND"),
        "random_seed": os.environ.get("PTRACE_SEED"),
        "source_files": files,
        "dropped_lines": dropped,
        "counts": {
            "events": len(events),
            "per_actor": actor_counts,
            "per_level": level_counts,
            "artifacts": art_count,
            "lanes": lane_names,
        },
        "node_map": node_map,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)

    # results
    results = {"scenarios": [], "failed_invariants": [], "totals": {
        "events": len(events), "dropped_lines": dropped}}
    for ev in events:
        etype = (ev.get("event") or {}).get("type")
        if etype == "scenario_end":
            results["scenarios"].append({
                "nodeid": (ev.get("event") or {}).get("_nodeid", ev.get("scenario_id")),
                "outcome": (ev.get("event") or {}).get("outcome"),
            })
        elif etype == "invariant" and not (ev.get("event") or {}).get("passed", True):
            results["failed_invariants"].append(ev.get("event"))
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(results, fh, indent=1)

    # renderings
    from .llm import render
    from .perfetto import export_chrome_trace

    with open(os.path.join(out_dir, "trace.llm.md"), "w") as fh:
        fh.write(render(events, manifest))
    with open(os.path.join(out_dir, "exports", "perfetto.json"), "w") as fh:
        json.dump(export_chrome_trace(events), fh)
    return out_dir
