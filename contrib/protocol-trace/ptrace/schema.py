"""lightning-trace/1 envelope writer — mirrors vls-core/src/trace/event.rs.

The Rust sink assigns ``seq``/``actor_seq``/``ts_us``/``mono_us`` and
the schema/provenance/level stamps so emitters cannot get them wrong;
this writer does the same for the driver / cln-observer lanes (and any
future Python emitter).

Level filtering (matches the Rust sink):

* ``core``  — semantic events only; before/after snapshots and
  artifacts are dropped.
* ``base``  — + snapshots and decoded artifacts; artifact ``raw``
  payloads are stripped.
* ``extra`` — everything, raw bytes included.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Dict, Optional

SCHEMA = "lightning-trace/1"
LEGACY_SCHEMA = "vls-trace/1"  # accepted on read everywhere; never written

LEVELS = {"core": 0, "base": 1, "extra": 2}
LEVEL_NAMES = {0: "core", 1: "base", 2: "extra"}

# payload type -> (level, provenance). MUST mirror EventPayload in
# vls-core/src/trace/event.rs (fn trace_level / fn provenance).
#   level: core = semantic protocol narrative (CI-safe)
#          base = state snapshots / richer diagnostics
#   provenance: observed = the actor's own testimony
#               expected = driver assertions / declared models
# `derived` is consumer-only and intentionally absent.
PAYLOAD_META: Dict[str, tuple] = {
    # driver — narrative spine
    "scenario_start": ("core", "observed"),
    "scenario_end": ("core", "observed"),
    "step": ("core", "observed"),
    "inject": ("core", "observed"),
    "expect": ("core", "expected"),
    "invariant": ("core", "expected"),
    "state_declared": ("core", "expected"),
    "transition_declared": ("core", "expected"),
    # cln — observed at whatever boundary the source labels
    "cln_request": ("core", "observed"),
    "cln_response": ("core", "observed"),
    "cln_state": ("base", "observed"),
    "cln_event": ("core", "observed"),
    # vls — signer choke points
    "setup_channel": ("core", "observed"),
    "splice_setup": ("core", "observed"),
    "funding_view_resolved": ("base", "observed"),
    "sign_splice_tx": ("core", "observed"),
    "validate_holder_commitment": ("core", "observed"),
    "sign_counterparty_commitment": ("core", "observed"),
    "funding_locked": ("core", "observed"),
    "monitor_update": ("base", "observed"),
    "persisted": ("base", "observed"),
    "snapshot_checkpoint": ("base", "observed"),
    "restored": ("core", "observed"),
}

_ACTOR_RANK = {"driver": 0, "cln": 1, "vls": 2}

# Secret-shaped payload keys: the writer refuses them outright. The
# Rust builders are typed over public data only; this guards the open
# dict surface Python emitters have. (Addresses/txs/keys-that-are-public
# are fine on test networks; SECRET KEY MATERIAL is never fine.)
_SECRET_KEY_RE = re.compile(
    r"(secret|privkey|private_key|seed|mnemonic|hsm_secret|macaroon|xprv)",
    re.IGNORECASE,
)


def payload_meta(payload: Dict[str, Any]) -> tuple:
    """(level, provenance) for a payload dict; unknown types are base/observed."""
    return PAYLOAD_META.get(str(payload.get("type")), ("base", "observed"))


def provenance_of(payload: Dict[str, Any]) -> str:
    return payload_meta(payload)[1]


def actor_rank(actor: str) -> int:
    return _ACTOR_RANK.get(str(actor), 3)


def check_no_secrets(payload: Dict[str, Any]) -> None:
    """Raise if a payload key is secret-shaped (best-effort key-name guard)."""
    for key in payload:
        if _SECRET_KEY_RE.search(str(key)):
            raise ValueError(
                "refusing to trace secret-shaped payload key %r "
                "(lightning-trace never serializes key material)" % key
            )


class TraceWriter:
    """Thread-safe per-process JSONL writer for one actor lane.

    ``level`` filters attachments exactly like the Rust sink. The
    ``actor_instance`` label (e.g. ``l1``/``l2``) groups lanes in the
    viewer and is how a live farm's per-node vlsd/proxy files merge.
    """

    def __init__(
        self,
        path: str,
        actor: str,
        *,
        actor_instance: Optional[str] = None,
        run_id: Optional[str] = None,
        scenario_id: str = "",
        level: str = "base",
    ):
        self.path = path
        self.actor = actor
        self.actor_instance = actor_instance or os.environ.get("VLS_TRACE_INSTANCE") or None
        self.run_id = run_id or os.environ.get("VLS_TRACE_RUN_ID") or "%d-%d" % (
            time.time() * 1e6,
            os.getpid(),
        )
        self.scenario_id = scenario_id or os.environ.get("VLS_TRACE_SCENARIO", "")
        self.level_name = level
        self.level = LEVELS.get(level, 1)
        self._seq = 0
        self._actor_seq = 0
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._fh = open(path, "a", buffering=1)  # line-buffered: crash-safe

    # -- envelope assembly -------------------------------------------------
    def emit(
        self,
        payload: Dict[str, Any],
        *,
        correlation_id: Optional[str] = None,
        channel_id: Optional[str] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        artifacts: Optional[list] = None,
        result: Optional[Dict[str, Any]] = None,
        actor: Optional[str] = None,
        actor_instance: Optional[str] = None,
    ) -> Optional[dict]:
        """Emit one event; returns the envelope (None if level-filtered)."""
        check_no_secrets(payload)
        lvl_name, prov = payload_meta(payload)
        if LEVELS[lvl_name] > self.level:
            return None
        actor = actor or self.actor
        with self._lock:
            self._seq += 1
            self._actor_seq += 1
            env = {
                "schema": SCHEMA,
                "run_id": self.run_id,
                "scenario_id": self.scenario_id,
                "seq": self._seq,
                "actor": actor,
                "actor_instance": actor_instance if actor_instance is not None else self.actor_instance,
                "actor_seq": self._actor_seq,
                "ts_us": int(time.time() * 1e6),
                "mono_us": int((time.monotonic() - self._t0) * 1e6),
                "provenance": prov,
                "level": lvl_name,
                "correlation_id": correlation_id,
                "channel_id": channel_id,
                "event": payload,
            }
            if self.level >= LEVELS["base"]:
                if before is not None:
                    env["before"] = before
                if after is not None:
                    env["after"] = after
                if artifacts:
                    arts = []
                    for a in artifacts:
                        a = dict(a)
                        if self.level < LEVELS["extra"]:
                            a.pop("raw", None)
                        arts.append(a)
                    env["artifacts"] = arts
            if result is not None:
                env["result"] = result
            self._fh.write(json.dumps(env, separators=(",", ":")) + "\n")
            return env

    def close(self) -> None:
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass


def read_events(path: str, *, accept_legacy: bool = True) -> tuple:
    """Parse a JSONL lane file. Returns (events, dropped_line_count).

    Malformed lines are skipped and counted (a crash mid-write must not
    make the whole lane unreadable); unknown event types pass through
    (open-world contract).
    """
    events = []
    dropped = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    dropped += 1
                    continue
                if not isinstance(ev, dict) or "event" not in ev or "actor" not in ev:
                    dropped += 1
                    continue
                schema = ev.get("schema")
                if schema not in (SCHEMA, LEGACY_SCHEMA if accept_legacy else SCHEMA):
                    dropped += 1
                    continue
                events.append(ev)
    except FileNotFoundError:
        pass
    return events, dropped
