"""pytest driver-lane plugin — the narrative spine for live CLN+VLS runs.

Activated only when ``VLS_TRACE_DIR`` is set (inert otherwise). Loads
via ``-p ptrace.pytest_plugin`` with ``contrib/protocol-trace`` on
``PYTHONPATH`` (the splice-dev gate wires both). Zero CLN-tree changes:
the plugin wraps pyln-testing at runtime —

* ``LightningRpc.call`` interception: splice/fault/payment RPCs become
  driver ``step``+``inject`` events with CLN ``cln_state`` snapshots
  taken BEFORE and AFTER the call (stock ``listpeerchannels``);
* ``LightningNode.restart`` interception: ``restart_cln`` injections;
* pytest hooks: ``scenario_start``/``scenario_end`` per test, an
  ``invariant`` event recording the outcome.

Everything the driver lane says is ``observed`` driver behavior or
``expected`` assertions — the provenance stamp comes from the payload
type, never from the caller.
"""

from __future__ import annotations

import json
import os
import re
import threading

from .schema import TraceWriter

# RPC methods that advance the scenario narrative. value = the inject
# action name used in the trace.
DRIVING_RPCS = {
    "splice_init": "splice_init",
    "splice_update": "splice_update",
    "splice_signed": "splice_signed",
    "splice_abort": "tx_abort",
    "dev_disconnect": "fault_injected",
    "dev_fail": "fault_injected",
    "close": "mutual_close",
    "fundchannel": "fund_channel",
    "fundchannel_start": "fund_channel",
    "connect": "connect",
    "disconnect": "disconnect",
    "pay": "payment_start",
    "invoice": "invoice",
    "keysend": "payment_start",
    "dev-feerate": "feerate_change",
}

# methods whose before/after CLN state matters most — snapshot around them
SNAPSHOT_RPCS = {
    "splice_init",
    "splice_update",
    "splice_signed",
    "splice_abort",
    "dev_disconnect",
    "close",
}

# response fields worth keeping (small, public, forensic)
_RESULT_FIELDS = ("txid", "channel_id", "commitments_secured")

_state = threading.local()
_writer = None          # type: ignore
_observer_cls = None


def _safe_args(method, payload):
    """Compact, secret-free arg summary for the trace."""
    if payload is None:
        return None
    if not isinstance(payload, dict):
        return {"arg": str(payload)[:80]}
    out = {}
    for k, v in payload.items():
        s = v if isinstance(v, (int, float, bool)) else str(v)
        s = str(s)
        out[k] = s if len(s) <= 96 else s[:93] + "..."
    return out


def pytest_configure(config):
    global _writer, _observer_cls
    trace_dir = os.environ.get("VLS_TRACE_DIR", "")
    if not trace_dir:
        return
    from .cln_observer import ClnObserver  # noqa: F401  (kept for API symmetry)

    _observer_cls = ClnObserver
    level = os.environ.get("VLS_TRACE_LEVEL", "base")
    _writer = TraceWriter(
        os.path.join(trace_dir, "driver-%d.jsonl" % os.getpid()),
        "driver",
        scenario_id=os.environ.get("VLS_TRACE_SCENARIO", "live-gate"),
        level=level,
    )
    _install_pyln_hooks(trace_dir)


def _install_pyln_hooks(trace_dir: str) -> None:
    """Wrap pyln-testing at runtime (no CLN-tree patching)."""
    try:
        from pyln.client.lightning import LightningRpc
        import pyln.testing.utils as pyln_utils
    except ImportError:
        _writer and _writer.emit(
            {"type": "cln_event", "what": "pyln_unavailable",
             "source": "driver", "detail": None},
            actor="cln",
        )
        return

    orig_call = LightningRpc.call
    orig_init = pyln_utils.LightningNode.__init__
    orig_restart = pyln_utils.LightningNode.restart

    # LightningRpc.__getattr__ fabricates an RPC wrapper for any unknown
    # attribute name (getattr-with-default therefore NEVER returns the
    # default) — instance caches must read __dict__ directly.
    def _instance_of(rpc_self):
        return rpc_self.__dict__.get("_ptrace_instance")

    def _observer_for(rpc_self):
        from .cln_observer import ClnObserver

        obs = rpc_self.__dict__.get("_ptrace_observer")
        if obs is None:
            obs = ClnObserver(_writer, _instance_of(rpc_self))
            rpc_self._ptrace_observer = obs
        return obs

    def wrapped_init(self, *args, **kwargs):
        orig_init(self, *args, **kwargs)
        try:
            ldir = str(getattr(self, "lightning_dir", ""))
            instance = os.path.basename(ldir.rstrip("/")) or None
            if instance:
                instance = re.sub(r"^lightning-(\d+)$", r"l\1", instance)
            self.rpc._ptrace_instance = instance
            _register_node(instance, ldir, os.getpid())
        except Exception:
            pass

    def wrapped_restart(self, *args, **kwargs):
        instance = getattr(getattr(self, "rpc", None), "_ptrace_instance", None)
        _writer and _writer.emit(
            {"type": "inject", "action": "restart_cln",
             "detail": {"instance": instance}},
            actor_instance=None,
        )
        res = orig_restart(self, *args, **kwargs)
        try:
            if _writer:
                from .cln_observer import ClnObserver

                ClnObserver(_writer, instance).snapshot(
                    _raw_rpc(self.rpc), "after restart_cln"
                )
        except Exception:
            pass
        return res

    def _raw_rpc(rpc_obj):
        """Snapshot transport that bypasses the interception entirely."""
        return lambda method, payload=None: orig_call(rpc_obj, method, payload)

    in_flight = threading.local()

    def wrapped_call(self, method, payload=None, *args, **kwargs):
        action = DRIVING_RPCS.get(method)
        if _writer is None or action is None or getattr(in_flight, "on", False):
            return orig_call(self, method, payload, *args, **kwargs)
        in_flight.on = True
        try:
            step = "%s(%s)" % (
                method,
                ",".join("%s=%s" % kv for kv in sorted((_safe_args(method, payload) or {}).items()))[:60],
            )
            corr = "rpc-%s-%d" % (method, _writer._actor_seq + 1)
            _writer.emit({"type": "step", "name": step}, correlation_id=corr)
            _writer.emit(
                {"type": "inject", "action": action, "detail": _safe_args(method, payload)},
                correlation_id=corr,
            )
            if method in SNAPSHOT_RPCS:
                _observer_for(self).snapshot(_raw_rpc(self), "before " + method)
            try:
                res = orig_call(self, method, payload, *args, **kwargs)
            except Exception as exc:
                _writer.emit(
                    {"type": "expect", "expect": method, "outcome": "fail",
                     "detail": {"error": str(exc)[:200]}},
                    correlation_id=corr,
                )
                raise
            if method in SNAPSHOT_RPCS:
                _observer_for(self).snapshot(_raw_rpc(self), "after " + method)
            detail = None
            if isinstance(res, dict):
                keep = {k: res[k] for k in _RESULT_FIELDS if res.get(k) is not None}
                if keep:
                    detail = keep
            _writer.emit(
                {"type": "expect", "expect": method, "outcome": "ok", "detail": detail},
                correlation_id=corr,
            )
            return res
        finally:
            in_flight.on = False

    LightningRpc.call = wrapped_call
    pyln_utils.LightningNode.__init__ = wrapped_init
    pyln_utils.LightningNode.restart = wrapped_restart

    _writer.emit(
        {"type": "cln_event", "what": "pyln_hooks_installed", "source": "driver",
         "detail": {"trace_dir": trace_dir}},
        actor="cln",
    )


_NODE_MAP = {}
_NODE_MAP_LOCK = threading.Lock()
_META_PATH = None


def _register_node(instance, lightning_dir, pid):
    with _NODE_MAP_LOCK:
        _NODE_MAP[instance or "?"] = {
            "lightning_dir": lightning_dir,
            "pytest_pid": pid,
        }


def pytest_runtest_logstart(nodeid, location):
    if _writer is not None:
        _writer.emit({"type": "scenario_start", "declared_states": [], "_nodeid": nodeid})


def pytest_runtest_logreport(report):
    if _writer is None or report.when != "call":
        return
    detail = None
    if report.longrepr:
        detail = {"error": str(report.longrepr)[:1000]}
    _writer.emit(
        {"type": "invariant", "name": report.nodeid,
         "passed": report.passed, "detail": detail},
        correlation_id=report.nodeid,
    )
    _writer.emit(
        {"type": "scenario_end", "outcome": report.outcome, "_nodeid": report.nodeid},
    )


def pytest_unconfigure(config):
    global _writer
    if _writer is None:
        return
    try:
        with _NODE_MAP_LOCK:
            meta = {"nodes": _NODE_MAP, "schema_note": "instance = basename(lightning_dir)"}
            meta_path = os.path.join(os.environ.get("VLS_TRACE_DIR", "."), "driver-meta.json")
            with open(meta_path, "w") as fh:
                json.dump(meta, fh, indent=1)
    except Exception:
        pass
    _writer.close()
    _writer = None
