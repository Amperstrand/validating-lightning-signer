"""ClnObserver — CLN's brain observed through STOCK CLN RPC facilities.

No CLN patch, no log parsing for state that a structured RPC field
already carries: channel/splice state comes from ``listpeerchannels``
(direct CLN observation, ``source: "cln-rpc"``). Everything recorded
is a verbatim-normalized RPC field; nothing here is inferred.

Visibility gaps (documented, not faked):

* transient channeld-internal states between RPC boundaries are NOT
  visible — snapshots exist only where the observer took them;
* in-flight splice detail is whatever ``listpeerchannels.inflights``
  exposes (feerate/total_funding/funding_fee + the ``last_tx`` hex,
  recorded as a sha256 fingerprint, never a fabricated txid);
* notification-driven observation (``channel_state_changed``) is a
  future surface; v1 snapshots at driver RPC boundaries, which is
  exactly where the narrative needs them.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

SOURCE = "cln-rpc"


def _msat(v: Any) -> Optional[int]:
    """Parse an msat field ('123msat' | int) to int msat."""
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v)
    if s.endswith("msat"):
        s = s[:-4]
    try:
        return int(s)
    except ValueError:
        return None


def _tx_fingerprint(hexstr: Any) -> Optional[str]:
    """sha256 fingerprint of a raw tx hex — an identity tag, NOT a txid
    (txid requires non-witness serialization we don't attempt here)."""
    if not hexstr or not isinstance(hexstr, str):
        return None
    return "sha256:" + hashlib.sha256(hexstr.encode()).hexdigest()[:16]


def normalize_channel(ch: Dict[str, Any]) -> Dict[str, Any]:
    """listpeerchannels entry -> flat cln_state detail dict (verbatim fields)."""
    out: Dict[str, Any] = {}
    for key in ("channel_id", "state", "status", "peer_id", "peer_connected",
                "short_channel_id", "feerate", "channel_type", "last_stable_connection"):
        if key in ch and ch[key] is not None:
            out[key] = ch[key]
    ft, fo = ch.get("funding_txid"), ch.get("funding_outnum")
    if ft:
        out["funding_outpoint"] = "%s:%s" % (ft, fo if fo is not None else "?")
    for key in ("total_msat", "our_amount_msat", "their_amount_msat",
                "spendable_msat", "receivable_msat", "funding_fee_msat",
                "lease_fee_msat", "push_msat"):
        v = _msat(ch.get(key))
        if v is not None:
            out[key] = v
    inflights = ch.get("inflights") or []
    if inflights:
        ifs = []
        for inf in inflights:
            entry = {}
            for key in ("channel_id", "feerate"):
                if inf.get(key) is not None:
                    entry[key] = inf[key]
            for key in ("total_funding_msat", "funding_fee_msat"):
                v = _msat(inf.get(key))
                if v is not None:
                    entry[key] = v
            fp = _tx_fingerprint(inf.get("last_tx"))
            if fp:
                entry["last_tx_fp"] = fp
            ifs.append(entry)
        out["inflights"] = ifs
    return out


def funding_of(detail: Dict[str, Any]) -> Optional[str]:
    """The outpoint CLN currently considers the channel funding (if any)."""
    return detail.get("funding_outpoint")


class ClnObserver:
    """Snapshot CLN's channel state around interesting driver operations.

    ``rpc`` is any callable ``(method, payload) -> result`` that talks to
    a real lightningd (pyln ``LightningRpc.call`` or a raw JSON-RPC
    function). Snapshots are honest observations at observation time —
    the trace records *when* they were taken (``why``), never pretends
    to be continuous.
    """

    def __init__(self, writer, instance: Optional[str] = None):
        self.writer = writer
        self.instance = instance
        self._depth = 0  # recursion guard: snapshot RPCs must not re-enter

    def snapshot(self, rpc, why: str, *, channel_id: Optional[str] = None) -> List[dict]:
        """Emit one cln_state event per channel (all, or one selected)."""
        if self._depth:
            return []
        emitted = []
        self._depth += 1
        try:
            try:
                res = rpc("listpeerchannels", {})
            except TypeError:  # 1-arg callable form
                res = rpc("listpeerchannels")
            channels = res.get("channels", []) if isinstance(res, dict) else []
            for ch in channels:
                detail = normalize_channel(ch)
                if channel_id and ch.get("channel_id") != channel_id:
                    continue
                env = self.writer.emit(
                    {"type": "cln_state", "source": SOURCE, "why": why,
                     "current_funding": funding_of(detail), "detail": detail},
                    actor="cln",
                    actor_instance=self.instance,
                    channel_id=ch.get("channel_id"),
                )
                if env:
                    emitted.append(env)
        except Exception as exc:  # observation must never kill the test
            self.writer.emit(
                {"type": "cln_event", "what": "observer_error", "source": SOURCE,
                 "detail": {"error": str(exc)[:200], "why": why}},
                actor="cln",
                actor_instance=self.instance,
            )
        finally:
            self._depth -= 1
        return emitted
