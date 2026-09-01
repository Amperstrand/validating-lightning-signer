"""Deterministic trace-to-text renderer (trace.llm.md).

One rendering pass over the SAME structured events the viewer reads —
never a second logging system. Information-dense, LLM-friendly, and
byte-stable for a given trace.jsonl (only relative time is rendered,
so re-rendering a copied trace produces identical output).

Anything this module computes and states beyond the events themselves
(e.g. the era-lineage footer) is explicitly labeled ``derived`` — the
renderer is a consumer, and consumers never present inference as
implementation testimony.
"""

from __future__ import annotations

from typing import Dict, List, Optional

_MAX = 88


def _short(v, n=_MAX) -> str:
    s = str(v)
    return s if len(s) <= n else s[: n - 3] + "..."


def _era_line(snap: Dict) -> str:
    eras = snap.get("eras") or []
    parts = []
    for era in eras:
        label = era.get("label", "?")
        life = era.get("lifecycle", "?")
        val = era.get("value_sat", "?")
        parts.append("%s[%s,%s]" % (label, life, val))
    chain = snap.get("chain") or {}
    flags = []
    if chain.get("splice_pending"):
        flags.append("splice-window")
    if chain.get("funding_locked_outpoint"):
        flags.append("locked=%s" % _short(chain["funding_locked_outpoint"], 20))
    ens = snap.get("enforcement") or {}
    if ens:
        flags.append(
            "nH=%s nC=%s nR=%s" % (
                ens.get("next_holder_commit_num", "?"),
                ens.get("next_counterparty_commit_num", "?"),
                ens.get("next_counterparty_revoke_num", "?"),
            )
        )
    return " ".join(parts) + ("  (" + " ".join(flags) + ")" if flags else "")


def _snapshot_delta(ev: Dict) -> Optional[str]:
    before, after = ev.get("before"), ev.get("after")
    if not before or not after:
        return None
    b_lifecycles = {e.get("outpoint"): e.get("lifecycle") for e in before.get("eras", [])}
    changes = []
    for era in after.get("eras", []):
        op = era.get("outpoint")
        prev = b_lifecycles.get(op)
        if prev != era.get("lifecycle"):
            label = era.get("label", "?")
            changes.append("%s:%s->%s" % (label, prev or "absent", era.get("lifecycle")))
    b_count = len(before.get("eras", []))
    a_count = len(after.get("eras", []))
    if b_count != a_count:
        changes.append("eras %d->%d" % (b_count, a_count))
    return "; ".join(changes) if changes else None


def _detail_lines(detail: Optional[Dict]) -> List[str]:
    if not detail:
        return []
    out = []
    for k in sorted(detail):
        v = detail[k]
        if isinstance(v, (dict, list)):
            v = _short(v, 70)
        out.append("      %s=%s" % (k, _short(v)))
    return out


def render(events: List[Dict], manifest: Optional[Dict] = None) -> str:
    """Render events to markdown. Deterministic for a fixed input list."""
    lines: List[str] = []
    scenario_ids = sorted({str(e.get("scenario_id")) for e in events if e.get("scenario_id")})
    header = "# lightning-trace/1 — %s (%d events)" % (
        ", ".join(scenario_ids) or "<no-scenario>", len(events)
    )
    lines.append(header)
    if manifest:
        v = manifest.get("versions") or {}
        lines.append(
            "run %s · vls %s · cln %s · tool %s"
            % (
                manifest.get("run_id") or "?",
                v.get("vls") or "?",
                v.get("cln") or "?",
                "ptrace/%s" % (manifest.get("tool", "").split()[0] if manifest.get("tool") else "?"),
            )
        )
    lines.append("")

    t0 = events[0].get("ts_us") if events else 0
    last_state: Dict[str, Dict] = {}  # actor+instance -> last snapshot

    for i, ev in enumerate(events):
        ev_type = (ev.get("event") or {}).get("type", "?")
        actor = ev.get("actor", "?")
        inst = ev.get("actor_instance")
        lane = "%s%s" % (actor.upper(), (":" + inst) if inst else "")
        rel = ((ev.get("ts_us") or 0) - (t0 or 0)) / 1000.0
        prov = ev.get("provenance", "?")
        lvl = ev.get("level", "?")
        seq = ev.get("seq", i + 1)
        lines.append("[%4d] %s  t=%+9.1fms  %s/%s" % (seq, lane.ljust(8), rel, prov, lvl))
        payload = ev.get("event") or {}

        if ev_type in ("cln_request", "cln_response"):
            src = payload.get("source", "?")
            msg = payload.get("message", "?")
            lines.append("      %s %s (source=%s)" % (ev_type, msg, src))
        elif ev_type == "cln_state":
            d = payload.get("detail") or {}
            state = d.get("state", "?")
            fund = payload.get("current_funding")
            infl = d.get("inflights") or []
            bits = ["state=%s" % state]
            if fund:
                bits.append("funding=%s" % _short(fund, 24))
            if infl:
                bits.append("inflights=%d" % len(infl))
            lines.append("      cln_state %s" % " ".join(bits))
        elif ev_type in ("setup_channel", "splice_setup"):
            lines.append(
                "      %s %s -> %s  value=%s push=%s prev_depth=%s"
                % (
                    ev_type,
                    payload.get("from_outpoint", "genesis"),
                    payload.get("to_outpoint", payload.get("outpoint", "?")),
                    payload.get("value_sat", "?"),
                    payload.get("push_msat", "?"),
                    payload.get("prev_chain_depth", "-"),
                )
            )
        elif ev_type in ("sign_splice_tx",):
            lines.append(
                "      sign_splice_tx txid=%s input=%s era=%s"
                % (_short(payload.get("txid"), 16), payload.get("input_outpoint", "?"), payload.get("era", "?"))
            )
        elif ev_type in ("validate_holder_commitment", "sign_counterparty_commitment"):
            lines.append(
                "      %s funding=%s era=%s num=%s feerate=%s htlcs=%s to_holder=%s to_cp=%s"
                % (
                    ev_type,
                    _short(payload.get("funding_outpoint"), 24),
                    payload.get("era", "?"),
                    payload.get("commitment_number", "?"),
                    payload.get("feerate_per_kw", "?"),
                    payload.get("htlc_count", "?"),
                    payload.get("to_holder_sat", "-"),
                    payload.get("to_counterparty_sat", "-"),
                )
            )
        elif ev_type == "funding_view_resolved":
            lines.append(
                "      funding_view_resolved txid=%s -> %s era=%s matched=%s"
                % (_short(payload.get("txid"), 16), payload.get("resolved_outpoint", "?"), payload.get("era", "?"), payload.get("matched"))
            )
        elif ev_type == "funding_locked":
            retired = payload.get("retired") or []
            lines.append(
                "      funding_locked outpoint=%s era=%s retired=%s"
                % (_short(payload.get("outpoint"), 24), payload.get("era", "?"), ",".join(retired) or "-")
            )
        elif ev_type in ("step", "inject", "expect", "invariant", "scenario_start", "scenario_end"):
            name = payload.get("name") or payload.get("action") or payload.get("expect") or payload.get("outcome", "")
            extra = ""
            if ev_type == "inject":
                extra = " " + _short(payload.get("detail") or {}, 60)
            if ev_type == "invariant":
                extra = " passed=%s" % payload.get("passed")
            lines.append("      %s: %s%s" % (ev_type, _short(name), extra))
        else:
            # generic: first-order fields only
            flat = {k: v for k, v in payload.items() if not isinstance(v, (dict, list))}
            lines.append("      %s" % _short(flat, 110))

        for extra in _detail_lines(payload.get("detail") if ev_type not in ("cln_state",) else None):
            lines.append(extra)
        if payload.get("detail") and ev_type == "cln_state":
            for extra in _detail_lines({k: v for k, v in payload["detail"].items() if k in ("status", "short_channel_id", "our_amount_msat", "total_msat")}):
                lines.append(extra)

        delta = _snapshot_delta(ev)
        if ev.get("after"):
            lines.append("      state: %s" % _era_line(ev["after"]))
            last_state["%s:%s" % (actor, inst or "")] = ev["after"]
        if delta:
            lines.append("      delta: %s" % delta)
        if ev.get("result"):
            r = ev["result"]
            lines.append(
                "      result: %s%s%s"
                % (
                    r.get("status", "?"),
                    " code=%s" % r["code"] if r.get("code") else "",
                    " %s" % _short(r.get("message"), 70) if r.get("message") else "",
                )
            )
        for art in ev.get("artifacts") or []:
            ref = art.get("sha256") or "inline"
            lines.append("      artifact %s %s" % (art.get("kind", "?"), ref))

    # ---- derived footer (clearly labeled; consumer-computed) ----
    lines.append("")
    lines.append("## DERIVED (renderer-computed, provenance=derived — not implementation testimony)")
    for key, snap in sorted(last_state.items()):
        lines.append("- last %s snapshot: %s" % (key.replace(":", "/"), _era_line(snap)))
    if not last_state:
        lines.append("- no VLS snapshots in trace")
    return "\n".join(lines) + "\n"
