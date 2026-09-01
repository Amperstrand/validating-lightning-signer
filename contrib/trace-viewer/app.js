/* vls-trace/1 splice trace viewer — vanilla JS, no dependencies.
 * Loads one or more .jsonl trace files (file picker works from file://;
 * ?trace=name.jsonl works when served), merges them by timestamp, and
 * renders the three-brain swimlane timeline with playback, state
 * snapshots, era lineage, diffs and artifact inspection.
 */
"use strict";

const SCHEMA = "vls-trace/1";
const state = {
  events: [],        // merged, sorted, indexed
  filtered: [],      // indices into events
  selected: -1,      // index into filtered
  eraFilter: null,   // era label or null
  malformed: 0,
  sources: [],
  eraByOutpoint: new Map(), // outpoint -> label
  lineage: [],       // [{from, to, fromLabel, toLabel}]
};

// ---------------------------------------------------------------- parsing

function parseJsonl(text, source) {
  const out = [];
  let bad = 0;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let ev;
    try { ev = JSON.parse(t); } catch { bad++; continue; }
    if (!ev || typeof ev !== "object" || !ev.event || !ev.actor) { bad++; continue; }
    if (ev.schema && ev.schema !== SCHEMA) { bad++; continue; }
    if (!ev.seq) ev.seq = out.length; // partial-trace tolerance
    ev._src = source;
    out.push(ev);
  }
  return { events: out, bad };
}

function mergeEvents(batches) {
  const all = batches.flat();
  all.sort((a, b) => (a.ts_us ?? 0) - (b.ts_us ?? 0) || (a.seq ?? 0) - (b.seq ?? 0));
  all.forEach((e, i) => { e._i = i; });
  return all;
}

function outpointShort(o) {
  if (!o) return "?";
  const [txid, vout] = String(o).split(":");
  return `${txid.slice(0, 8)}:${vout}`;
}
function keyShort(k) { return k ? String(k).slice(0, 10) + "…" : "?"; }

// ---------------------------------------------------------------- era model

function buildEraModel() {
  // era labels + outpoints from snapshots (authoritative), then lineage
  // from splice_setup events.
  for (const ev of state.events) {
    for (const snapKey of ["after", "before"]) {
      const snap = ev[snapKey];
      if (snap && Array.isArray(snap.eras)) {
        for (const era of snap.eras) {
          if (era.label && era.label !== "?") state.eraByOutpoint.set(era.outpoint, era.label);
        }
      }
    }
  }
  for (const ev of state.events) {
    const e = ev.event;
    if (e.type === "splice_setup") {
      state.lineage.push({
        from: e.from_outpoint, to: e.to_outpoint,
        fromLabel: state.eraByOutpoint.get(e.from_outpoint) || outpointShort(e.from_outpoint),
        toLabel: state.eraByOutpoint.get(e.to_outpoint) || outpointShort(e.to_outpoint),
      });
    }
  }
}

function eraLabelOfEvent(ev) {
  const e = ev.event;
  if (e.era) return e.era;
  const out = e.input_outpoint || e.outpoint || e.resolved_outpoint ||
    (e.type === "splice_setup" ? e.to_outpoint : null) ||
    (e.type === "setup_channel" ? e.outpoint : null);
  if (out) return state.eraByOutpoint.get(out) || null;
  return null;
}

// ---------------------------------------------------------------- filtering

function eventVisible(i) {
  const ev = state.events[i];
  const cb = document.querySelector(`#controls input[data-actor=${ev.actor}]`);
  if (cb && !cb.checked) return false;
  const tf = document.getElementById("type-filter").value.trim().toLowerCase();
  if (tf && !ev.event.type.toLowerCase().includes(tf)) return false;
  if (document.getElementById("only-rejects").checked &&
      !(ev.result && (ev.result.status === "rejected" || ev.result.status === "fail"))) return false;
  if (document.getElementById("only-transitions").checked &&
      !["splice_setup", "funding_locked", "setup_channel", "state_declared", "transition_declared", "monitor_update", "restored"].includes(ev.event.type)) return false;
  if (document.getElementById("only-disagreements").checked && !disagreementAt(i)) return false;
  if (state.eraFilter) {
    const label = eraLabelOfEvent(ev);
    const mentions = JSON.stringify(ev.event).includes(state.eraFilter) ||
      (label === state.eraFilter) ||
      (ev.event.type.startsWith("cln") && JSON.stringify(ev.event).includes(state.eraFilter));
    if (!mentions) return false;
  }
  return true;
}

function applyFilter() {
  state.filtered = state.events.filter((e) => eventVisible(e._i)).map((e) => e._i);
  if (state.selected >= state.filtered.length) state.selected = state.filtered.length - 1;
  renderLanes();
  renderPosition();
}

// ------------------------------------------------------- disagreement model

function vlsBrainAt(i) {
  for (let j = i; j >= 0; j--) {
    const ev = state.events[j];
    if (ev.actor === "vls" && ev.after && Array.isArray(ev.after.eras)) return ev.after;
  }
  return null;
}

function clnBrainAt(i) {
  let belief = null;
  for (let j = 0; j <= i; j++) {
    const ev = state.events[j];
    if (ev.actor !== "cln") continue;
    const e = ev.event;
    if (e.type === "cln_state" && e.current_funding) belief = { outpoint: e.current_funding, at: j };
  }
  return belief;
}

function disagreementAt(i) {
  const vls = vlsBrainAt(i);
  const cln = clnBrainAt(i);
  if (!vls || !cln) return null;
  const clnLabel = state.eraByOutpoint.get(cln.outpoint);
  const current = vls.eras.find((e) => e.lifecycle === "current" || e.lifecycle === "locked");
  if (!current) return null;
  if (clnLabel && current.label !== clnLabel) {
    return `CLN believes funding ${clnLabel} is current; VLS current is ${current.label}`;
  }
  if (!clnLabel && cln.outpoint !== current.outpoint) {
    return `CLN believes ${outpointShort(cln.outpoint)} is current; VLS current is ${current.label} (${outpointShort(current.outpoint)})`;
  }
  return null;
}

// ---------------------------------------------------------------- rendering

function chipLabel(ev) {
  const e = ev.event;
  switch (e.type) {
    case "cln_request": return `→ ${e.message}`;
    case "cln_response": return `← ${e.message}`;
    case "cln_state": return `state: ${outpointShort(e.current_funding)}`;
    case "cln_event": return e.what;
    case "step": return e.name;
    case "inject": return `inject: ${e.action}`;
    case "expect": return `expect: ${e.expect} [${e.outcome}]`;
    case "invariant": return `invariant: ${e.name} ${e.passed ? "✓" : "✗"}`;
    case "state_declared": return `state: ${e.state}`;
    case "transition_declared": return `${e.from} →(${e.trigger}) ${e.to}`;
    case "scenario_start": return "scenario start";
    case "scenario_end": return `scenario end: ${e.outcome}`;
    case "sign_splice_tx": return `sign_splice_tx ${outpointShort(e.input_outpoint)}[${e.input_index}]`;
    case "splice_setup": return `splice ${outpointShort(e.from_outpoint)} → ${outpointShort(e.to_outpoint)}`;
    case "setup_channel": return `setup ${outpointShort(e.outpoint)}`;
    case "funding_view_resolved": return `view: ${outpointShort(e.resolved_outpoint)}${e.matched ? "" : " (fallback)"}`;
    case "validate_holder_commitment": return `validate_holder #${e.commitment_number} (${e.htlc_count} htlc)`;
    case "sign_counterparty_commitment": return `sign_cp_commitment #${e.commitment_number}`;
    case "funding_locked": return `funding_locked ${outpointShort(e.outpoint)}${e.retired?.length ? ` — retired ${e.retired.join(",")}` : ""}`;
    case "monitor_update": return `watch: ${e.what}`;
    case "restored": return "restored";
    default: return e.type;
  }
}

function renderLanes() {
  document.getElementById("cln-empty").classList.toggle("hidden",
    state.events.some((e) => e.actor === "cln"));
  for (const lane of ["driver", "cln", "vls"]) {
    const box = document.querySelector(`.lane[data-lane=${lane}] .events`);
    box.querySelectorAll(".chip").forEach((n) => n.remove());
  }
  const frag = { driver: [], cln: [], vls: [] };
  for (const i of state.filtered) {
    const ev = state.events[i];
    frag[ev.actor].push(chipNode(ev, i));
  }
  for (const lane of ["driver", "cln", "vls"]) {
    document.querySelector(`.lane[data-lane=${lane}] .events`).append(...frag[lane]);
  }
  drawLinks();
}

function chipNode(ev, i) {
  const chip = document.createElement("div");
  chip.className = `chip ${ev.actor}`;
  chip.dataset.i = i;
  const res = ev.result;
  if (res) chip.classList.add(res.status === "rejected" || res.status === "fail" ? "reject" : "accept");
  const era = eraLabelOfEvent(ev);
  const t = document.createElement("span");
  t.className = "t";
  t.textContent = chipLabel(ev);
  chip.appendChild(t);
  if (era) {
    const tag = document.createElement("span");
    tag.className = "era-tag";
    tag.textContent = `era ${era}`;
    chip.appendChild(tag);
  }
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = `seq ${ev.seq ?? "?"} · ${ev.correlation_id ?? ""}`;
  chip.appendChild(meta);
  chip.addEventListener("click", () => select(i, true));
  return chip;
}

function select(i, scroll) {
  state.selected = state.filtered.indexOf(i);
  if (state.selected < 0) { // event filtered out — still allow inspection
    state.selected = i; // fallback: treat as absolute
  }
  document.querySelectorAll(".chip.selected").forEach((n) => n.classList.remove("selected"));
  const chip = document.querySelector(`.chip[data-i="${i}"]`);
  if (chip) { chip.classList.add("selected"); if (scroll) chip.scrollIntoView({ block: "nearest", behavior: "smooth" }); }
  renderDetail(i);
  renderBrains(i);
  renderPosition();
  renderMachine(i);
  highlightEraGraph(i);
}

function renderPosition() {
  const pos = document.getElementById("position");
  if (state.selected >= 0 && state.filtered.length) {
    pos.textContent = `event ${state.selected + 1} / ${state.filtered.length} (of ${state.events.length})`;
  } else {
    pos.textContent = `${state.events.length} events`;
  }
}

function step() {
  if (!state.filtered.length) return;
  const idx = Math.min(Math.max(state.selected + 1, 0), state.filtered.length - 1);
  select(state.filtered[idx], true);
}
function stepBack() {
  if (!state.filtered.length) return;
  const idx = Math.max(state.selected - 1, 0);
  select(state.filtered[idx], true);
}

// ------------------------------------------------------------ overlay links

function drawLinks() {
  const svg = document.getElementById("link-overlay");
  svg.innerHTML = "";
  const byCorr = new Map();
  for (const i of state.filtered) {
    const ev = state.events[i];
    if (!ev.correlation_id) continue;
    if (!byCorr.has(ev.correlation_id)) byCorr.set(ev.correlation_id, []);
    byCorr.get(ev.correlation_id).push(i);
  }
  const panel = document.getElementById("timeline-panel");
  const pr = panel.getBoundingClientRect();
  for (const [, idxs] of byCorr) {
    if (idxs.length < 2) continue;
    const chips = idxs.map((i) => document.querySelector(`.chip[data-i="${i}"]`)).filter(Boolean);
    if (chips.length < 2) continue;
    const pts = chips.map((c) => {
      const r = c.getBoundingClientRect();
      return { x: r.left - pr.left + r.width / 2 + panel.scrollLeft, y: r.top - pr.top + 4 + panel.scrollTop };
    });
    for (let k = 0; k + 1 < pts.length; k++) {
      const a = pts[k], b = pts[k + 1];
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      const midY = (a.y + b.y) / 2;
      path.setAttribute("d", `M ${a.x} ${a.y} C ${a.x} ${midY}, ${b.x} ${midY}, ${b.x} ${b.y}`);
      svg.appendChild(path);
    }
  }
}

// ---------------------------------------------------------------- brains

function commitmentRow(c) {
  if (!c) return "—";
  return `${c.to_broadcaster_sat ?? "?"}→b / ${c.to_countersigner_sat ?? "?"}→c · ${c.offered_htlc_count ?? 0}+${c.received_htlc_count ?? 0} htlc (${c.htlc_total_sat ?? 0}) · fee ${c.feerate_per_kw ?? "?"}`;
}

function renderBrains(i) {
  // driver
  let stepName = null, lastExpect = null;
  for (let j = 0; j <= i; j++) {
    const ev = state.events[j];
    if (ev.actor !== "driver") continue;
    if (ev.event.type === "step") stepName = ev.event.name;
    if (ev.event.type === "expect" || ev.event.type === "invariant") lastExpect = ev.event;
  }
  const dBody = document.querySelector("#brain-driver .body");
  dBody.textContent = stepName ? `step: ${stepName}${lastExpect ? `\nlast: ${lastExpect.type === "expect" ? lastExpect.expect : lastExpect.name} [${lastExpect.outcome ?? (lastExpect.passed ? "✓" : "✗")}]` : ""}` : "—";

  // cln
  const cln = clnBrainAt(i);
  const cBody = document.querySelector("#brain-cln .body");
  let lastClnMsg = null;
  for (let j = 0; j <= i; j++) {
    const ev = state.events[j];
    if (ev.actor === "cln" && (ev.event.type === "cln_request" || ev.event.type === "cln_response")) {
      lastClnMsg = `${ev.event.type === "cln_request" ? "sent" : "received"} ${ev.event.message} (${ev.event.source})`;
    }
  }
  if (cln) {
    const label = state.eraByOutpoint.get(cln.outpoint);
    cBody.textContent = `current funding: ${label ?? "?"} (${outpointShort(cln.outpoint)})\n${lastClnMsg ?? ""}`;
  } else if (lastClnMsg) {
    cBody.textContent = `state: unknown (no cln_state event)\n${lastClnMsg}`;
  } else {
    cBody.textContent = "no CLN observations at this point";
  }

  // vls
  const vls = vlsBrainAt(i);
  const vBody = document.querySelector("#brain-vls .body");
  const dis = document.getElementById("disagreement");
  if (!vls) {
    vBody.textContent = "no VLS snapshot yet";
    dis.classList.add("hidden");
  } else {
    const lines = [];
    for (const era of (vls.eras ?? [])) {
      lines.push(`${era.label} [${era.lifecycle ?? "?"}] ${outpointShort(era.outpoint)} · ${era.value_sat ?? "?"} sat · remote ${keyShort(era.remote_funding_key)}`);
      lines.push(`   holder: ${commitmentRow(era.holder_commitment)}`);
      lines.push(`   cp:     ${commitmentRow(era.counterparty_commitment)}`);
      lines.push(`   watch:  ${(era.watched_txids ?? []).length ? (era.watched_txids ?? []).map((t) => String(t).slice(0, 8)).join(",") : "(tracker-held)"}`);
    }
    const en = vls.enforcement, ch = vls.chain;
    if (en) lines.push(`nums: holder ${en.next_holder_commit_num} cp ${en.next_counterparty_commit_num} revoke ${en.next_counterparty_revoke_num}`);
    if (en?.holder_commitment_funding || en?.counterparty_commitment_funding) {
      lines.push(`commitment funding tags: holder→${en.holder_commitment_funding ?? "?"} cp→${en.counterparty_commitment_funding ?? "?"}`);
    }
    if (en?.prev_funding_commitment) lines.push(`justice snapshot: ${en.prev_funding_commitment.era ?? "?"} (holder=${en.prev_funding_commitment.has_holder_info} cp=${en.prev_funding_commitment.has_counterparty_info})`);
    if (ch) lines.push(`chain: splice_pending=${ch.splice_pending} locked=${ch.funding_locked_outpoint ? outpointShort(ch.funding_locked_outpoint) : "—"} depth=${ch.funding_depth}`);
    vBody.textContent = lines.join("\n");
    const msg = disagreementAt(i);
    if (msg) {
      dis.classList.remove("hidden");
      dis.innerHTML = `<h4>DISAGREEMENT</h4>${escapeHtml(msg)}`;
    } else {
      dis.classList.add("hidden");
    }
  }
}

// ---------------------------------------------------------------- era graph

function renderEraGraph() {
  const box = document.getElementById("era-graph");
  box.innerHTML = "";
  if (!state.lineage.length && !state.eraByOutpoint.size) {
    box.innerHTML = '<span class="muted small">no funding eras in trace</span>';
    return;
  }
  const seen = [];
  for (const [outpoint, label] of state.eraByOutpoint) {
    if (!seen.includes(label)) seen.push(label);
  }
  seen.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  seen.forEach((label, idx) => {
    if (idx > 0) {
      const arrow = document.createElement("span");
      arrow.className = "era-arrow";
      arrow.textContent = "→";
      box.appendChild(arrow);
    }
    const node = document.createElement("span");
    node.className = "era-node";
    node.dataset.era = label;
    const outpoints = [...state.eraByOutpoint.entries()].filter(([, l]) => l === label).map(([o]) => outpointShort(o));
    node.innerHTML = `${escapeHtml(label)}<small>${escapeHtml(outpoints[0] ?? "")}</small>`;
    node.addEventListener("click", () => {
      state.eraFilter = state.eraFilter === label ? null : label;
      document.querySelectorAll(".era-node").forEach((n) => n.classList.toggle("active", n.dataset.era === state.eraFilter));
      applyFilter();
    });
    box.appendChild(node);
  });
}

function highlightEraGraph(i) {
  const label = eraLabelOfEvent(state.events[i]);
  document.querySelectorAll(".era-node").forEach((n) => {
    n.style.borderWidth = n.dataset.era === label ? "2.5px" : "1.5px";
  });
}

// ------------------------------------------------------------ state machine

function renderMachine(i) {
  const box = document.getElementById("machine-graph");
  const states = [], edges = [], invs = new Map();
  for (const ev of state.events) {
    if (ev.event.type === "state_declared") {
      if (!states.includes(ev.event.state)) states.push(ev.event.state);
      if (ev.event.invariants) invs.set(ev.event.state, ev.event.invariants);
    }
    if (ev.event.type === "transition_declared") {
      edges.push(ev.event);
    }
  }
  if (!states.length) { box.innerHTML = "no declared states in trace"; return; }
  let current = null;
  for (let j = 0; j <= i; j++) {
    const ev = state.events[j];
    if (ev.event.type === "state_declared") current = ev.event.state;
  }
  box.innerHTML = "";
  for (const s of states) {
    const node = document.createElement("div");
    node.className = "machine-node" + (s === current ? " current" : "");
    node.textContent = s;
    const inv = invs.get(s);
    if (inv) {
      const pre = document.createElement("div");
      pre.className = "machine-invariants";
      pre.textContent = JSON.stringify(inv, null, 1).slice(0, 300);
      node.appendChild(pre);
    }
    box.appendChild(node);
    const matching = edges.filter((e) => e.from === s);
    for (const e of matching) {
      const edge = document.createElement("div");
      edge.className = "machine-edge";
      edge.textContent = `↓ ${e.trigger} → ${e.to}`;
      box.appendChild(edge);
    }
  }
}

// ---------------------------------------------------------------- detail

function renderDetail(i) {
  const ev = state.events[i];
  const panel = document.getElementById("detail-panel");
  panel.classList.remove("hidden");
  const res = ev.result ? ` · <span style="color:${ev.result.status === "rejected" || ev.result.status === "fail" ? "var(--reject)" : "var(--ok)"}">${escapeHtml(ev.result.status)}${ev.result.code ? ` ${escapeHtml(ev.result.code)}` : ""}${ev.result.message ? `: ${escapeHtml(ev.result.message)}` : ""}</span>` : "";
  document.getElementById("detail-header").innerHTML =
    `<span class="seq">#${ev.seq ?? i}</span><b>${escapeHtml(ev.actor)} · ${escapeHtml(ev.event.type)}</b>` +
    `<span class="muted">mono ${ev.mono_us ?? "?"}µs${ev.correlation_id ? ` · corr ${escapeHtml(ev.correlation_id)}` : ""}${ev.channel_id ? ` · chan ${escapeHtml(ev.channel_id.slice(0, 12))}…` : ""}</span>${res}`;
  renderTab(activeTab(), i);
}

function activeTab() {
  const b = document.querySelector("#detail-tabs button.active");
  return b ? b.dataset.tab : "fields";
}

function kvTable(obj, depth) {
  const rows = [];
  const walk = (o, prefix) => {
    if (o === null || o === undefined) { rows.push([prefix, "null"]); return; }
    if (typeof o !== "object") { rows.push([prefix, String(o)]); return; }
    if (Array.isArray(o)) {
      o.forEach((v, k) => walk(v, `${prefix}[${k}]`));
      if (!o.length) rows.push([prefix, "[]"]);
      return;
    }
    for (const [k, v] of Object.entries(o)) walk(v, prefix ? `${prefix}.${k}` : k);
  };
  walk(obj, "");
  const maxLen = 90;
  return `<table class="kv">${rows.map(([k, v]) =>
    `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v.length > maxLen ? v.slice(0, maxLen) + "…" : v)}</td></tr>`).join("")}</table>`;
}

function summarize(v) {
  if (v === null || v === undefined) return "∅";
  if (typeof v !== "object") return String(v);
  if (Array.isArray(v)) return `[${v.length}]`;
  if (v.label && v.lifecycle) return `${v.label}[${v.lifecycle}]`;           // funding era
  if (v.to_broadcaster_sat !== undefined) return `commit(${v.to_broadcaster_sat}/${v.to_countersigner_sat}, htlc ${v.offered_htlc_count}+${v.received_htlc_count})`;
  if (v.outpoint) return `${v.label ?? ""}${outpointShort(v.outpoint)}`;
  return JSON.stringify(v).slice(0, 60);
}

function diffRows(a, b, prefix, out) {
  const aObj = a ?? {}, bObj = b ?? {};
  const isArr = Array.isArray(aObj) || Array.isArray(bObj);
  const keys = isArr
    ? [...Array(Math.max(aObj.length ?? 0, bObj.length ?? 0)).keys()].map(String)
    : new Set([...Object.keys(aObj), ...Object.keys(bObj)]);
  for (const k of keys) {
    const p = prefix ? `${prefix}${isArr ? "" : "."}${isArr ? `[${k}]` : k}` : (isArr ? `[${k}]` : k);
    const av = aObj[k], bv = bObj[k];
    if (av === bv) continue;
    const aPlain = av === null || av === undefined || typeof av !== "object";
    const bPlain = bv === null || bv === undefined || typeof bv !== "object";
    if (!aPlain && !bPlain) {
      diffRows(av, bv, p, out);
    } else if (!(k in aObj) || av === undefined) {
      out.push(["add", p, null, bv]);
    } else if (!(k in bObj) || bv === undefined) {
      out.push(["del", p, av, null]);
    } else {
      out.push(["chg", p, av, bv]);
    }
  }
}

function renderTab(tab, i) {
  const ev = state.events[i];
  const body = document.getElementById("detail-body");
  if (tab === "fields") {
    body.innerHTML = kvTable({ ...ev.event, _actor: ev.actor, _correlation: ev.correlation_id, _channel: ev.channel_id });
  } else if (tab === "raw") {
    body.innerHTML = `<pre class="raw">${escapeHtml(JSON.stringify(ev, null, 2))}</pre>`;
  } else if (tab === "diff") {
    if (!ev.before && !ev.after) {
      body.innerHTML = '<span class="muted">no state snapshots on this event</span>';
    } else if (!ev.before || !ev.after) {
      const snap = ev.after ?? ev.before;
      body.innerHTML = `<div class="muted small">${ev.after ? "after only (new state)" : "before only"}</div>` + kvTable(snap);
    } else {
      const rows = [];
      diffRows(ev.before, ev.after, "", rows);
      body.innerHTML = rows.length
        ? `<table class="kv"><tr><th>Δ</th><th>field</th><th>before → after</th></tr>${rows.map(([kind, p, av, bv]) =>
            `<tr><td class="diff-${kind}">${kind === "add" ? "+" : kind === "del" ? "−" : "~"}</td><th>${escapeHtml(p)}</th><td>${escapeHtml(summarize(av))} → ${escapeHtml(summarize(bv))}</td></tr>`).join("")}</table>`
        : '<span class="muted">no state change</span>';
    }
  } else if (tab === "artifacts") {
    if (!ev.artifacts?.length) {
      body.innerHTML = '<span class="muted">no artifacts on this event</span>';
    } else {
      body.innerHTML = ev.artifacts.map((a, k) => `
        <div class="artifact-block">
          <div class="kind">artifact ${k}: ${escapeHtml(a.kind)}</div>
          ${a.decoded ? kvTable(a.decoded) : '<span class="muted small">no decoded form</span>'}
          <details><summary>raw (${a.raw.length} chars)</summary><pre class="raw">${escapeHtml(a.raw)}</pre></details>
        </div>`).join("");
    }
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------------------------------------------------------------- loading

function ingest(batches, sourceNames) {
  state.events = mergeEvents(batches);
  state.sources = sourceNames;
  state.malformed = batches.metaBad ?? 0;
  state.selected = -1;
  state.eraFilter = null;
  state.eraByOutpoint = new Map();
  state.lineage = [];
  buildEraModel();
  // steps dropdown
  const jump = document.getElementById("jump-step");
  jump.innerHTML = '<option value="">jump to step…</option>';
  for (const ev of state.events) {
    if (ev.event.type === "step") {
      const o = document.createElement("option");
      o.value = ev._i;
      o.textContent = `#${ev.seq ?? "?"} ${ev.event.name}`;
      jump.appendChild(o);
    }
  }
  const runs = new Set(state.events.map((e) => e.run_id));
  const scenarios = new Set(state.events.map((e) => e.scenario_id));
  document.getElementById("trace-meta").textContent =
    `${state.events.length} events · ${runs.size} run(s) · scenario: ${[...scenarios].join(", ")} · sources: ${sourceNames.join(", ")}`;
  const warn = document.getElementById("parse-warnings");
  if (state.malformed > 0) {
    warn.classList.remove("hidden");
    warn.textContent = `${state.malformed} malformed line(s) skipped`;
  } else {
    warn.classList.add("hidden");
  }
  document.getElementById("infobar").classList.remove("hidden");
  applyFilter();
  renderEraGraph();
  if (state.filtered.length) select(state.filtered[0], true);
}

async function loadFromUrl(names) {
  const batches = [], srcs = [];
  let bad = 0;
  for (const n of names) {
    let text = null;
    for (const url of [n, `/trace/${encodeURIComponent(n)}`]) {
      try {
        const r = await fetch(url);
        if (r.ok) { text = await r.text(); break; }
      } catch { /* try next */ }
    }
    if (text === null) { bad++; continue; }
    const parsed = parseJsonl(text, n);
    bad += parsed.bad;
    batches.push(parsed.events);
    srcs.push(n);
  }
  batches.metaBad = bad;
  ingest(batches, srcs);
}

function loadFromFiles(files) {
  const batches = [], srcs = [];
  let bad = 0, pending = files.length;
  return new Promise((resolve) => {
    if (!pending) { resolve(); return; }
    for (const f of files) {
      const reader = new FileReader();
      reader.onload = () => {
        const parsed = parseJsonl(String(reader.result), f.name);
        bad += parsed.bad;
        batches.push(parsed.events);
        srcs.push(f.name);
        if (--pending === 0) {
          document.title = `vls trace — ${srcs.join(", ")}`;
          history.replaceState(null, "", `?trace=${encodeURIComponent(srcs.join(","))}`);
          batches.metaBad = bad;
          ingest(batches, srcs);
          resolve();
        }
      };
      reader.readAsText(f);
    }
  });
}

// ---------------------------------------------------------------- wiring

document.getElementById("file-input").addEventListener("change", (e) => loadFromFiles(e.target.files));
document.getElementById("btn-prev").addEventListener("click", stepBack);
document.getElementById("btn-next").addEventListener("click", step);
document.getElementById("jump-step").addEventListener("change", (e) => {
  if (e.target.value !== "") select(Number(e.target.value), true);
});
for (const cb of document.querySelectorAll("#controls input[data-actor]")) {
  cb.addEventListener("change", applyFilter);
}
document.getElementById("type-filter").addEventListener("input", applyFilter);
for (const id of ["only-rejects", "only-transitions", "only-disagreements"]) {
  document.getElementById(id).addEventListener("change", applyFilter);
}
for (const btn of document.querySelectorAll("#detail-tabs button")) {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#detail-tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    if (state.selected >= 0) renderTab(btn.dataset.tab, state.selected);
  });
}
document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
  if (e.key === "ArrowRight") { step(); e.preventDefault(); }
  else if (e.key === "ArrowLeft") { stepBack(); e.preventDefault(); }
  else if (e.key === "Escape") {
    document.querySelectorAll(".chip.selected").forEach((n) => n.classList.remove("selected"));
    document.getElementById("detail-panel").classList.add("hidden");
  }
});
window.addEventListener("resize", drawLinks);
document.getElementById("timeline-panel").addEventListener("scroll", drawLinks);

const params = new URLSearchParams(location.search);
if (params.get("trace")) {
  loadFromUrl(params.get("trace").split(",").filter(Boolean));
} else {
  document.getElementById("load-status").textContent = "pick a .jsonl file (works offline) or serve with contrib/trace-viewer/serve.py and use ?trace=";
}
