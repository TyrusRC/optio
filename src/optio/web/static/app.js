"use strict";
// Optio web UI — attack-surface graph + "what to find" + free-form runner.
// Vanilla JS over the stdlib API. No build step, no framework.

const $ = (s) => document.querySelector(s);
const SEV_CLASS = { critical: "crit", high: "high", medium: "med", low: "low" };
// Escape every dynamic value before it reaches innerHTML. Asset values and
// finding text come from tested targets — a hostile target must never run JS
// in the operator's browser.
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let TARGET = null, CY = null, CATALOG = [], PIPELINES = [];

async function api(method, path, body) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
function setStatus(msg) { $("#status").textContent = msg || ""; }
async function busy(msg, fn) {
  setStatus(msg + "…");
  try { return await fn(); }
  catch (e) { setStatus("error: " + e.message); throw e; }
  finally { setTimeout(() => setStatus(""), 1500); }
}

// ── tabs ──────────────────────────────────────────────────────────────────
document.querySelectorAll("#tabs button").forEach((b) =>
  b.onclick = () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("#tab-" + b.dataset.tab).classList.add("active");
  });

// ── modal (prompt) ──────────────────────────────────────────────────────────
function prompt(title, initial) {
  return new Promise((resolve) => {
    $("#modal-title").textContent = title;
    $("#modal-input").value = initial || "";
    $("#modal").classList.remove("hidden");
    $("#modal-input").focus();
    const done = (v) => { $("#modal").classList.add("hidden"); resolve(v); };
    $("#modal-ok").onclick = () => done($("#modal-input").value);
    $("#modal-cancel").onclick = () => done(null);
  });
}

// ── targets ──────────────────────────────────────────────────────────────────
async function loadTargets() {
  const targets = await api("GET", "/targets");
  const sel = $("#target-select");
  sel.innerHTML = "";
  targets.forEach((t) => {
    const o = document.createElement("option");
    o.value = o.textContent = t.name; sel.appendChild(o);
  });
  if (targets.length) { TARGET = sel.value; await refresh(); }
}
$("#target-select").onchange = async (e) => { TARGET = e.target.value; await refresh(); };
$("#add-target").onclick = async () => {
  const name = await prompt("Add target (host or URL)", "");
  if (!name || !name.trim()) return;
  await api("POST", "/targets", { name: name.trim() });
  await loadTargets();
};

// ── refresh all panes for the current target ─────────────────────────────────
async function refresh() {
  if (!TARGET) return;
  const enc = encodeURIComponent(TARGET);
  const [graph, coverage, findings, next, catalog, pipelines] = await Promise.all([
    api("GET", `/targets/${enc}/surface`),
    api("GET", `/targets/${enc}/coverage-classes`),
    api("GET", `/targets/${enc}/findings`),
    api("GET", `/targets/${enc}/next`),
    api("GET", "/catalog"),
    api("GET", "/pipelines"),
  ]);
  CATALOG = catalog; PIPELINES = pipelines;
  renderGraph(graph, findings);
  renderCoverage(coverage);
  renderFindings(findings);
  renderNext(next);
  renderRunners();
}

// ── the attack-surface graph (Wiz-style) ─────────────────────────────────────
function renderGraph(graph, findings) {
  const els = [];
  graph.nodes.forEach((n) =>
    els.push({ data: { id: "a" + n.id, label: n.value, kind: n.kind,
      sev: n.severity || "none", fc: n.finding_count } }));
  graph.edges.forEach((e) =>
    els.push({ data: { source: "a" + e.source, target: "a" + e.target } }));
  if (!els.length) els.push({ data: { id: "empty", label: "no assets yet — run recon or add one", kind: "note", sev: "none", fc: 0 } });

  const color = { crit: "#e5484d", high: "#f2711c", med: "#e3b341", low: "#58a6ff", none: "#3b4250" };
  CY = cytoscape({
    container: $("#graph"),
    elements: els,
    style: [
      { selector: "node", style: {
        "background-color": (n) => color[SEV_CLASS[n.data("sev")] || "none"] || color.none,
        "label": "data(label)", "color": "#d7dde6", "font-size": 11,
        "text-valign": "bottom", "text-margin-y": 4, "width": 26, "height": 26,
        "border-width": (n) => n.data("fc") > 0 ? 3 : 1, "border-color": "#0e1116" } },
      { selector: "edge", style: { "width": 1.5, "line-color": "#2b3240",
        "target-arrow-color": "#2b3240", "target-arrow-shape": "triangle",
        "curve-style": "bezier" } },
    ],
    layout: { name: "breadthfirst", directed: true, padding: 24, spacingFactor: 1.1 },
  });
  CY.on("tap", "node", (ev) => {
    const id = ev.target.data("id");
    const node = graph.nodes.find((x) => "a" + x.id === id);
    if (node) showNode(node, findings);
  });
}

// ── "what to find" coverage board ─────────────────────────────────────────────
function pill(status) {
  const map = { untested: "s-untested", tested: "s-tested", finding: "s-finding", n_a: "s-na" };
  return `<span class="pill ${map[status] || "s-untested"}">${status}</span>`;
}
function renderCoverage(cov) {
  const tb = $("#coverage-table tbody");
  tb.innerHTML = "";
  cov.forEach((c) => {
    const tr = document.createElement("tr");
    const act = c.tool ? `tool: ${esc(c.tool)}` : "manual";
    tr.innerHTML = `<td><b>${esc(c.vuln_class)}</b><br><small class="muted">${esc(c.action)}</small></td>
      <td>${pill(c.status)}<br><small class="muted">${act}</small></td>
      <td><button data-c="${esc(c.vuln_class)}" data-s="tested">tested</button>
          <button data-c="${esc(c.vuln_class)}" data-s="finding">finding</button></td>`;
    tb.appendChild(tr);
  });
  tb.querySelectorAll("button").forEach((b) => b.onclick = async () => {
    await api("POST", `/targets/${encodeURIComponent(TARGET)}/coverage-classes`,
      { vuln_class: b.dataset.c, status: b.dataset.s });
    await refresh();
  });
}

function showNode(node, findings) {
  document.querySelector('#tabs button[data-tab="node"]').click();
  $("#node-title").textContent = `${node.kind}: ${node.value}`;
  const fs = findings.filter((f) => (f.endpoint || "") === node.value);
  const meta = Object.entries(node.data || {}).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" · ");
  let html = `<p class="muted">${meta || "no metadata"}</p>`;
  html += `<h3>Findings here (${fs.length})</h3>`;
  html += fs.length ? fs.map(findingCard).join("") : `<p class="muted">none</p>`;
  $("#node-body").innerHTML = html;
}

// ── findings ──────────────────────────────────────────────────────────────────
function findingCard(f) {
  const sev = (f.severity || "").toLowerCase();
  return `<div class="finding"><span class="sev ${esc(sev)}">${esc(sev.toUpperCase())}</span>
    <b>${esc(f.title)}</b> <small class="muted">${esc(f.status)}</small>
    <div class="muted">${esc(f.endpoint || "")}</div>
    ${f.impact ? `<div>${esc(f.impact)}</div>` : ""}</div>`;
}
function renderFindings(findings) {
  $("#findings-list").innerHTML = findings.length
    ? findings.map(findingCard).join("") : `<span class="muted">none yet</span>`;
}

// ── advisor hints (non-blocking) ──────────────────────────────────────────────
function renderNext(next) {
  const el = $("#next-list");
  el.innerHTML = "";
  next.forEach((s) => {
    const d = document.createElement("div");
    d.className = "row";
    d.innerHTML = `<span>${esc(s.action)}<br><small>${esc(s.reason)}</small></span>`;
    if (s.tool) {
      const b = document.createElement("button");
      b.textContent = "run";
      b.onclick = () => runTool(s.tool);
      d.appendChild(b);
    }
    el.appendChild(d);
  });
}

// ── free-form runners ─────────────────────────────────────────────────────────
function renderRunners() {
  const filt = ($("#tool-filter").value || "").toLowerCase();
  const list = $("#tool-list"); list.innerHTML = "";
  CATALOG.filter((t) => !filt || t.name.includes(filt) || (t.description || "").toLowerCase().includes(filt))
    .forEach((t) => {
      const d = document.createElement("div");
      d.className = "row";
      d.innerHTML = `<span class="tool"><b>${esc(t.name)}</b> <small>${esc(t.lane)}/${esc(t.phase)}</small><br><small class="muted">${esc(t.description || "")}</small></span>`;
      const b = document.createElement("button"); b.textContent = "run";
      b.onclick = () => runTool(t.name); d.appendChild(b);
      list.appendChild(d);
    });
  const pl = $("#pipeline-list"); pl.innerHTML = "";
  PIPELINES.forEach((p) => {
    const d = document.createElement("div");
    d.className = "row";
    d.innerHTML = `<span><b>${esc(p.name)}</b><br><small class="muted">${esc((p.steps || []).join(" → "))}</small></span>`;
    const b = document.createElement("button"); b.textContent = "run";
    b.onclick = () => runPipeline(p.name); d.appendChild(b);
    pl.appendChild(d);
  });
}
$("#tool-filter").oninput = renderRunners;

async function runTool(tool) {
  await busy(`running ${tool}`, async () => {
    const out = await api("POST", `/targets/${encodeURIComponent(TARGET)}/run`, { tool });
    if (out.error) throw new Error(out.error);
    setStatus(`${tool}: exit ${out.exit_code}`);
  });
  await refresh();
}
async function runPipeline(name) {
  await busy(`pipeline ${name}`, () =>
    api("POST", `/targets/${encodeURIComponent(TARGET)}/run-pipeline`, { pipeline: name }));
  await refresh();
}

// ── request runner + report ───────────────────────────────────────────────────
$("#btn-request").onclick = async () => {
  if (!TARGET) return;
  const tmpl = `GET / HTTP/1.1\nHost: ${TARGET.replace(/^https?:\/\//, "")}\nUser-Agent: optio\n\n`;
  const raw = await prompt("Send raw request (edit, then OK)", tmpl);
  if (!raw || !raw.trim()) return;
  await busy("sending", async () => {
    const out = await api("POST", `/targets/${encodeURIComponent(TARGET)}/request-raw`, { raw });
    if (out.error) throw new Error(out.error);
    setStatus(`request #${out.request_id}: ${out.status} (${out.elapsed_ms} ms)`);
  });
  await refresh();
};
$("#btn-auto").onclick = async () => {
  if (!TARGET) return;
  await busy("auto-running flow", async () => {
    const out = await api("POST", `/targets/${encodeURIComponent(TARGET)}/auto-run`, {});
    const ran = out.steps.filter((s) => s.command).length;
    const skipped = out.steps.filter((s) => s.skipped).length;
    setStatus(`auto-run: ${ran} ran, ${skipped} skipped`);
  });
  await refresh();
};
$("#btn-config").onclick = async () => {
  if (!TARGET) return;
  const cur = await api("GET", `/targets/${encodeURIComponent(TARGET)}/config`);
  const tmpl = JSON.stringify(
    Object.keys(cur).length ? cur
      : { headers: { "X-Example": "value" }, user_agent: "Mozilla/5.0 (optio)" }, null, 2);
  const raw = await prompt("Target config — headers + User-Agent (JSON)", tmpl);
  if (raw === null) return;
  let cfg;
  try { cfg = JSON.parse(raw); }
  catch (e) { setStatus("config: invalid JSON"); return; }
  await api("POST", `/targets/${encodeURIComponent(TARGET)}/config`, { config: cfg });
  setStatus("config saved — applied to every request");
};
$("#btn-report").onclick = async () => {
  const out = await api("GET", `/targets/${encodeURIComponent(TARGET)}/report`);
  const w = window.open("", "_blank");
  const pre = w.document.createElement("pre");
  pre.style.cssText = "white-space:pre-wrap;font:13px ui-monospace,monospace;padding:20px;max-width:900px;margin:auto";
  pre.textContent = out.markdown;             // textContent — no HTML injection
  w.document.body.appendChild(pre);
  w.document.title = "Optio report — " + TARGET;
};

loadTargets().catch((e) => setStatus("error: " + e.message));
