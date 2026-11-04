"use strict";
// Optio web UI — attack-surface graph + "what to find" + free-form runner.
// Vanilla JS over the stdlib API. No build step, no framework.

const $ = (s) => document.querySelector(s);
const enc = encodeURIComponent;
const SEV_CLASS = { critical: "crit", high: "high", medium: "med", low: "low" };
// Escape every dynamic value before it reaches innerHTML. Asset values and
// finding text come from tested targets — a hostile target must never run JS
// in the operator's browser.
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let TARGET = null, CY = null, CATALOG = [], PIPELINES = [], COVERAGE_RAN = new Set();
const FINDING_STATUSES = ["suspected", "confirmed", "false_positive", "fixed"];

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
  $("#status").classList.add("loading");      // animated spinner: shows the run is alive, not hung
  try {
    const r = await fn();
    $("#status").classList.remove("loading");
    setTimeout(() => setStatus(""), 1500);   // clear only on success
    return r;
  } catch (e) {
    $("#status").classList.remove("loading");
    setStatus("error: " + e.message);        // sticky — stays until the next action
    throw e;
  }
}

// ── tabs ──────────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.remove("active"));
  document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
  document.querySelector(`#tabs button[data-tab="${name}"]`).classList.add("active");
  $("#tab-" + name).classList.add("active");
}
document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => showTab(b.dataset.tab));

// ── modal (prompt) ──────────────────────────────────────────────────────────
// opts.short: single-line input that submits on Enter. Multiline submits on
// Ctrl/Cmd+Enter. Esc always cancels.
function prompt(title, initial, opts = {}) {
  return new Promise((resolve) => {
    $("#modal-title").textContent = title;
    const inp = $("#modal-input");
    inp.value = initial || "";
    inp.classList.toggle("short", !!opts.short);
    $("#modal").classList.remove("hidden");
    inp.focus();
    const done = (v) => { $("#modal").classList.add("hidden"); inp.onkeydown = null; resolve(v); };
    $("#modal-ok").onclick = () => done(inp.value);
    $("#modal-cancel").onclick = () => done(null);
    inp.onkeydown = (e) => {
      if (e.key === "Enter" && (opts.short || e.ctrlKey || e.metaKey)) { e.preventDefault(); done(inp.value); }
      else if (e.key === "Escape") { e.preventDefault(); done(null); }
    };
  });
}

// ── onboarding / toolbar state ────────────────────────────────────────────────
function setHasTarget(has) {
  $("#onboard").classList.toggle("hidden", !!has);
  ["#btn-auto", "#btn-config", "#btn-request", "#btn-report"].forEach((s) => $(s).disabled = !has);
}

// ── targets ──────────────────────────────────────────────────────────────────
async function loadTargets(select) {
  const targets = await api("GET", "/targets");
  const sel = $("#target-select");
  sel.innerHTML = "";
  targets.forEach((t) => {
    const o = document.createElement("option");
    o.value = o.textContent = t.name; sel.appendChild(o);
  });
  if (targets.length) {
    TARGET = select && targets.some((t) => t.name === select) ? select : sel.value;
    sel.value = TARGET;
    setHasTarget(true);
    await refresh();
  } else {
    TARGET = null; setHasTarget(false);
  }
}
$("#target-select").onchange = async (e) => { TARGET = e.target.value; await refresh(); };
async function addTarget() {
  const name = await prompt(
    "Add target — host or URL  (e.g. example.com  or  https://example.com:8443)", "", { short: true });
  if (!name || !name.trim()) return;
  await api("POST", "/targets", { name: name.trim() });
  await loadTargets(name.trim());
}
$("#add-target").onclick = addTarget;
$("#onboard-add").onclick = addTarget;

// ── refresh all panes for the current target ─────────────────────────────────
async function refresh() {
  if (!TARGET) return;
  const e = enc(TARGET);
  $("#status").classList.add("loading"); setStatus("loading");
  try {
    const [graph, coverage, covClasses, findings, next, catalog, pipelines, requests, config] =
      await Promise.all([
        api("GET", `/targets/${e}/surface`),
        api("GET", `/targets/${e}/coverage`),
        api("GET", `/targets/${e}/coverage-classes`),
        api("GET", `/targets/${e}/findings`),
        api("GET", `/targets/${e}/next`),
        api("GET", "/catalog"),
        api("GET", "/pipelines"),
        api("GET", `/targets/${e}/requests`),
        api("GET", `/targets/${e}/config`),
      ]);
    CATALOG = catalog; PIPELINES = pipelines; COVERAGE_RAN = new Set(coverage.ran || []);
    renderGraph(graph, findings);
    renderCoverage(covClasses);
    renderFindings(findings);
    renderNext(next);
    renderRequests(requests);
    renderEvidenceOptions(requests);
    renderProxyIndicator(config);
    renderRunners();
    setStatus("");
  } catch (err) {
    setStatus("error: " + err.message);
  } finally {
    $("#status").classList.remove("loading");
  }
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

  // refresh() re-renders on every action; tear the old instance down first, or
  // each render leaks a cytoscape instance + its listeners onto #graph.
  if (CY) { CY.destroy(); CY = null; }
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
    await api("POST", `/targets/${enc(TARGET)}/coverage-classes`,
      { vuln_class: b.dataset.c, status: b.dataset.s });
    await refresh();
  });
}

function showNode(node, findings) {
  showTab("node");
  $("#node-title").textContent = `${node.kind}: ${node.value}`;
  const fs = findings.filter((f) => (f.endpoint || "") === node.value);
  const meta = Object.entries(node.data || {}).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" · ");
  let html = `<p class="muted">${meta || "no metadata"}</p>`;
  html += `<button id="node-add-finding">+ finding here</button>`;
  html += `<h3>Findings here (${fs.length})</h3>`;
  html += fs.length ? fs.map(findingCard).join("") : `<p class="muted">none</p>`;
  $("#node-body").innerHTML = html;
  wireFindingStatus($("#node-body"));
  $("#node-add-finding").onclick = () => openFindingForm({ endpoint: node.value });
}

// ── findings ──────────────────────────────────────────────────────────────────
function findingCard(f) {
  const sev = (f.severity || "").toLowerCase();
  const opts = FINDING_STATUSES.map((s) =>
    `<option value="${s}"${s === (f.status || "") ? " selected" : ""}>${s}</option>`).join("");
  return `<div class="finding ${f.status === "confirmed" ? "confirmed" : ""}">
    <div class="finding-head">
      <span><span class="sev ${esc(sev)}">${esc(sev.toUpperCase())}</span> <b>${esc(f.title)}</b></span>
      <select class="f-status" name="status" data-id="${esc(f.id)}" aria-label="finding status" title="status — only confirmed reach the client report">${opts}</select>
    </div>
    <div class="muted">${esc(f.endpoint || "")}</div>
    ${f.impact ? `<div>${esc(f.impact)}</div>` : ""}</div>`;
}
// Wire the status selects inside any container that holds finding cards.
function wireFindingStatus(root) {
  root.querySelectorAll(".f-status").forEach((sel) => sel.onchange = async () => {
    await busy("updating finding", () =>
      api("POST", `/targets/${enc(TARGET)}/findings/${sel.dataset.id}/status`,
          { status: sel.value }));
    await refresh();
  });
}
function renderFindings(findings) {
  const el = $("#findings-list");
  el.innerHTML = findings.length
    ? findings.map(findingCard).join("") : `<span class="muted">none yet</span>`;
  wireFindingStatus(el);
}

// ── add-finding form ──────────────────────────────────────────────────────────
function openFindingForm(prefill = {}) {
  showTab("findings");
  $("#finding-form").classList.remove("hidden");
  $("#add-finding-btn").classList.add("hidden");
  $("#f-title").value = prefill.title || "";
  $("#f-class").value = prefill.vuln_class || "";
  $("#f-endpoint").value = prefill.endpoint || "";
  $("#f-impact").value = "";
  $("#f-sev").value = "low";
  $("#f-evidence").value = prefill.evidence_request_id || "";
  $("#f-title").focus();
}
function closeFindingForm() {
  $("#finding-form").classList.add("hidden");
  $("#add-finding-btn").classList.remove("hidden");
}
$("#add-finding-btn").onclick = () => openFindingForm();
$("#f-cancel").onclick = closeFindingForm;
$("#finding-form").onsubmit = async (e) => {
  e.preventDefault();
  const title = $("#f-title").value.trim();
  if (!title) { setStatus("finding: title is required"); return; }
  const payload = {
    title, severity: $("#f-sev").value,
    vuln_class: $("#f-class").value.trim(), endpoint: $("#f-endpoint").value.trim(),
    impact: $("#f-impact").value.trim(),
  };
  const ev = $("#f-evidence").value;
  if (ev) payload.evidence_request_id = Number(ev);
  await busy("saving finding", () =>
    api("POST", `/targets/${enc(TARGET)}/findings`, payload));
  closeFindingForm();
  await refresh();
};

// ── captured requests (durable evidence) ──────────────────────────────────────
function reqCodeClass(status) {
  if (!status) return "cli";              // 0 = transport/client error
  if (status >= 400) return "err";
  return "ok";
}
function renderRequests(reqs) {
  const el = $("#requests-list");
  if (!reqs.length) { el.innerHTML = `<span class="muted">none yet — use “Send request”, or forward traffic from Burp</span>`; return; }
  el.innerHTML = "";
  reqs.forEach((r) => {
    const d = document.createElement("div");
    d.className = "req-row";
    d.innerHTML = `<span class="code ${reqCodeClass(r.status)}">${esc(r.status || "ERR")}</span>
      <span><b>${esc(r.method)}</b> ${esc(r.url)}</span>
      <span class="muted">#${esc(r.id)} · ${esc(r.elapsed_ms)}ms</span>`;
    d.onclick = () => showRequest(r.id);
    el.appendChild(d);
  });
}
function renderEvidenceOptions(reqs) {
  const sel = $("#f-evidence");
  const cur = sel.value;
  sel.innerHTML = `<option value="">— no evidence request —</option>` +
    reqs.map((r) => `<option value="${esc(r.id)}">#${esc(r.id)} ${esc(r.method)} ${esc(r.url)} → ${esc(r.status || "ERR")}</option>`).join("");
  sel.value = cur;
}
async function showRequest(id) {
  showTab("requests");
  const r = await api("GET", `/targets/${enc(TARGET)}/requests/${id}`);
  const hdrs = (o) => Object.entries(o || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
  $("#request-detail").innerHTML =
    `<h3>Request #${esc(r.id)}</h3>
     <pre>${esc(r.method)} ${esc(r.url)}\n${esc(hdrs(r.req_headers))}\n\n${esc(r.req_body || "")}</pre>
     <h3>Response — ${esc(r.status)} (${esc(r.elapsed_ms)} ms)</h3>
     <pre>${esc(hdrs(r.resp_headers))}\n\n${esc(r.resp_body || "")}</pre>`;
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

// ── proxy indicator ────────────────────────────────────────────────────────────
function renderProxyIndicator(cfg) {
  const ind = $("#proxy-ind");
  if (cfg && cfg.proxy) {
    ind.textContent = "⇄ " + cfg.proxy + (cfg.verify_tls === false ? " · TLS off" : "");
    ind.classList.remove("hidden");
  } else {
    ind.classList.add("hidden");
  }
}

// ── free-form runners (grouped by lane, pipelines first) ───────────────────────
function renderRunners() {
  const pl = $("#pipeline-list"); pl.innerHTML = "";
  PIPELINES.forEach((p) => {
    const d = document.createElement("div");
    d.className = "pipe";
    d.innerHTML = `<span><b>${esc(p.name)}</b><br><small class="muted">${esc((p.steps || []).join(" → "))}</small></span>`;
    const b = document.createElement("button"); b.className = "btn-primary"; b.textContent = "run";
    b.onclick = () => runPipeline(p.name); d.appendChild(b);
    pl.appendChild(d);
  });

  const filt = ($("#tool-filter").value || "").toLowerCase();
  const instOnly = $("#tool-installed-only").checked;
  const match = (t) =>
    (!filt || t.name.includes(filt) || (t.lane || "").includes(filt) ||
      (t.phase || "").includes(filt) || (t.description || "").toLowerCase().includes(filt)) &&
    (!instOnly || t.installed);

  const byLane = {};
  CATALOG.filter(match).forEach((t) => (byLane[t.lane] = byLane[t.lane] || []).push(t));
  const list = $("#tool-list"); list.innerHTML = "";
  Object.keys(byLane).sort().forEach((lane) => {
    const h = document.createElement("div"); h.className = "lane-head"; h.textContent = lane;
    list.appendChild(h);
    byLane[lane].forEach((t) => {
      const ran = COVERAGE_RAN.has(t.name);
      const badges = `${ran ? '<span class="badge ran">ran</span>' : ""}` +
        `${t.installed ? "" : '<span class="badge missing">not installed</span>'}`;
      const d = document.createElement("div");
      d.className = "row" + (t.installed ? "" : " off");
      d.innerHTML = `<span class="tool"><b>${esc(t.name)}</b> <small>${esc(t.phase)}</small>${badges}<br><small class="muted">${esc(t.description || "")}</small></span>`;
      const b = document.createElement("button"); b.textContent = "run";
      b.onclick = () => runTool(t.name); d.appendChild(b);
      list.appendChild(d);
    });
  });
  if (!list.children.length) list.innerHTML = `<span class="muted">no tools match.</span>`;
}
$("#tool-filter").oninput = renderRunners;
$("#tool-installed-only").onchange = renderRunners;

// Preview the exact command (flag memory or template), let the operator edit it,
// then run. Nothing fires at the target until they confirm — scope safety.
async function runTool(tool) {
  if (!TARGET) return;
  let prev;
  try { prev = await api("POST", `/targets/${enc(TARGET)}/preview-command`, { tool }); }
  catch (e) { setStatus("error: " + e.message); return; }
  if (prev.error) { setStatus("error: " + prev.error); return; }
  const note = (prev.missing && prev.missing.length)
    ? `   ⚠ fill in: ${prev.missing.join(", ")}` : "";
  const command = await prompt(`Run ${tool} — review / edit the command${note}`, prev.command, { short: true });
  if (command === null || !command.trim()) return;
  await busy(`running ${tool}`, async () => {
    const out = await api("POST", `/targets/${enc(TARGET)}/run`, { tool, command: command.trim() });
    if (out.error) throw new Error(out.error);
    setStatus(`${tool}: exit ${out.exit_code}${out.summary ? " — " + out.summary : ""}`);
  });
  await refresh();
}
async function runPipeline(name) {
  if (!TARGET) return;
  await busy(`pipeline ${name}`, () =>
    api("POST", `/targets/${enc(TARGET)}/run-pipeline`, { pipeline: name }));
  await refresh();
}

// ── request runner + report ───────────────────────────────────────────────────
$("#btn-request").onclick = async () => {
  if (!TARGET) return;
  // Host is authority only — strip scheme AND any path/query, or a URL target
  // like "https://h:81/app" leaks "Host: h:81/app".
  const host = TARGET.replace(/^https?:\/\//, "").replace(/[/?#].*$/, "");
  const tmpl = `GET / HTTP/1.1\nHost: ${host}\nUser-Agent: optio\n\n`;
  const raw = await prompt("Send raw request  (edit, then Ctrl/Cmd+Enter or OK)", tmpl);
  if (!raw || !raw.trim()) return;
  const out = await busy("sending", () =>
    api("POST", `/targets/${enc(TARGET)}/request-raw`, { raw }));
  if (out.error) { setStatus("error: " + out.error); return; }
  setStatus(`request #${out.request_id}: ${out.status} (${out.elapsed_ms} ms)`);
  await refresh();
  await showRequest(out.request_id);   // land on the captured request/response
};

$("#btn-auto").onclick = async () => {
  if (!TARGET) return;
  await busy("auto-running flow", async () => {
    const out = await api("POST", `/targets/${enc(TARGET)}/auto-run`, {});
    const ran = out.steps.filter((s) => s.command).length;
    const skipped = out.steps.filter((s) => s.skipped).length;
    setStatus(`auto-run: ${ran} ran, ${skipped} skipped`);
  });
  await refresh();
};

// ── config (structured: proxy, TLS, User-Agent, headers) ────────────────────────
$("#btn-config").onclick = async () => {
  if (!TARGET) return;
  let cfg;
  try { cfg = await api("GET", `/targets/${enc(TARGET)}/config`); }
  catch (e) { setStatus("error: " + e.message); return; }
  $("#cfg-proxy").value = cfg.proxy || "";
  $("#cfg-verify").checked = cfg.verify_tls !== false;   // default: verify on
  $("#cfg-ua").value = cfg.user_agent || "";
  $("#cfg-headers").value = Object.entries(cfg.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
  $("#config-modal").classList.remove("hidden");
};
$("#cfg-burp").onclick = () => { $("#cfg-proxy").value = "http://127.0.0.1:8080"; $("#cfg-verify").checked = false; };
$("#cfg-cancel").onclick = () => $("#config-modal").classList.add("hidden");
$("#cfg-save").onclick = async () => {
  const headers = {};
  ($("#cfg-headers").value || "").split("\n").forEach((line) => {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  const config = {
    proxy: $("#cfg-proxy").value.trim(),
    verify_tls: $("#cfg-verify").checked,
    user_agent: $("#cfg-ua").value.trim(),
    headers,
  };
  await busy("saving config", () => api("POST", `/targets/${enc(TARGET)}/config`, { config }));
  $("#config-modal").classList.add("hidden");
  await refresh();
};

// ── report (rendered markdown, copy / download) ─────────────────────────────────
// XSS-safe: every line is escaped FIRST, then only structural tags are added.
function mdToHtml(md) {
  const esced = (s) => esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
  let html = "", inCode = false, inList = false;
  for (const line of String(md).split("\n")) {
    if (line.trim().startsWith("```")) {
      html += inCode ? "</pre>" : "<pre>"; inCode = !inCode; continue;
    }
    if (inCode) { html += esc(line) + "\n"; continue; }
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) { if (inList) { html += "</ul>"; inList = false; } const n = h[1].length; html += `<h${n}>${esced(h[2])}</h${n}>`; continue; }
    if (line.startsWith("- ")) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${esced(line.slice(2))}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (line.trim()) html += `<p>${esced(line)}</p>`;
  }
  if (inCode) html += "</pre>";
  if (inList) html += "</ul>";
  return html;
}
let REPORT_MD = "";
$("#btn-report").onclick = async () => {
  if (!TARGET) return;
  const out = await busy("building report", () => api("GET", `/targets/${enc(TARGET)}/report`));
  REPORT_MD = out.markdown || "";
  $("#report-body").innerHTML = mdToHtml(REPORT_MD);
  $("#report-modal").classList.remove("hidden");
};
$("#report-close").onclick = () => $("#report-modal").classList.add("hidden");
$("#report-copy").onclick = async () => {
  try { await navigator.clipboard.writeText(REPORT_MD); setStatus("report copied"); }
  catch { setStatus("copy failed — select and copy manually"); }
};
$("#report-download").onclick = () => {
  const blob = new Blob([REPORT_MD], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `optio-report-${TARGET.replace(/[^\w.-]+/g, "_")}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
};

setHasTarget(false);
loadTargets().catch((e) => setStatus("error: " + e.message));
