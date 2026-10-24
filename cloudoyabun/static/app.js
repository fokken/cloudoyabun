"use strict";
const $ = id => document.getElementById(id);
const selection = new Map();
const state = {token: "", assessments: [], assessment: "", view: "findings", offset: 0, sort: "title", direction: "asc", request: 0, finding: null, run: null, logAfter: 0, logRequest: 0};

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
function badge(text) {
  const safe = ["high", "critical", "medium", "low", "informational", "confirmed", "succeeded", "pass", "failed", "fail", "timed-out", "running", "needs-review"];
  const style = String(text || "").toLowerCase();
  return element("span", text || "—", "badge " + (safe.includes(style) ? style : ""));
}
function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = error ? "error" : "";
  $("notice").hidden = false;
}
async function api(path, options = {}) {
  const response = await fetch("/api" + path, {...options, headers: {"X-CloudOyabun-Token": state.token, ...options.headers}});
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(typeof data.detail === "string" ? data.detail : "Request failed. Check the fields and try again.");
  }
  return response.json();
}
function jsonOptions(method, body) { return {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}; }
function guarded(fn) { return (...args) => Promise.resolve().then(() => fn(...args)).catch(error => notice(error.message, true)); }
function assessmentPath(suffix) { return `/assessments/${state.assessment}/${suffix}`; }
function facet(id, values, label) {
  const previous = $(id).value;
  $(id).replaceChildren(new Option(label, ""), ...values.map(v => new Option(v, v)));
  if (values.includes(previous)) $(id).value = previous;
}
async function loadAssessments(preferred) {
  state.assessments = await api("/assessments");
  $("assessment").replaceChildren(...state.assessments.map(a => new Option(a.name, a.id)));
  if (state.assessments.some(a => a.id === preferred)) $("assessment").value = preferred;
  state.assessment = $("assessment").value;
  await refreshAssessment();
}
async function refreshOverview() {
  if (!state.assessment) return;
  const id = state.assessment;
  const overview = await api(assessmentPath("overview"));
  if (state.assessment !== id) return;
  for (const key of ["total", "unreviewed", "selected", "runs"]) $("stat-" + key).textContent = overview.counts[key];
  $("nav-count").textContent = overview.counts.total;
  facet("tool", overview.facets.tool, "All tools");
  facet("provider", overview.facets.provider, "All providers");
  facet("severity", overview.facets.severity, "All severities");
  facet("category", overview.facets.category, "All categories");
}
async function refreshAssessment() {
  state.offset = 0;
  clearSelection();
  state.run = null;
  $("log-panel").hidden = true;
  $("welcome").hidden = !!state.assessment;
  $("workspace").hidden = !state.assessment;
  $("import-button").disabled = !state.assessment;
  if (!state.assessment) return;
  $("scope").textContent = state.assessments.find(a => a.id === state.assessment).scope;
  await refreshOverview();
  await loadView();
}
async function loadView() {
  if (!state.assessment) return;
  if (state.view === "findings") await loadFindings();
  if (state.view === "runs") await loadRuns();
  if (state.view === "reports") await loadReports();
  if (state.view === "ai") await loadAI();
  if (state.view === "repeat") await loadRepeat();
}
async function switchView(view) {
  state.view = view;
  document.querySelectorAll(".nav").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  for (const name of ["findings", "runs", "reports", "ai", "repeat"]) $(name + "-view").hidden = view !== name;
  const titles = {repeat: ["Repeat assessments", "Track change over time", "Compare imports, retain decisions, and manage recurring noise."], ai: ["AI assistance", "Review evidence with AI", "Summaries and priorities, grounded in selected findings."], findings: ["Findings", "Finding workbench", "Investigate the evidence. Surface what matters."], runs: ["Execution log", "Every step, accounted for", "Follow tool execution and inspect the original output."], reports: ["Reports", "From evidence to insight", "Build a technical report from your selected findings."]};
  [$("breadcrumb").textContent, $("page-title").textContent, $("page-description").textContent] = titles[view];
  await loadView();
}
function findingParams() {
  const params = new URLSearchParams({suppression: $("suppression").value, q: $("search").value, sort: state.sort, direction: state.direction, limit: 50});
  for (const key of ["tool", "provider", "severity", "disposition", "category", "tag"]) if ($(key).value) params.set(key, $(key).value);
  if ($("selected-only").checked) params.set("selected", "true");
  return params;
}
function displayedChecks() {
  return [...$("finding-rows").querySelectorAll("input[data-finding]")].filter(input => {
    const group = input.closest(".group-detail");
    return !group || !group.hidden;
  });
}
function updateSelection() {
  $("bulk-bar").hidden = selection.size === 0;
  $("bulk-count").textContent = `${selection.size} selected`;
  const checks = displayedChecks();
  checks.forEach(input => { input.checked = selection.has(input.dataset.finding); });
  const count = checks.filter(input => input.checked).length;
  $("select-displayed").checked = checks.length > 0 && count === checks.length;
  $("select-displayed").indeterminate = count > 0 && count < checks.length;
  $("select-displayed").disabled = checks.length === 0;
}
function clearSelection() { selection.clear(); updateSelection(); }
function selectFinding(input, checked) {
  if (checked) {
    if (selection.size >= 1000 && !selection.has(input.dataset.finding)) {
      notice("Select at most 1000 findings per tag operation.", true); return;
    }
    selection.set(input.dataset.finding, {id: input.dataset.finding, revision: Number(input.dataset.revision)});
  } else selection.delete(input.dataset.finding);
}
function findingRow(finding) {
  const row = element("tr"), selectCell = element("td", null, "select-cell"), check = element("input");
  check.type = "checkbox"; check.dataset.finding = finding.id; check.dataset.revision = finding.revision;
  check.setAttribute("aria-label", `Select ${finding.title || "finding"} on ${finding.asset || finding.id}`);
  check.checked = selection.has(finding.id);
  check.onchange = () => { selectFinding(check, check.checked); updateSelection(); };
  selectCell.append(check); row.append(selectCell);
  const title = element("td");
  const button = element("button", finding.title || finding.rule_id || "Untitled finding", "finding-link");
  button.addEventListener("click", guarded(() => openFinding(finding.id)));
  title.append(button, element("span", finding.asset || finding.rule_id || "No asset reference", "asset"));
  title.append(element("span", `${finding.environment || "Environment unspecified"} · run ${finding.run_id.slice(0, 8)}`, "asset"));
  if (finding.tags.length) title.append(element("span", finding.tags.join(" · "), "finding-tags"));
  row.append(title, element("td", finding.provider || "—", "provider-mark"));
  const severityCell = element("td");
  severityCell.append(badge(finding.effective_severity), element("small", finding.severity_override ? "Analyst override" : "Tool", "asset"));
  row.append(severityCell);
  const statusCell = element("td"); statusCell.append(badge(finding.native_status)); row.append(statusCell);
  row.append(element("td", finding.category || "—"), element("td", finding.priority ? "P" + finding.priority : "—"));
  const triage = element("td"); triage.append(badge(finding.disposition)); row.append(triage);
  const selected = element("td", finding.selected ? "✓" : "—", finding.selected ? "report-mark" : "muted");
  selected.setAttribute("aria-label", finding.selected ? "Included in report" : "Not selected");
  row.append(selected); return row;
}
function appendGroup(group, request, params) {
  const row = element("tr", null, "check-group"), cell = element("td"); cell.colSpan = 2;
  const toggle = element("button", `▸ ${group.title || group.rule_id || "Untitled check"}`, "group-toggle");
  toggle.setAttribute("aria-expanded", "false");
  cell.append(toggle, element("span", `${group.count} matching findings`, "count-pill"),
    element("span", `${group.tool} · ${group.rule_id || "No check ID; individual record"}`, "asset"));
  const provider = element("td", group.provider || "—", "provider-mark");
  const severity = element("td");
  severity.append(badge(group.severity), element("small", group.override_count ? `${group.override_count} of ${group.count} analyst overrides` : "Tool", "asset"));
  severity.title = `Group severity: ${group.severities.map(value => value || "Unspecified").join(", ")}`;
  const remainder = element("td"); remainder.colSpan = 5;
  row.append(cell, provider, severity, remainder);
  const detail = element("tr", null, "group-detail"), detailCell = element("td"); detailCell.colSpan = 9;
  const table = element("table"), body = element("tbody"), more = element("button", "Load more findings", "quiet");
  table.setAttribute("aria-label", `Findings for ${group.rule_id || group.title}`);
  table.append(body); detailCell.append(table, more); detail.append(detailCell); detail.hidden = true;
  $("finding-rows").append(row, detail);
  let loaded = 0, initialized = false;
  async function loadChildren() {
    more.disabled = true; toggle.disabled = true;
    try {
      const query = new URLSearchParams(params); query.set("group_key", group.group_key); query.set("offset", loaded);
      const data = await api(assessmentPath("findings?") + query);
      if (request !== state.request) return;
      data.items.forEach(finding => body.append(findingRow(finding)));
      loaded += data.items.length; initialized = true;
      more.hidden = loaded >= data.total;
      more.textContent = `Load more findings (${loaded} of ${data.total} displayed)`;
      updateSelection();
    } finally { more.disabled = false; toggle.disabled = false; }
  }
  toggle.onclick = guarded(async () => {
    detail.hidden = !detail.hidden;
    toggle.setAttribute("aria-expanded", String(!detail.hidden));
    toggle.textContent = `${detail.hidden ? "▸" : "▾"} ${group.title || group.rule_id || "Untitled check"}`;
    if (!detail.hidden && !initialized) await loadChildren();
    updateSelection();
  });
  more.onclick = guarded(loadChildren);
}
async function loadFindings() {
  const request = ++state.request, params = findingParams();
  const grouped = $("group-checks").checked;
  const query = new URLSearchParams(params); query.set("offset", state.offset); query.set("grouped", grouped);
  $("finding-rows").replaceChildren(); updateSelection();
  const data = await api(assessmentPath("findings?") + query);
  if (request !== state.request) return;
  for (const item of data.items) {
    if (grouped) appendGroup(item, request, params);
    else $("finding-rows").append(findingRow(item));
  }
  updateSelection();
  const unit = grouped ? "check groups" : "findings";
  $("result-count").textContent = `${data.total} ${unit}`;
  $("no-findings").hidden = data.items.length > 0;
  $("page-info").textContent = data.total ? `${state.offset + 1}–${state.offset + data.items.length} of ${data.total} ${unit}` : `0 ${unit}`;
  $("previous").disabled = state.offset === 0;
  $("next").disabled = state.offset + 50 >= data.total;
}
async function openFinding(id) {
  const assessment = state.assessment, request = (state.detailRequest || 0) + 1;
  state.detailRequest = request;
  const finding = await api("/findings/" + id);
  if (assessment !== state.assessment || request !== state.detailRequest) return;
  state.finding = finding;
  const f = state.finding, form = $("triage-form");
  $("suppression-state").textContent = f.suppressed ? "An active rule currently suppresses this finding. Manage rules in Repeat assessments." : "No active suppression applies.";
  $("suppress-reason").value = ""; $("suppress-expiry").value = ""; $("suppress-check").checked = false;
  $("detail-title").textContent = f.title || "Untitled finding";
  $("detail-tool").textContent = `${f.tool.toUpperCase()} / NATIVE FINDING`;
  $("detail-meta").textContent = `${f.provider || "Provider unspecified"} · ${f.environment || "Environment unspecified"} · ${f.asset || "No asset reference"} · Original tool severity: ${f.severity || "Unspecified"} · Effective severity: ${f.effective_severity || "Unspecified"} (${f.severity_override ? "analyst override" : "tool"}) · ${f.native_status || "No check status"}`;
  for (const key of ["disposition", "priority", "category", "report_order", "notes"]) form.elements[key].value = f[key];
  form.elements.severity_override.value = f.severity_override || "";
  form.elements.tags.value = f.tags.join(", ");
  form.elements.selected.checked = f.selected;
  $("native-payload").textContent = JSON.stringify(f.payload, null, 2);
  $("provenance").textContent = JSON.stringify({run_id: f.run_id, artifact_id: f.artifact_id, locator: f.locator, source_executions: f.source_executions, metadata_sources: f.provenance}, null, 2);
  $("artifact-download").href = "/api/artifacts/" + f.artifact_id;
  $("audit-summary").textContent = `Decision history (${f.audit.length})`;
  $("audit-list").replaceChildren(...f.audit.map(item => {
    const entry = element("div", `${new Date(item.timestamp).toLocaleString()} · ${item.actor}`, "audit-entry");
    const changes = Object.entries(item.after_state).filter(([key, value]) => JSON.stringify(value) !== JSON.stringify(item.before_state[key]));
    entry.append(element("pre", JSON.stringify(Object.fromEntries(changes), null, 2)));
    return entry;
  }));
  $("save-status").textContent = "";
  if (!$("finding-dialog").open) $("finding-dialog").showModal();
}
async function saveTriage(event) {
  event.preventDefault();
  const finding = state.finding, assessment = state.assessment, detailRequest = state.detailRequest;
  const current = () => state.assessment === assessment && state.finding === finding && state.detailRequest === detailRequest;
  const form = $("triage-form"), changes = {revision: finding.revision};
  for (const key of ["disposition", "category", "notes"]) changes[key] = form.elements[key].value;
  changes.severity_override = form.elements.severity_override.value || null;
  changes.priority = Number(form.elements.priority.value);
  changes.report_order = Number(form.elements.report_order.value);
  changes.tags = form.elements.tags.value.split(",").map(t => t.trim()).filter(Boolean);
  changes.selected = form.elements.selected.checked;
  const button = form.querySelector('[type="submit"]'); button.disabled = true;
  try {
    await api("/findings/" + finding.id, jsonOptions("PATCH", changes));
    if (state.assessment === assessment) { selection.delete(finding.id); updateSelection(); }
    if (!current()) return;
    $("finding-dialog").close();
    notice("Analyst decision saved. Original tool evidence is unchanged.");
    await refreshOverview(); await loadFindings();
  } catch (error) { if (current()) $("save-status").textContent = error.message; }
  finally { button.disabled = false; }
}
async function loadRuns() {
  const id = state.assessment;
  const [runs, archives] = await Promise.all([api(assessmentPath("runs")), api(assessmentPath("scan-archives"))]);
  if (id !== state.assessment) return;
  const signature = JSON.stringify([runs, archives]);
  if (signature === state.runsSignature) return;
  state.runsSignature = signature;
  $("run-list").replaceChildren();
  if (!runs.length) $("run-list").append(element("p", "No runs yet. Import a result file or invoke a tool through the CLI.", "muted"));
  for (const run of runs) {
    const card = element("div", null, "run-card"), content = element("div");
    const button = element("button", `${run.tool} · ${run.kind}`);
    button.addEventListener("click", guarded(() => openRun(run)));
    content.append(button, element("small", `${new Date(run.started_at).toLocaleString()} · ${run.id.slice(0, 12)}${run.exit_code !== null ? " · exit " + run.exit_code : ""}`));
    if (run.kind === "import" && ["failed", "interrupted"].includes(run.status)) {
      const retry = element("button", "Retry import", "quiet");
      retry.onclick = guarded(async () => {
        retry.disabled = true;
        try {
          const result = await api(`/runs/${run.id}/retry-import`, {method: "POST"});
          if (id !== state.assessment) return;
          state.runsSignature = "";
          notice(`Import retry ${result.run.status}: ${result.accepted} findings.`, result.run.status !== "succeeded");
          await loadRuns(); await openRun(result.run);
        } finally { retry.disabled = false; }
      });
      content.append(retry);
    }
    card.append(content, badge(run.status)); $("run-list").append(card);
  }
  $("archive-list").replaceChildren();
  if (!archives.length) $("archive-list").append(element("p", "No imported scans to archive yet.", "muted"));
  for (const archive of archives) {
    const card = element("div", null, "report-card");
    const details = element("div", `${archive.name} · ${archive.finding_count} findings`);
    details.append(element("small", `${archive.adapter} · ${new Date(archive.started_at).toLocaleString()}`));
    const link = element("a", "Download scan ZIP ↗", "quiet");
    link.href = `/api/artifacts/${archive.id}/archive`;
    card.append(details, link); $("archive-list").append(card);
  }
  await refreshOverview();
}
async function openRun(run) {
  state.run = run.id;
  $("log-title").textContent = `${run.tool} / ${run.id.slice(0, 12)}`;
  $("log-download").href = `/api/runs/${run.id}/logs`;
  $("log-panel").hidden = false;
  await loadLogs(true);
}
async function loadLogs(reset = false) {
  if (!state.run) return;
  const request = ++state.logRequest;
  if (reset) state.logAfter = 0;
  const params = new URLSearchParams({after: state.logAfter, source: $("log-source").value, q: $("log-search").value});
  const rows = await api(`/runs/${state.run}/events?` + params);
  if (request !== state.logRequest) return;
  if (reset) $("events").replaceChildren();
  for (const row of rows) {
    const item = element("div", null, "event " + (row.source === "stderr" ? "stderr" : row.source === "stdout" ? "stdout" : "orchestrator"));
    item.append(element("span", `#${row.seq} ${row.timestamp} +${row.elapsed_ms}ms · ${row.step} / attempt ${row.attempt} · ${row.source} · ${row.type}`, "event-label"));
    item.append(document.createTextNode(row.type === "output" ? row.details.text : JSON.stringify(row.details)));
    $("events").append(item);
  }
  if (rows.length) state.logAfter = rows[rows.length - 1].seq;
  $("more-events").hidden = rows.length < 500;
  $("log-state").textContent = `Through event #${state.logAfter} · refreshes every 3s`;
}
async function loadReports() {
  const id = state.assessment;
  const reports = await api(assessmentPath("reports"));
  if (id !== state.assessment) return;
  $("report-list").replaceChildren();
  if (!reports.length) $("report-list").append(element("p", "No report snapshots yet. Select findings from the workbench, then create a snapshot.", "muted"));
  for (const report of reports) {
    const card = element("div", null, "report-card"), details = element("div", `Technical report · ${report.finding_count} findings`);
    details.append(element("small", `${new Date(report.created_at).toLocaleString()} · ${report.id.slice(0, 12)}`));
    const link = element("a", "Download Markdown ↗", "quiet"); link.href = `/api/reports/${report.id}/download`;
    card.append(details, link); $("report-list").append(card);
  }
}
function newAssessment() { $("assessment-error").textContent = ""; $("assessment-dialog").showModal(); }
$("new-assessment").onclick = newAssessment; $("welcome-create").onclick = newAssessment;
$("close-assessment").onclick = () => $("assessment-dialog").close();
$("close-finding").onclick = () => $("finding-dialog").close();
$("assessment-form").onsubmit = async event => {
  event.preventDefault(); const form = event.currentTarget, button = form.querySelector('[type="submit"]'); button.disabled = true;
  try {
    const created = await api("/assessments", jsonOptions("POST", {name: form.elements.name.value, scope: form.elements.scope.value}));
    $("assessment-dialog").close(); form.reset(); await loadAssessments(created.id); notice("Assessment created. Import results to start investigating.");
  } catch (error) { $("assessment-error").textContent = error.message; }
  finally { button.disabled = false; }
};
$("assessment").onchange = guarded(async () => {
  state.assessment = $("assessment").value; ++state.request; ++state.logRequest;
  $("finding-dialog").close(); state.finding = null;
  for (const key of ["search", "tool", "provider", "severity", "disposition", "category", "tag"]) $(key).value = "";
  $("selected-only").checked = false; $("notice").hidden = true; await refreshAssessment();
});
document.querySelectorAll(".nav").forEach(button => button.onclick = guarded(() => switchView(button.dataset.view)));
document.querySelectorAll("[data-sort]").forEach(button => button.onclick = guarded(async () => {
  state.direction = state.sort === button.dataset.sort && state.direction === "asc" ? "desc" : "asc";
  state.sort = button.dataset.sort; state.offset = 0; await loadFindings();
}));
for (const key of ["suppression", "tool", "provider", "severity", "disposition", "category", "selected-only"]) $(key).onchange = guarded(async () => { clearSelection(); state.offset = 0; await loadFindings(); });
let searchTimer;
for (const key of ["search", "tag"]) $(key).oninput = () => { clearSelection(); ++state.request; clearTimeout(searchTimer); searchTimer = setTimeout(guarded(async () => { state.offset = 0; await loadFindings(); }), 200); };
$("previous").onclick = guarded(async () => { state.offset = Math.max(0, state.offset - 50); await loadFindings(); });
$("next").onclick = guarded(async () => { state.offset += 50; await loadFindings(); });
$("triage-form").onsubmit = saveTriage;
$("import-button").onclick = () => $("import-file").click();
$("import-file").onchange = guarded(async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 25 * 1024 * 1024) throw new Error("Import exceeds the 25 MiB limit.");
  $("import-button").disabled = true; $("import-button").textContent = "Importing…";
  try {
    const result = await api(assessmentPath("imports?") + new URLSearchParams({filename: file.name, adapter: $("import-format").value}), {method: "POST", headers: {"Content-Type": "application/octet-stream"}, body: file});
    const problem = ["failed", "partial"].includes(result.run.status);
    notice(`${result.reused ? "Existing import reused" : "Import " + result.run.status}: ${result.accepted} findings. ${problem ? "Inspect the execution log for rejected records or parsing errors." : "Native evidence has been retained."}`, problem);
    await refreshOverview(); await loadView();
    if (problem) { await switchView("runs"); await openRun(result.run); }
  } finally { $("import-button").disabled = false; $("import-button").textContent = "＋ Import results"; event.target.value = ""; }
});
$("refresh-runs").onclick = guarded(loadRuns);
$("restore-button").onclick = () => $("restore-file").click();
$("restore-file").onchange = guarded(async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 64 * 1024 * 1024) throw new Error("Scan archive exceeds the 64 MiB limit.");
  $("restore-button").disabled = true;
  try {
    const result = await api(assessmentPath("restore"), {method: "POST", headers: {"Content-Type": "application/zip"}, body: file});
    state.runsSignature = "";
    notice(result.reused ? `This scan is already present (${result.findings} findings); existing analyst decisions were kept.` : `Scan restored with ${result.findings} findings and its recorded logs.`);
    await loadRuns();
  } finally { $("restore-button").disabled = false; event.target.value = ""; }
});
$("refresh-log").onclick = guarded(() => loadLogs(true));
$("log-source").onchange = guarded(() => loadLogs(true));
$("log-search").onchange = guarded(() => loadLogs(true));
$("more-events").onclick = guarded(() => loadLogs());
$("create-report").onclick = guarded(async () => {
  $("create-report").disabled = true;
  try { const result = await api(assessmentPath("reports"), {method: "POST"}); notice(`Report snapshot created with ${result.finding_count} findings.`); await loadReports(); }
  finally { $("create-report").disabled = false; }
});
setInterval(() => { if (state.view === "runs" && state.assessment && !document.hidden) guarded(async () => { await loadRuns(); if (state.run && $("more-events").hidden) await loadLogs(); })(); }, 3000);
guarded(async () => { state.token = (await api("/session")).token; await loadAssessments(); })();

$("group-checks").onchange = guarded(async () => { state.offset = 0; await loadFindings(); });
$("select-displayed").onchange = () => {
  const checked = $("select-displayed").checked;
  displayedChecks().forEach(input => selectFinding(input, checked)); updateSelection();
};
$("clear-selection").onclick = clearSelection;
$("apply-tags").onclick = guarded(async () => {
  const assessment = state.assessment;
  const targets = [...selection.values()];
  const tags = $("bulk-tags").value.split(",").map(t => t.trim()).filter(Boolean);
  if (!tags.length) throw new Error("Enter at least one tag.");
  $("apply-tags").disabled = true;
  try {
    const result = await api(assessmentPath("bulk-tags"), jsonOptions("POST", {targets, tags, mode: $("bulk-mode").value}));
    if (assessment !== state.assessment) return;
    clearSelection(); $("bulk-tags").value = "";
    notice(`Tags updated on ${result.updated} of ${result.selected} selected findings. Existing unrelated tags and native evidence are preserved.`);
    await loadFindings();
  } finally { $("apply-tags").disabled = false; }
});

async function loadAI() {
  const assessment = state.assessment;
  const [config, history] = await Promise.all([api("/ai/config"), api(assessmentPath("ai"))]);
  if (assessment !== state.assessment) return;
  $("ai-config").textContent = `${config.endpoint} · ${config.model || "No model configured"} · ${config.protocol}. ${config.configured ? "Ready" : "Configure CLOUDOYABUN_AI_BASE_URL, CLOUDOYABUN_AI_MODEL and optional OPENAI_API_KEY on the server; restart to apply."}`;
  $("ai-detail").replaceChildren();
  $("ai-history").replaceChildren();
  if (!history.length) $("ai-history").append(element("p", "No analyses yet.", "muted"));
  for (const item of history) {
    const button = element("button", `${new Date(item.created_at).toLocaleString()} · ${item.model || "Model unset"} · ${item.status} · ${item.review_status}`, "quiet");
    button.onclick = guarded(async () => {
      const detail = await api(`/assessments/${assessment}/ai/${item.id}`);
      if (assessment === state.assessment) renderAI(detail, config);
    });
    $("ai-history").append(button);
  }
}
function renderAI(item, config) {
  const host = $("ai-detail"); host.replaceChildren();
  host.append(element("h2", item.status === "draft" ? "Review AI input" : "AI suggestions"),
    element("p", `${item.endpoint} · ${item.model || "Model unset"} · ${item.evidence.length} findings · ${item.status} · ${item.review_status}`));
  const details = element("details"), summary = element("summary", "Exact input sent to the model");
  details.append(summary, element("pre", JSON.stringify(item.evidence, null, 2))); host.append(details);
  if (item.batches && item.batches.length) {
    const completed = element("details"); completed.append(element("summary", `${item.batches.length} completed batch analyses (retained even on failure)`), element("pre", JSON.stringify(item.batches,null,2))); host.append(completed);
  }
  if (item.error) host.append(element("p", item.error, "form-error"));
  if (item.status === "draft") {
    host.append(element("p", `${item.plan.batches || 1} batches plus synthesis calls as needed. ${item.plan.include_native ? "Redacted native evidence included; oversized records are explicitly truncated." : "Metadata only."} Analyst notes are excluded. Inspect input for sensitive text. Selection does not establish complete assessment coverage.`));
    const send = element("button", "Send to AI server", "primary"); send.disabled = !config.configured || ["endpoint", "model", "protocol"].some(key => item[key] !== config[key]);
    send.onclick = guarded(async () => {
      send.disabled = true; send.textContent = "Analyzing…";
      try {
        const result = await api(`/assessments/${item.assessment_id}/ai/${item.id}/generate`, {method:"POST"});
        if (state.assessment === item.assessment_id && state.view === "ai") { await loadAI(); if (state.assessment === item.assessment_id && state.view === "ai") renderAI(result, config); }
      } finally { send.textContent = "Refresh history to check request status"; }
    }); host.append(send);
  }
  if (item.status === "succeeded") {
    host.append(element("p", item.result.limitations, "muted"));
    for (const area of item.result.areas) {
      const card = element("article", null, "ai-area");
      card.append(element("h3", `${area.area} · Suggested priority ${area.priority}`), element("p", area.summary), element("p", area.rationale), element("p", area.next_steps));
      for (const id of area.finding_ids) {
        const f = item.evidence.find(f => f.id === id);
        const link = element("button", f.title || id, "finding-link"); link.onclick = guarded(() => openFinding(id)); card.append(link);
      }
      host.append(card);
    }
    for (const status of ["reviewed", "dismissed"]) {
      const button = element("button", `Mark ${status}`, "quiet");
      button.onclick = guarded(async () => {
        const result = await api(`/assessments/${item.assessment_id}/ai/${item.id}`, jsonOptions("PATCH", {status}));
        if (state.assessment === item.assessment_id && state.view === "ai") { await loadAI(); if (state.assessment === item.assessment_id && state.view === "ai") renderAI(result, config); }
      }); host.append(button);
    }
  }
}
$("refresh-ai").onclick = guarded(loadAI);
$("ai-selected").onclick = guarded(async () => {
  const assessment = state.assessment, finding_ids = [...selection.keys()];
  if (finding_ids.length > 2000) throw new Error("Select at most 2000 findings for one analysis.");
  const item = await api(assessmentPath("ai"), jsonOptions("POST", {finding_ids, include_native: $("ai-native").checked, batch_size: Number($("ai-batch-size").value)}));
  if (assessment !== state.assessment) return;
  await switchView("ai");
  const config = await api("/ai/config");
  if (assessment === state.assessment) renderAI(item, config);
});

$("ai-scope").onclick = guarded(async () => {
  const assessment = state.assessment;
  const item = await api(assessmentPath("ai"), jsonOptions("POST", {category:$("ai-category").value.trim(), include_native:$("ai-native").checked, batch_size:Number($("ai-batch-size").value)}));
  const config = await api("/ai/config");
  if (assessment === state.assessment) { await loadAI(); renderAI(item,config); }
});
async function loadRepeat() {
  const [artifacts,rules] = await Promise.all([api("/reassessment/artifacts"),api("/suppressions")]);
  for (const key of ["compare-before","compare-after"]) {
    const previous = $(key).value;
    $(key).replaceChildren(...artifacts.map(a => new Option(`${a.assessment_name} · ${a.name} · ${a.status} · ${a.id.slice(0,8)}`,a.id)));
    if (artifacts.some(a=>a.id===previous)) $(key).value=previous;
  }
  $("suppression-list").replaceChildren();
  if (!rules.length) $("suppression-list").append(element("p","No rules yet. Open a finding to suppress recurring noise."));
  for (const rule of rules) {
    const card=element("article",null,"ai-area");
    card.append(element("h3",`${rule.tool} · ${rule.rule_id}`),element("p",`${rule.provider} · ${rule.environment} · ${rule.asset || "All resources"} · status ${rule.native_status || "unset"}`),element("p",rule.reason),element("p",`${rule.enabled ? "Enabled" : "Disabled"} · Expires: ${rule.expires_at || "Never"}`));
    const button=element("button",rule.enabled ? "Disable rule" : "Enable rule","quiet");
    button.onclick=guarded(async()=>{await api(`/suppressions/${rule.id}`,jsonOptions("PATCH",{enabled:!rule.enabled}));await loadRepeat();});card.append(button);$("suppression-list").append(card);
  }
}
$("suppress-finding").onclick=guarded(async()=>{
  await api("/suppressions",jsonOptions("POST",{finding_id:state.finding.id,reason:$("suppress-reason").value,expires_at:$("suppress-expiry").value || null,whole_check:$("suppress-check").checked}));
  $("finding-dialog").close();notice("Suppression rule saved. Original findings and report selections remain intact.");await loadView();
});
$("compare-scans").onclick=guarded(async()=>{
  const result=await api("/reassessment/compare",jsonOptions("POST",{before_id:$("compare-before").value,after_id:$("compare-after").value}));
  const host=$("comparison-result");host.replaceChildren(element("p",result.warning));
  const counts={};for (const row of result.rows) counts[row.status]=(counts[row.status]||0)+1;
  host.append(element("p",Object.entries(counts).map(([k,v])=>`${k}: ${v}`).join(" · ")));
  const eligible=result.rows.filter(r=>r.status==="unchanged" && r.after[0].revision===0 && r.before[0].revision>0);
  host.append(element("p",`${eligible.length} unchanged, untouched matches eligible for decision carry-forward. Category, tags, disposition, priority, severity override and notes only; report inclusion/order are not copied.`));
  for (const row of result.rows) {
    const detail=element("details");detail.append(element("summary",`${row.status} · ${(row.after[0] || row.before[0]).title}`),element("pre",JSON.stringify({earlier:row.before,later:row.after},null,2)));host.append(detail);
  }
  const carry=element("button","Carry forward eligible decisions","primary");carry.disabled=!eligible.length;
  carry.onclick=guarded(async()=>{carry.disabled=true;const applied=await api(`/reassessment/${result.id}/carry`,{method:"POST"});notice(`Carried decisions to ${applied.updated} findings. Source links are in decision history.`);await refreshOverview();});host.append(carry);
});

$("bulk-category-mode").onchange = () => { $("bulk-category").disabled = $("bulk-category-mode").value !== "set"; };
$("apply-triage").onclick = guarded(async () => {
  const assessment = state.assessment, targets = [...selection.values()], changes = {};
  if ($("bulk-disposition").value) changes.disposition = $("bulk-disposition").value;
  if ($("bulk-severity").value) changes.severity_override = $("bulk-severity").value === "reset" ? null : $("bulk-severity").value;
  if ($("bulk-report").value) changes.selected = $("bulk-report").value === "add";
  const notesMode = $("bulk-notes-mode").value;
  if (notesMode) {
    changes.notes_mode = notesMode;
    if (notesMode !== "clear") {
      changes.notes = $("bulk-notes").value;
      if (!changes.notes.trim()) throw new Error("Enter analyst notes first.");
    }
  }
  const mode = $("bulk-category-mode").value;
  if (mode === "clear") changes.category = "";
  if (mode === "set") {
    changes.category = $("bulk-category").value.trim();
    if (!changes.category) throw new Error("Enter a category, or choose Clear category.");
  }
  if (!Object.keys(changes).length) throw new Error("Choose a disposition, category, report selection, severity, or notes change first.");
  $("apply-triage").disabled = true;
  try {
    const result = await api(assessmentPath("bulk-triage"), jsonOptions("POST", {targets, ...changes}));
    if (assessment !== state.assessment) return;
    clearSelection(); $("bulk-severity").value = ""; $("bulk-notes-mode").value = ""; $("bulk-notes").value = ""; $("bulk-notes").disabled = true; $("bulk-report").value = ""; $("bulk-disposition").value = ""; $("bulk-category-mode").value = "keep";
    $("bulk-category").value = ""; $("bulk-category").disabled = true;
    notice(`Decisions updated on ${result.updated} of ${result.selected} selected findings.`);
    await refreshOverview(); await loadFindings();
  } finally { $("apply-triage").disabled = false; }
});

$("bulk-notes-mode").onchange = () => { $("bulk-notes").disabled = !["append", "replace"].includes($("bulk-notes-mode").value); };
