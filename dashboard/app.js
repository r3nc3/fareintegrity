const state = {
  token: null,
  user: null,
  tenants: [],
  tenantId: null,
  vehicles: [],
  routes: [],
  vehicleMap: {},
  stageMap: {},
  page: "overview",
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const PAGE_META = {
  overview: ["Overview", "Live view of fare record integrity"],
  transactions: ["Transactions", "Every fare record, validated and immutable"],
  ingest: ["Device ingest", "Sync device / CSV records and detect gaps"],
  anomalies: ["Anomalies", "Duplicates, gaps, mismatches and cash variances"],
  reconciliation: ["Reconciliation", "Shift and period reconciliation runs"],
  audit: ["Audit trail", "Append-only, hash-chained evidence"],
};

const canManage = () =>
  ["SACCO_ADMIN", "PLATFORM_ADMIN"].includes(state.user?.role);
const isPlatform = () => state.user?.role === "PLATFORM_ADMIN";

/* ---------- utilities ---------- */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function kes(cents) {
  if (cents === null || cents === undefined) return "—";
  return "KES " + (cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

function todayInput() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function uuid() {
  if (window.crypto?.randomUUID) return crypto.randomUUID();
  return "idem-" + Date.now() + "-" + Math.random().toString(36).slice(2);
}

function scopeParam(path) {
  if (isPlatform() && state.tenantId) {
    return path + (path.includes("?") ? "&" : "?") + "tenant_id=" + state.tenantId;
  }
  return path;
}

function bodyWithTenant(body) {
  if (isPlatform()) return { ...body, tenant_id: state.tenantId };
  return body;
}

let toastTimer = null;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("err", isError);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 4200);
}

async function api(method, path, body) {
  const headers = {};
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const error = new Error(
      (data && (data.detail || data.error)) || res.statusText || "Request failed"
    );
    error.status = res.status;
    error.data = data;
    throw error;
  }
  return data;
}

/* ---------- auth ---------- */

async function doLogin(event) {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const data = await api("POST", "/api/auth/login", {
      email: $("#login-email").value.trim(),
      password: $("#login-password").value,
    });
    state.token = data.token;
    state.user = data.user;
    state.tenantId = data.user.tenant_id;
    localStorage.setItem("fareguard_token", data.token);
    await bootstrap();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
}

function logout() {
  state.token = null;
  state.user = null;
  state.tenantId = null;
  localStorage.removeItem("fareguard_token");
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
}

async function resume() {
  const token = localStorage.getItem("fareguard_token");
  if (!token) return;
  state.token = token;
  try {
    state.user = await api("GET", "/api/me");
    state.tenantId = state.user.tenant_id;
    await bootstrap();
  } catch {
    logout();
  }
}

/* ---------- bootstrap ---------- */

async function bootstrap() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#user-chip").innerHTML =
    `<strong>${esc(state.user.full_name)}</strong>` +
    `${esc(state.user.role.replace("_", " "))}`;

  if (isPlatform()) {
    state.tenants = await api("GET", "/api/tenants");
    $("#tenant-wrap").classList.remove("hidden");
    $("#tenant-select").innerHTML = state.tenants
      .map((t) => `<option value="${t.id}">${esc(t.name)}</option>`)
      .join("");
    if (!state.tenantId && state.tenants.length) {
      state.tenantId = state.tenants[0].id;
    }
    $("#tenant-select").value = state.tenantId;
  } else {
    $("#tenant-wrap").classList.add("hidden");
  }

  await loadMasters();
  applyRole();
  updateScopeBadge();
  navigate("overview");
}

async function loadMasters() {
  state.vehicles = await api("GET", scopeParam("/api/vehicles"));
  state.routes = await api("GET", scopeParam("/api/routes"));
  state.vehicleMap = {};
  state.vehicles.forEach((v) => { state.vehicleMap[v.id] = v.reg_no; });
  state.stageMap = {};
  state.routes.forEach((r) => r.stages.forEach((s) => { state.stageMap[s.id] = s.name; }));
  populateMasters();
}

function updateScopeBadge() {
  const tenant = state.tenants.find((t) => t.id === state.tenantId);
  $("#scope-badge").textContent = isPlatform()
    ? (tenant ? tenant.name : "All SACCOs")
    : (state.user.tenant_name || "SACCO");
}

function applyRole() {
  const role = state.user.role;
  const hide = (page) => {
    const btn = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (btn) btn.classList.add("hidden");
  };
  if (role === "AUDITOR") {
    hide("ingest");
    $("#record-panel").classList.add("hidden");
    $("#recon-form")?.closest(".panel")?.classList.add("hidden");
  }
  if (role === "CONDUCTOR") {
    hide("audit");
    hide("reconciliation");
  }
  if (!canManage()) {
    $("#record-panel").classList.add("hidden");
  }
}

/* ---------- masters in forms ---------- */

function populateMasters() {
  const options = state.vehicles
    .map((v) => `<option value="${v.id}">${esc(v.reg_no)}${v.device_id ? " · " + esc(v.device_id) : ""}</option>`)
    .join("");
  ["#rf-vehicle", "#ing-vehicle", "#csv-vehicle"].forEach((sel) => {
    $(sel).innerHTML = options;
  });

  $("#rf-route").innerHTML = state.routes
    .map((r) => `<option value="${r.id}">${esc(r.name)}</option>`)
    .join("");
  populateStages();

  $("#ing-vehicle").addEventListener("change", () => {
    const vehicle = state.vehicles.find((v) => String(v.id) === $("#ing-vehicle").value);
    if (vehicle?.device_id) $("#ing-device").value = vehicle.device_id;
  });
}

function populateStages() {
  const route = state.routes.find((r) => String(r.id) === $("#rf-route").value)
    || state.routes[0];
  const stages = route ? route.stages : [];
  $("#rf-stage").innerHTML = stages
    .map((s) => `<option value="${s.id}" data-fare="${s.fare_cents}">${esc(s.name)} — ${kes(s.fare_cents)}</option>`)
    .join("");
  updateAmount();
}

function updateAmount() {
  const option = $("#rf-stage").selectedOptions[0];
  const fare = option ? Number(option.dataset.fare) : 0;
  const pax = Math.max(1, Number($("#rf-passengers").value) || 1);
  $("#rf-amount").value = ((fare * pax) / 100).toFixed(2);
}

/* ---------- navigation ---------- */

function navigate(page) {
  state.page = page;
  $$(".page").forEach((p) => p.classList.add("hidden"));
  const section = $("#page-" + page);
  if (section) section.classList.remove("hidden");
  $$(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.page === page);
  });
  const meta = PAGE_META[page] || ["", ""];
  $("#page-title").textContent = meta[0];
  $("#page-subtitle").textContent = meta[1];
  const renderers = {
    overview: renderOverview,
    transactions: renderTransactions,
    ingest: renderIngest,
    anomalies: renderAnomalies,
    reconciliation: renderReconciliation,
    audit: renderAudit,
  };
  renderers[page]?.();
}

/* ---------- overview ---------- */

async function renderOverview() {
  const stats = await api("GET", scopeParam("/api/dashboard/stats"));
  $("#stat-score").textContent = stats.integrity_score;
  $("#stat-score-note").textContent =
    stats.integrity_score >= 80 ? "healthy" : stats.integrity_score >= 50 ? "needs attention" : "critical";
  $("#stat-open").textContent = stats.open_flags;
  $("#stat-sev").textContent =
    `HIGH ${stats.by_severity.HIGH} · MED ${stats.by_severity.MEDIUM} · LOW ${stats.by_severity.LOW}`;
  $("#stat-today").textContent = stats.transactions_today;
  $("#stat-today-amt").textContent = kes(stats.total_amount_cents) + " recorded";
  $("#stat-missing").textContent = stats.missing_records;
  $("#stat-dupes").textContent = stats.duplicate_suspects;
  $("#stat-cash").textContent = stats.cash_mismatches;
  renderBars("#severity-bars", stats.by_severity, true);
  renderBars("#kind-bars", stats.by_kind, false);
  renderFlagsTable("#recent-flags-table", stats.recent_flags, false);
}

function renderBars(selector, data, severityColors) {
  const el = $(selector);
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    el.innerHTML = `<p class="muted small">No anomalies.</p>`;
    return;
  }
  const max = Math.max(...entries.map(([, v]) => v), 1);
  el.innerHTML = entries.map(([key, value]) => {
    const cls = severityColors ? key : "";
    return `<div class="bar-row">
      <span>${esc(key)}</span>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${(value / max) * 100}%"></div></div>
      <strong>${value}</strong>
    </div>`;
  }).join("");
}

/* ---------- transactions ---------- */

async function renderTransactions() {
  const params = new URLSearchParams();
  if ($("#tf-day").value) params.set("day", $("#tf-day").value);
  if ($("#tf-method").value) params.set("method", $("#tf-method").value);
  if ($("#tf-integrity").value) params.set("integrity_status", $("#tf-integrity").value);
  params.set("limit", "200");
  const rows = await api("GET", scopeParam("/api/transactions?" + params.toString()));
  renderTxTable(rows);
}

function renderTxTable(rows) {
  const el = $("#tx-table");
  if (!rows.length) {
    el.innerHTML = `<tbody><tr><td class="empty">No transactions match the filter.</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr>
    <th>Time</th><th>Ticket</th><th>Vehicle</th><th>Stage</th><th>Tender</th>
    <th>Pax</th><th>Amount</th><th>Source</th><th>Integrity</th><th>Status</th><th></th>
  </tr></thead>`;
  const body = rows.map((t) => {
    const reversible = t.status === "RECORDED" && canManage();
    return `<tr>
      <td class="mono">${fmtDate(t.occurred_at)}</td>
      <td class="mono">${esc(t.external_ref)}</td>
      <td>${esc(state.vehicleMap[t.vehicle_id] || t.vehicle_id)}</td>
      <td>${esc(state.stageMap[t.stage_id] || t.stage_id)}</td>
      <td>${esc(t.method)}</td>
      <td>${t.passenger_count}</td>
      <td>${kes(t.amount_cents)}</td>
      <td class="muted">${esc(t.source)}</td>
      <td><span class="pill ${t.integrity_status}">${t.integrity_status}</span></td>
      <td><span class="pill ${t.status}">${t.status}</span></td>
      <td>${reversible ? `<button class="btn danger small" data-reverse="${t.id}">Reverse</button>` : ""}</td>
    </tr>`;
  }).join("");
  el.innerHTML = head + `<tbody>${body}</tbody>`;
}

async function submitRecord(event) {
  event.preventDefault();
  const resultEl = $("#rf-result");
  resultEl.textContent = "";
  const body = bodyWithTenant({
    vehicle_id: Number($("#rf-vehicle").value),
    route_id: Number($("#rf-route").value),
    stage_id: Number($("#rf-stage").value),
    passenger_count: Number($("#rf-passengers").value),
    amount_cents: Math.round(Number($("#rf-amount").value) * 100),
    method: $("#rf-method").value,
    external_ref: $("#rf-ref").value.trim() || undefined,
    provider_receipt: $("#rf-receipt").value.trim() || undefined,
    idempotency_key: uuid(),
  });
  if ($("#rf-when").value) {
    body.occurred_at = new Date($("#rf-when").value).toISOString();
  }
  try {
    const tx = await api("POST", "/api/transactions", body);
    resultEl.textContent = `Recorded ticket ${tx.external_ref} (${tx.integrity_status}).`;
    toast("Fare recorded: " + tx.external_ref);
    $("#rf-ref").value = "";
    $("#rf-receipt").value = "";
    renderTransactions();
  } catch (err) {
    if (err.status === 409 && err.data?.existing) {
      resultEl.textContent =
        `Duplicate blocked. Existing ticket ${err.data.existing.external_ref} ` +
        `(#${err.data.existing.id}) was returned instead.`;
      toast("Duplicate charge blocked", true);
    } else {
      resultEl.textContent = err.message;
      toast(err.message, true);
    }
  }
}

/* ---------- ingest ---------- */

async function renderIngest() {
  const batches = await api("GET", scopeParam("/api/ingest/batches"));
  const el = $("#batch-table");
  if (!batches.length) {
    el.innerHTML = `<tbody><tr><td class="empty">No batches ingested yet.</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr><th>When</th><th>Source</th><th>Device</th><th>Records</th><th>Accepted</th><th>Duplicates</th><th>Flagged</th><th>Gaps</th></tr></thead>`;
  const body = batches.map((b) => `<tr>
    <td class="mono">${fmtDate(b.received_at)}</td>
    <td>${esc(b.source)}</td>
    <td class="mono">${esc(b.device_id || "—")}</td>
    <td>${b.record_count}</td>
    <td>${b.accepted_count}</td>
    <td>${b.duplicate_count}</td>
    <td>${b.flagged_count}</td>
    <td>${b.gap_count ? `<span class="pill HIGH">${b.gap_count}</span>` : "0"}</td>
  </tr>`).join("");
  el.innerHTML = head + `<tbody>${body}</tbody>`;
}

async function runBatchIngest() {
  let records;
  try {
    records = JSON.parse($("#ing-json").value);
    if (!Array.isArray(records)) throw new Error("JSON must be an array");
  } catch (err) {
    toast("Invalid JSON: " + err.message, true);
    return;
  }
  try {
    const body = bodyWithTenant({
      source: "DEVICE",
      device_id: $("#ing-device").value.trim() || null,
      vehicle_id: Number($("#ing-vehicle").value) || null,
      records,
    });
    const result = await api("POST", "/api/ingest/batch", body);
    $("#ing-result").textContent = JSON.stringify(result, null, 2);
    toast(`Ingested: ${result.accepted_count} accepted, ${result.duplicate_count} duplicates, ${result.missing_sequences.length} gaps`);
    renderIngest();
  } catch (err) {
    toast(err.message, true);
  }
}

async function runCsvIngest() {
  try {
    const body = bodyWithTenant({
      source: "CSV",
      device_id: $("#csv-device").value.trim() || null,
      vehicle_id: Number($("#csv-vehicle").value) || null,
      csv: $("#csv-text").value,
    });
    const result = await api("POST", "/api/ingest/csv", body);
    $("#csv-result").textContent = JSON.stringify(result, null, 2);
    toast(`CSV: ${result.accepted_count} accepted, ${result.duplicate_count} duplicates, ${result.missing_sequences.length} gaps`);
    renderIngest();
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------- anomalies ---------- */

async function renderAnomalies() {
  const params = new URLSearchParams();
  if ($("#af-status").value) params.set("status", $("#af-status").value);
  if ($("#af-severity").value) params.set("severity", $("#af-severity").value);
  params.set("limit", "200");
  const rows = await api("GET", scopeParam("/api/flags?" + params.toString()));
  renderFlagsTable("#flag-table", rows, true);
}

function renderFlagsTable(selector, rows, actions) {
  const el = $(selector);
  if (!rows || !rows.length) {
    el.innerHTML = `<tbody><tr><td class="empty">No anomalies.</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr>
    <th>Detected</th><th>Type</th><th>Severity</th><th>Detail</th><th>Status</th>
    ${actions ? "<th>Action</th>" : ""}
  </tr></thead>`;
  const body = rows.map((f) => {
    const actionable = actions && canManage()
      && ["OPEN", "INVESTIGATING"].includes(f.status);
    const actionCell = actions
      ? `<td>${actionable ? `
          <button class="btn ghost small" data-flag-action="resolve" data-id="${f.id}">Resolve</button>
          <button class="btn ghost small" data-flag-action="dismiss" data-id="${f.id}">Dismiss</button>
        ` : ""}</td>`
      : "";
    return `<tr>
      <td class="mono">${fmtDate(f.detected_at)}</td>
      <td>${esc(f.kind)}</td>
      <td><span class="pill ${f.severity}">${f.severity}</span></td>
      <td>${esc(f.detail)}</td>
      <td><span class="pill ${f.status}">${f.status}</span></td>
      ${actionCell}
    </tr>`;
  }).join("");
  el.innerHTML = head + `<tbody>${body}</tbody>`;
}

/* ---------- reconciliation ---------- */

async function renderReconciliation() {
  const runs = await api("GET", scopeParam("/api/reconcile/runs"));
  const el = $("#recon-table");
  if (!runs.length) {
    el.innerHTML = `<tbody><tr><td class="empty">No reconciliation runs yet.</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr>
    <th>Period</th><th>Run at</th><th>Transactions</th><th>Total</th>
    <th>Device gaps</th><th>Duplicate groups</th><th>Cash mismatches</th>
    <th>Open flags</th><th>Score</th>
  </tr></thead>`;
  const body = runs.map((r) => {
    const s = r.summary || {};
    const gaps = Object.values(s.device_gaps || {}).reduce((a, b) => a + b.length, 0);
    return `<tr>
      <td>${esc(s.period || r.period_start.slice(0, 10))}</td>
      <td class="mono">${fmtDate(r.run_at)}</td>
      <td>${s.transaction_count ?? "—"}</td>
      <td>${kes(s.total_amount_cents)}</td>
      <td>${gaps ? `<span class="pill HIGH">${gaps}</span>` : "0"}</td>
      <td>${s.duplicate_groups ?? 0}</td>
      <td>${s.cash_mismatches ?? 0}</td>
      <td>${r.findings_count}</td>
      <td><strong>${r.integrity_score}</strong></td>
    </tr>`;
  }).join("");
  el.innerHTML = head + `<tbody>${body}</tbody>`;
}

async function runReconciliation(event) {
  event.preventDefault();
  try {
    const result = await api("POST", "/api/reconcile/run", bodyWithTenant({
      day: $("#recon-day").value || undefined,
    }));
    const s = result.summary;
    $("#recon-result").textContent =
      `${s.transaction_count} transactions · ${result.findings_count} open flags · score ${result.integrity_score}`;
    toast("Reconciliation complete");
    renderReconciliation();
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------- audit ---------- */

async function renderAudit() {
  const rows = await api("GET", scopeParam("/api/audit?limit=200"));
  const el = $("#audit-table");
  if (!rows.length) {
    el.innerHTML = `<tbody><tr><td class="empty">No audit entries.</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Entity</th><th>Summary</th><th>Hash</th></tr></thead>`;
  const body = rows.map((e) => `<tr>
    <td class="mono">${e.id}</td>
    <td class="mono">${fmtDate(e.ts)}</td>
    <td>${esc(e.actor_email || "system")}</td>
    <td>${esc(e.action)}</td>
    <td>${esc(e.entity)}${e.entity_id ? " #" + e.entity_id : ""}</td>
    <td>${esc(e.summary || "")}</td>
    <td class="mono">${esc(e.hash)}</td>
  </tr>`).join("");
  el.innerHTML = head + `<tbody>${body}</tbody>`;
}

async function verifyAudit() {
  try {
    const result = await api("GET", "/api/audit/verify");
    $("#audit-verify-result").textContent = result.ok
      ? `Chain intact · ${result.entries_checked} entries verified`
      : `TAMPER DETECTED · ${result.issue}`;
    toast(result.ok ? "Audit chain verified" : "Audit chain tampered", !result.ok);
  } catch (err) {
    toast(err.message, true);
  }
}

/* ---------- events ---------- */

function bindEvents() {
  $("#login-form").addEventListener("submit", doLogin);
  $("#logout-btn").addEventListener("click", logout);
  $$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => navigate(btn.dataset.page));
  });

  $("#tenant-select").addEventListener("change", async (e) => {
    state.tenantId = Number(e.target.value);
    updateScopeBadge();
    await loadMasters();
    navigate(state.page);
  });

  $("#rf-route").addEventListener("change", populateStages);
  $("#rf-stage").addEventListener("change", updateAmount);
  $("#rf-passengers").addEventListener("input", updateAmount);
  $("#record-form").addEventListener("submit", submitRecord);

  $("#tf-refresh").addEventListener("click", renderTransactions);
  $("#tf-method").addEventListener("change", renderTransactions);
  $("#tf-integrity").addEventListener("change", renderTransactions);
  $("#tf-day").addEventListener("change", renderTransactions);
  $("#tf-export").addEventListener("click", () => {
    const day = $("#tf-day").value;
    window.open(scopeParam("/api/export/transactions.csv" + (day ? "?day=" + day : "")), "_blank");
  });

  $("#ing-run").addEventListener("click", runBatchIngest);
  $("#csv-run").addEventListener("click", runCsvIngest);

  $("#af-refresh").addEventListener("click", renderAnomalies);
  $("#af-status").addEventListener("change", renderAnomalies);
  $("#af-severity").addEventListener("change", renderAnomalies);
  $("#af-export").addEventListener("click", () => {
    window.open(scopeParam("/api/export/flags.csv"), "_blank");
  });

  $("#recon-form").addEventListener("submit", runReconciliation);
  $("#audit-verify").addEventListener("click", verifyAudit);

  document.addEventListener("click", async (event) => {
    const goto = event.target.closest("[data-goto]");
    if (goto) { navigate(goto.dataset.goto); return; }

    const flagBtn = event.target.closest("[data-flag-action]");
    if (flagBtn) {
      const status = flagBtn.dataset.flagAction === "resolve" ? "RESOLVED" : "DISMISSED";
      const note = prompt(
        status === "RESOLVED" ? "Resolution note" : "Reason for dismissing",
        ""
      );
      if (note === null) return;
      try {
        await api("POST", `/api/flags/${flagBtn.dataset.id}/resolve`, { status, note });
        toast(`Anomaly ${status.toLowerCase()}`);
        renderAnomalies();
        if (state.page === "overview") renderOverview();
      } catch (err) {
        toast(err.message, true);
      }
      return;
    }

    const reverseBtn = event.target.closest("[data-reverse]");
    if (reverseBtn) {
      const reason = prompt("Reason for reversing this transaction", "");
      if (reason === null) return;
      try {
        await api("POST", `/api/transactions/${reverseBtn.dataset.reverse}/reverse`, { reason });
        toast("Transaction reversed (original row retained)");
        renderTransactions();
      } catch (err) {
        toast(err.message, true);
      }
    }
  });
}

/* ---------- init ---------- */

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  $("#recon-day").value = todayInput();
  $("#ing-json").value = JSON.stringify([
    { external_ref: "DEV-1001", device_seq: 1, stage: "Ruiru", passenger_count: 1, amount: 40, method: "CASH", occurred_at: "2026-11-09T08:00:00" },
    { external_ref: "DEV-1002", device_seq: 2, stage: "Ruiru", passenger_count: 1, amount: 40, method: "CASH", occurred_at: "2026-11-09T08:10:00" },
    { external_ref: "DEV-1004", device_seq: 4, stage: "Kahawa West", passenger_count: 1, amount: 70, method: "CASH", occurred_at: "2026-11-09T08:20:00" },
  ], null, 2);
  resume();
});
