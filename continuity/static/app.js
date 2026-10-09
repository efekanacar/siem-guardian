"use strict";
const $ = (id) => document.getElementById(id);
let state = null, targets = [], reports = [], filter = "ALL", auth = "password", busy = false;
let polling = false, dirty = false;
const fields = ["name", "index", "host", "sourcetype", "max_delay_minutes"];

function notice(message, kind = "info") {
  $("notice").textContent = message;
  $("notice").className = "notice " + kind;
  $("notice").hidden = !message;
}
async function api(path, data) {
  const options = {credentials: "same-origin", cache: "no-store"};
  if (data !== undefined) {
    options.method = "POST";
    options.headers = {"Content-Type": "application/json", "X-CSRF-Token": state?.csrf || ""};
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "İşlem tamamlanamadı.");
  return result;
}
function buttonStates() {
  const connected = !!state?.connected;
  $("connect").disabled = busy;
  $("disconnect").disabled = !connected && !busy;
  $("discover").disabled = busy || !connected;
  $("run").disabled = busy || !connected || !targets.length;
  $("add-target").disabled = busy;
  $("csv-file").disabled = busy;
  $("export-targets").disabled = busy || !targets.length;
  $("export-report").disabled = busy || !reports.length || dirty;
  $("export-diagnostics").disabled = busy || !state?.diagnostics?.search || dirty;
  $("health-run").disabled = busy || !connected || !state?.health_checks?.length;
  $("health-file").disabled = busy;
  $("window").disabled = busy;
  document.querySelectorAll("#target-body input, #target-body button").forEach((el) => el.disabled = busy);
  document.querySelectorAll("#connect-form input, #connect-form .auth-tabs button").forEach((el) => el.disabled = busy);
  const kind = state?.job?.kind;
  $("connect").firstElementChild.textContent = busy && kind === "connect" ? "Bağlanıyor…" : "Bağlan";
  $("run").lastChild.textContent = busy && kind === "check" ? " Kontrol ediliyor…" : " Kontrolü çalıştır";
  $("progress-label").textContent = busy ? (kind === "check" ? `${state.job.completed} / ${state.job.total} hedef kontrol edildi` : kind === "health" ? `${state.job.completed} / ${state.job.total} sağlık kontrolü tamamlandı` : kind === "connect" ? "Bağlantı doğrulanıyor…" : "Kaynaklar aranıyor…") : "Manuel kontrol · UTC";
}
function renderConnection() {
  const badge = $("connection-status");
  badge.className = "badge " + (state?.connected ? "ok" : "neutral");
  badge.textContent = state?.connected ? "Splunk bağlı" : "Bağlantı bekleniyor";
  $("connection-note").textContent = state?.connected ? state.address + (state.verify_tls ? " · TLS açık" : " · Lab: TLS kapalı") : "Giriş bilgileri yalnız bu oturumda tutulur.";
}
function markDirty() {
  dirty = true;
  reports = [];
  renderReports();
  renderDiagnostics();
  buttonStates();
}
function renderTargets() {
  $("target-count").textContent = targets.length;
  $("targets-empty").hidden = targets.length > 0;
  $("targets-wrap").hidden = !targets.length;
  $("target-body").replaceChildren();
  targets.forEach((target, position) => {
    const row = $("target-row").content.cloneNode(true);
    const sourceCell = row.querySelector(".source-cell");
    row.querySelectorAll("input").forEach((input) => {
      const key = input.dataset.field;
      input.value = target[key];
      input.addEventListener("input", () => {targets[position][key] = input.value; renderSources(sourceCell, targets[position]); markDirty();});
    });
    renderSources(sourceCell, target);
    row.querySelector("button").addEventListener("click", () => {targets.splice(position, 1); markDirty(); renderTargets(); buttonStates();});
    $("target-body").append(row);
  });
  const warnings = state?.discovery_warnings || [];
  $("discovery-warning").hidden = !warnings.length;
  $("discovery-warning").textContent = warnings.length ? "Keşif uyarısı: " + warnings.join(" ") + " Bu liste yalnız gözlenen kaynakları gösterir; hedeflerin sürekliliği ayrı kontrol edilir." : "";
}
function renderSources(cell, target) {
  cell.replaceChildren();
  const found = (state?.discovery_sources || []).find((item) => item.index === target.index && item.host === target.host && item.sourcetype === target.sourcetype);
  if (!found?.sources.length) {cell.textContent = "—"; cell.title = "Bu hedef için source bilgisi keşfedilmedi."; return;}
  if (found.sources.length === 1) textCell(cell, found.sources[0]);
  else {
    const details = document.createElement("details");
    textCell(details, `${found.sources.length} source`, "summary");
    found.sources.forEach((source) => textCell(details, source, "span"));
    cell.append(details);
  }
  cell.title = found.sources.join("\n");
}
function textCell(parent, text, tag = "span", className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}
function minutes(value) {
  return value === "" ? "—" : Number(value).toLocaleString("tr-TR", {maximumFractionDigits: 2}) + " dk";
}
function renderReports() {
  ["OK", "DELAYED", "NO_DATA", "ERROR"].forEach((status) => $("count-" + status).textContent = reports.length ? reports.filter((r) => r.status === status).length : "—");
  $("checked-at").textContent = dirty ? "Hedefler değişti. Güncel sonuçlar için kontrolü yeniden çalıştır." : state?.checked_at ? `Ölçüm: ${state.checked_at.replace("T", " ").replace("Z", " UTC")} · ${state.window} dakikalık aralık` : "İlk kontrolünden sonra sonuçlar burada görünecek.";
  $("result-toolbar").hidden = !reports.length;
  $("results-empty").hidden = reports.length > 0;
  $("results-wrap").hidden = !reports.length;
  $("result-body").replaceChildren();
  const query = $("result-search").value.toLocaleLowerCase("tr-TR");
  const visible = reports.filter((r) => (filter === "ALL" || r.status === filter) && [r.name, r.host, r.index, r.sourcetype].some((s) => s.toLocaleLowerCase("tr-TR").includes(query)));
  for (const report of visible) {
    const row = document.createElement("tr");
    const cells = Array.from({length: 6}, () => row.appendChild(document.createElement("td")));
    textCell(cells[0], report.name, "strong"); textCell(cells[0], report.host, "small");
    textCell(cells[1], report.index, "strong"); textCell(cells[1], report.sourcetype, "small");
    textCell(cells[2], report.last_seen_utc ? report.last_seen_utc.slice(0, 10) : "—");
    if (report.last_seen_utc) textCell(cells[2], report.last_seen_utc.slice(11).replace("Z", " UTC"), "small");
    textCell(cells[3], minutes(report.delay_minutes)); textCell(cells[4], minutes(report.threshold_minutes));
    textCell(cells[5], report.status, "span", "badge " + ({OK:"ok",DELAYED:"delayed",NO_DATA:"no-data",ERROR:"error"}[report.status] || "neutral"));
    if (report.error) textCell(cells[0], report.error, "small", "error-detail");
    if (report.note) textCell(cells[0], report.note, "small", "data-detail");
    $("result-body").append(row);
  }
  if (reports.length && !visible.length) {
    const row = document.createElement("tr"); const cell = row.appendChild(document.createElement("td"));
    cell.colSpan = 6; cell.textContent = "Bu filtreye uygun sonuç yok."; $("result-body").append(row);
  }
}
function applyState(next, updateTargets = true) {
  state = next; busy = next.job?.status === "RUNNING";
  if (updateTargets) { targets = next.targets.map((t) => ({...t})); $("window").value = next.window; dirty = false; renderTargets(); }
  reports = next.reports;
  renderConnection(); renderReports(); renderDiagnostics(); renderHealth(); buttonStates();
}
function renderHealth() {
  const rules = state?.health_checks || [], results = state?.health_results || [];
  const resources = new Map();
  const statusByName = new Map(results.map((result) => [result.name, result.status]));
  for (const rule of rules) {
    const key = JSON.stringify([rule.index, rule.host, rule.sourcetype, rule.source || ""]);
    if (!resources.has(key)) resources.set(key, []);
    resources.get(key).push(statusByName.get(rule.name));
  }
  $("guardian-expected").textContent = resources.size;
  $("guardian-healthy").textContent = results.length ? [...resources.values()].filter((items) => items.every((status) => status === "OK")).length : "—";
  $("guardian-problem").textContent = results.length ? [...resources.values()].filter((items) => items.some((status) => status && status !== "OK")).length : "—";
  $("health-count").textContent = rules.length;
  $("health-empty").hidden = !!rules.length;
  $("health-rules-wrap").hidden = !rules.length;
  $("health-export-rules").hidden = !rules.length;
  $("health-rules-body").replaceChildren();
  for (const rule of rules) {
    const row = document.createElement("tr");
    [rule.name, rule.kind, `${rule.index} / ${rule.host} / ${rule.sourcetype}${rule.source ? " / " + rule.source : ""}`, `${rule.window_minutes} dk`].forEach((value) => textCell(row, String(value), "td"));
    $("health-rules-body").append(row);
  }
  $("health-results-section").hidden = !results.length;
  $("health-checked-at").textContent = state?.health_checked_at ? `Ölçüm: ${state.health_checked_at}` : "";
  $("health-summary").replaceChildren();
  for (const status of ["OK", "ALERT", "NO_DATA", "INSUFFICIENT_BASELINE", "ERROR"]) {
    const count = results.filter((result) => result.status === status).length;
    if (results.length) textCell($("health-summary"), `${status}: ${count}`, "span", "badge " + ({OK:"ok",ALERT:"error",NO_DATA:"no-data",INSUFFICIENT_BASELINE:"delayed",ERROR:"error"}[status]));
  }
  $("health-results-body").replaceChildren();
  for (const result of results) {
    const row = document.createElement("tr");
    const cells = Array.from({length: 6}, () => row.appendChild(document.createElement("td")));
    textCell(cells[0], result.name, "strong"); textCell(cells[0], result.host, "small");
    textCell(cells[1], result.check_type);
    textCell(cells[2], result.status, "span", "badge " + ({OK:"ok",ALERT:"error",NO_DATA:"no-data",INSUFFICIENT_BASELINE:"delayed",ERROR:"error"}[result.status] || "neutral"));
    textCell(cells[3], result.observed || "—"); textCell(cells[4], result.threshold || "—");
    textCell(cells[5], result.details);
    if (result.search) {
      const details = document.createElement("details"); textCell(details, "SPL ve iş bilgisi", "summary");
      textCell(details, result.search, "pre");
      if (result.job?.sid) textCell(details, `Search job: ${result.job.sid}`, "small");
      cells[5].append(details);
    }
    $("health-results-body").append(row);
  }
  const detections = state?.detections || [], detectionResults = state?.detection_results || [];
  $("detection-count").textContent = detections.length;
  $("detection-empty").hidden = !!detections.length;
  $("detection-wrap").hidden = !detections.length;
  $("detection-export").hidden = !results.length || !detections.length;
  $("detection-body").replaceChildren();
  for (const detection of detectionResults) {
    const row = document.createElement("tr");
    const cells = Array.from({length: 4}, () => row.appendChild(document.createElement("td")));
    textCell(cells[0], detection.name, "strong"); textCell(cells[0], detection.technique, "small");
    textCell(cells[1], detection.status, "span", "badge " + ({COVERED:"ok",IMPAIRED:"error",UNKNOWN:"delayed",PENDING:"neutral"}[detection.status] || "neutral"));
    textCell(cells[2], `${detection.mode === "any" ? "Alternatif" : "Tümü gerekli"}: ` + Object.entries(detection.evidence).map(([name,status]) => `${name} (${status})`).join(" · "));
    textCell(cells[3], detection.impact || (detection.status === "PENDING" ? "Kontrol bekleniyor." : detection.status === "UNKNOWN" ? "Sonuç belirsiz; hatalı veya yetersiz kontrolleri inceleyin." : "Kapsam doğrulandı."));
    $("detection-body").append(row);
  }
}
function renderDiagnostics() {
  const diagnostic = state?.diagnostics;
  $("check-details").hidden = dirty || !diagnostic?.search;
  $("diagnostic-body").replaceChildren();
  if (!diagnostic?.search) return;
  $("check-summary").textContent = `API'den ${diagnostic.returned_rows} kaynak satırı alındı · ${diagnostic.expected_targets} beklenen hedefin ${diagnostic.matched_targets} tanesi eşleşti` + (diagnostic.job?.sid ? ` · Arama kimliği: ${diagnostic.job.sid}` : "");
  $("check-window").textContent = `Splunk ölçüm zamanı: ${diagnostic.measurement_utc} · Pencere: ${diagnostic.window_start_utc} ≤ geliş < ${diagnostic.window_end_utc}`;
  $("check-error").textContent = diagnostic.error || "";
  $("check-error").hidden = !diagnostic.error;
  $("check-query").textContent = diagnostic.search;
  for (const source of diagnostic.sources) {
    const row = document.createElement("tr");
    [source.index, source.host, source.sourcetype, source.last_before_check_utc || source.error || "—", source.latest_any_utc || "—", source.matched_events ?? "—"].forEach((value) => textCell(row, String(value), "td"));
    $("diagnostic-body").append(row);
  }
}
async function poll() {
  if (polling) return;
  polling = true;
  try {
    while (busy) {
      await new Promise((resolve) => setTimeout(resolve, 600));
      const next = await api("/api/state");
      applyState(next, next.job?.status !== "RUNNING" && next.job?.kind !== "health");
    }
    if (state.job?.status === "ERROR") {notice(state.job.error, "error"); if (state.job.kind === "check" && state.diagnostics?.search) $("check-details").open = true;}
    else if (state.job?.status === "DONE") {
      const kind = state.job.kind;
      const message = kind === "connect" ? "Splunk bağlantısı doğrulandı. Hedeflerini getirebilir veya CSV yükleyebilirsin." : kind === "discover" ? targets.length ? `${targets.length} hedef hazır. Host ve source bilgilerini incele, eşikleri düzenle ve kontrolü başlat.` : "Görünür indexlerde kaynak bulunamadı. Hesabın index yetkilerini kontrol et veya CSV yükle." : kind === "health" ? "Sağlık kontrolleri tamamlandı. Sonuçları ve SPL ayrıntılarını incele." : "Kontrol tamamlandı. Sonuçları inceleyebilir ve raporu indirebilirsin.";
      const allNoData = kind === "check" && reports.length && reports.every((r) => r.status === "NO_DATA");
      const healthErrors = kind === "health" && state.health_results?.some((r) => r.status === "ERROR");
      const healthAlerts = kind === "health" && state.health_results?.some((r) => r.status !== "OK");
      notice(allNoData ? "Bütün hedefler NO_DATA. Arama ayrıntılarında dönen kaynakları, hedef eşleşmelerini ve son geliş tarihlerini incele." : healthErrors ? "Bazı sağlık kontrolleri hata verdi. İlgili satırları ve SPL ayrıntılarını incele." : message,
        healthErrors ? "error" : allNoData || healthAlerts || (kind === "discover" && (state.discovery_warnings?.length || !targets.length)) ? "info" : "success");
      if (allNoData || (kind === "check" && reports.some((r) => r.status === "ERROR"))) $("check-details").open = true;
      if (kind === "connect") {$("password").value = ""; $("token").value = "";}
    }
  } catch (error) {busy = false; buttonStates(); notice("Arayüz bağlantısı kesildi. Sunucuyu kontrol edip sayfayı yenile.", "error");}
  finally {polling = false;}
}
async function action(path, data, preserveTargets = false) {
  busy = true; buttonStates(); notice("");
  try {applyState(await api(path, data), !preserveTargets); if (busy) await poll();}
  catch (error) {busy = false; buttonStates(); notice(error.message, "error");}
}
function payload() {return {window: $("window").value, targets};}
function authMode(mode) {
  auth = mode; $("password-fields").hidden = mode !== "password"; $("token-fields").hidden = mode !== "token";
  $("username").required = mode === "password"; $("password").required = mode === "password"; $("token").required = mode === "token";
  ["password", "token"].forEach((name) => {$(name + "-auth").classList.toggle("selected", mode === name); $(name + "-auth").setAttribute("aria-pressed", String(mode === name));});
}
$("password-auth").addEventListener("click", () => authMode("password"));
$("token-auth").addEventListener("click", () => authMode("token"));
$("tls").addEventListener("change", () => {$("tls-warning").hidden = $("tls").checked;});
$("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await action("/api/connect", {
    SPLUNK_BASE_URL: $("address").value, SPLUNK_USERNAME: auth === "password" ? $("username").value : "",
    SPLUNK_PASSWORD: auth === "password" ? $("password").value : "", SPLUNK_TOKEN: auth === "token" ? $("token").value : "",
    SPLUNK_VERIFY_TLS: String($("tls").checked), SPLUNK_CA_BUNDLE: $("ca-bundle").value,
  });
});
$("disconnect").addEventListener("click", async () => {await action("/api/disconnect", {}); $("password").value = ""; $("token").value = ""; notice("Bağlantı kapatıldı. Giriş bilgileri oturumdan silindi.");});
$("add-target").addEventListener("click", () => {
  if (targets.length >= 500) return notice("En fazla 500 hedef ekleyebilirsin.", "error");
  targets.push({name:"", index:"", host:"", sourcetype:"", max_delay_minutes:30}); markDirty(); renderTargets(); buttonStates(); $("target-body").lastElementChild.querySelector("input").focus();
});
$("window").addEventListener("input", markDirty);
$("discover").addEventListener("click", () => action("/api/discover", payload()));
$("run").addEventListener("click", () => {filter = "ALL"; $("result-search").value = ""; document.querySelector('[data-filter="ALL"]').click(); action("/api/check", payload());});
$("csv-file").addEventListener("change", async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try {if (file.size > 900000) throw new Error("CSV dosyası en fazla 900 KB olabilir."); await action("/api/import", {csv: await file.text(), window: $("window").value});}
  catch (error) {notice(error.message, "error");} finally {event.target.value = "";}
});
$("health-file").addEventListener("change", async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try {if (file.size > 250000) throw new Error("Kontrol dosyası en fazla 250 KB olabilir."); const format = file.name.toLowerCase().endsWith(".csv") ? "csv" : "json"; await action("/api/health/import", {[format]: await file.text()}, true); notice("Sağlık kontrolleri yüklendi. Kaynak adlarını ve eşikleri inceleyin.", "success");}
  catch (error) {notice(error.message, "error");} finally {event.target.value = "";}
});
$("health-run").addEventListener("click", () => action("/api/health/check", {}, true));
async function download(path, filename) {
  const response = await fetch(path, {credentials:"same-origin", cache:"no-store"});
  if (!response.ok) {const result = await response.json(); throw new Error(result.error);}
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("export-targets").addEventListener("click", async () => {
  busy = true; buttonStates();
  try {applyState(await api("/api/targets", payload())); await download("/api/targets.csv", "targets.csv"); notice("Hedef listesi indirildi.", "success");}
  catch (error) {notice(error.message, "error");} finally {busy = false; buttonStates();}
});
$("export-report").addEventListener("click", async () => {try {await download("/api/report.csv", "continuity-report.csv");} catch (error) {notice(error.message, "error");}});
$("export-diagnostics").addEventListener("click", async () => {try {await download("/api/diagnostics.json", "search-diagnostics.json");} catch (error) {notice(error.message, "error");}});
document.querySelectorAll("[data-filter]").forEach((button) => button.addEventListener("click", () => {
  filter = button.dataset.filter; document.querySelectorAll("[data-filter]").forEach((item) => {item.classList.toggle("selected", item === button); item.setAttribute("aria-pressed", String(item === button));}); renderReports();
}));
$("result-search").addEventListener("input", renderReports);
authMode("password");
api("/api/state").then((next) => {applyState(next); if (busy) poll();}).catch(() => notice("Arayüz başlatılamadı. Sunucuyu kontrol edip sayfayı yenile.", "error"));
