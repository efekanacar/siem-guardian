"use strict";
const $ = (id) => document.getElementById(id);
let state = null, targets = [], reports = [], filter = "ALL", auth = "password", busy = false;
let polling = false, dirty = false, editingRule = null, editingDetection = null;
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
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("Yerel arayüz sunucusuna ulaşılamadı. Ubuntu terminalinde webapp.py çalışıyor mu? Sayfayı yenileyin; bağlantı ve kurallar yeniden yüklenebilir."); }
  let result;
  try { result = await response.json(); }
  catch { throw new Error("Yerel sunucudan eksik yanıt geldi. Terminali kontrol edip sayfayı yenileyin."); }
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
  ["rules-from-targets", "rule-new", "detection-new"].forEach((id) => $(id).disabled = busy);
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
  rememberLocal();
}
function rememberLocal() {
  try { localStorage.setItem("siem-guardian-inventory", JSON.stringify({targets, window: $("window").value,
    checks: state?.health_checks || [], detections: state?.detections || []})); } catch { /* Gizli modda depolama kapalı olabilir. */ }
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
  $("guardian-problem").textContent = results.length ? [...resources.values()].filter((items) => items.some((status) => ["ALERT", "NO_DATA"].includes(status))).length : "—";
  $("guardian-unknown").textContent = results.length ? [...resources.values()].filter((items) =>
    !items.some((status) => ["ALERT", "NO_DATA"].includes(status)) && !items.every((status) => status === "OK")).length : "—";
  $("health-count").textContent = rules.length;
  $("health-empty").hidden = !!rules.length;
  $("health-rules-wrap").hidden = !rules.length;
  $("health-export-rules").hidden = !rules.length;
  $("health-rules-body").replaceChildren();
  for (const rule of rules) {
    const row = document.createElement("tr");
    [rule.name, rule.kind, `${rule.index} / ${rule.host} / ${rule.sourcetype}${rule.source ? " / " + rule.source : ""}`, `${rule.window_minutes} dk · ${rule.availability === "intermittent" ? "aralıklı" : "sürekli"}`].forEach((value) => textCell(row, String(value), "td"));
    const actions = row.appendChild(document.createElement("td"));
    const edit = textCell(actions, "Düzenle", "button", "text-button"); edit.type = "button";
    edit.addEventListener("click", () => showRuleForm(rule.name));
    const remove = textCell(actions, "Sil", "button", "text-button"); remove.type = "button";
    remove.addEventListener("click", () => removeRule(rule.name));
    $("health-rules-body").append(row);
  }
  $("health-results-section").hidden = !results.length;
  $("health-checked-at").textContent = state?.health_checked_at ? `Ölçüm: ${state.health_checked_at}` : "";
  $("health-summary").replaceChildren();
  for (const status of ["OK", "ALERT", "NO_DATA", "QUIET", "INSUFFICIENT_BASELINE", "ERROR"]) {
    const count = results.filter((result) => result.status === status).length;
    if (results.length) textCell($("health-summary"), `${status}: ${count}`, "span", "badge " + ({OK:"ok",ALERT:"error",NO_DATA:"no-data",QUIET:"neutral",INSUFFICIENT_BASELINE:"delayed",ERROR:"error"}[status]));
  }
  $("health-results-body").replaceChildren();
  for (const result of results) {
    const row = document.createElement("tr");
    const cells = Array.from({length: 6}, () => row.appendChild(document.createElement("td")));
    textCell(cells[0], result.name, "strong"); textCell(cells[0], result.host, "small");
    textCell(cells[1], result.check_type);
    textCell(cells[2], result.status, "span", "badge " + ({OK:"ok",ALERT:"error",NO_DATA:"no-data",QUIET:"neutral",INSUFFICIENT_BASELINE:"delayed",ERROR:"error"}[result.status] || "neutral"));
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
    const edit = textCell(cells[3], "Düzenle", "button", "text-button"); edit.type = "button";
    edit.addEventListener("click", () => showDetectionForm(detection.name));
    const remove = textCell(cells[3], "Sil", "button", "text-button"); remove.type = "button";
    remove.addEventListener("click", () => removeDetection(detection.name));
    $("detection-body").append(row);
  }
  if ($("detection-form").hidden) renderDetectionEditor();
}
function formField(form, name) { return form.elements.namedItem(name); }
function showKindFields() {
  const kind = formField($("rule-form"), "kind").value;
  $("rule-form").querySelectorAll("[data-kinds]").forEach((label) => { label.hidden = !label.dataset.kinds.split(" ").includes(kind); });
}
function showRuleForm(name = null) {
  editingRule = name;
  const form = $("rule-form"); form.reset();
  const rule = state.health_checks.find((item) => item.name === name);
  if (rule) for (const [key, value] of Object.entries(rule)) { const input = formField(form, key); if (input) input.value = value; }
  const reference = formField(form, "activity_check"); reference.replaceChildren(new Option("Yok", ""));
  for (const item of state.health_checks) if (item.name !== name && item.host === formField(form, "host").value)
    reference.add(new Option(item.name, item.name));
  if (rule?.activity_check) reference.value = rule.activity_check;
  $("rule-form-title").textContent = rule ? "Sağlık kontrolünü düzenle" : "Sağlık kontrolü ekle";
  showKindFields(); form.hidden = false; form.scrollIntoView({behavior:"smooth", block:"center"});
}
async function saveConfig(checks, detections) {
  busy = true; buttonStates();
  try { applyState(await api("/api/health/config", {checks, detections}), false); rememberLocal(); notice("Kurallar kaydedildi. Sonuçlar için sağlık kontrolünü çalıştırın.", "success"); return true; }
  catch (error) { notice(error.message, "error"); return false; }
  finally { busy = false; buttonStates(); }
}
async function removeRule(name) {
  const checks = state.health_checks.filter((item) => item.name !== name).map((item) => item.activity_check === name ? {...item, activity_check:""} : item);
  const detections = state.detections.map((item) => ({...item, checks:item.checks.filter((check) => check !== name)})).filter((item) => item.checks.length);
  if (await saveConfig(checks, detections)) $("rule-form").hidden = true;
}
function renderDetectionEditor(selected = []) {
  const list = $("detection-check-options"); list.replaceChildren();
  for (const rule of state?.health_checks || []) {
    const label = document.createElement("label");
    const input = document.createElement("input"); input.type = "checkbox"; input.value = rule.name; input.checked = selected.includes(rule.name);
    label.append(input, document.createTextNode(" " + rule.name)); list.append(label);
  }
}
function showDetectionForm(name = null) {
  if (!state?.health_checks?.length) return notice("Önce en az bir sağlık kontrolü ekleyin.", "info");
  editingDetection = name;
  const form = $("detection-form"); form.reset();
  const detection = state.detections.find((item) => item.name === name);
  if (detection) for (const [key, value] of Object.entries(detection)) {const input = formField(form, key); if (input) input.value = value;}
  renderDetectionEditor(detection?.checks || []);
  $("detection-form-title").textContent = detection ? "Detection düzenle" : "Detection ekle";
  form.hidden = false; form.scrollIntoView({behavior:"smooth", block:"center"});
}
async function removeDetection(name) {
  if (await saveConfig(state.health_checks, state.detections.filter((item) => item.name !== name))) $("detection-form").hidden = true;
}
function renderDiagnostics() {
  const diagnostic = state?.diagnostics;
  $("check-details").hidden = dirty || !diagnostic?.search;
  $("diagnostic-body").replaceChildren();
  if (!diagnostic?.search) return;
  $("check-summary").textContent = (diagnostic.returned_rows == null
    ? `Arama güvenilir tamamlanmadı; kaynak satırları alınamadı · ${diagnostic.expected_targets} beklenen hedef değerlendirilemedi`
    : `API'den ${diagnostic.returned_rows} kaynak satırı alındı · ${diagnostic.expected_targets} beklenen hedefin ${diagnostic.matched_targets} tanesi eşleşti`)
    + (diagnostic.job?.sid ? ` · Arama kimliği: ${diagnostic.job.sid}` : "");
  $("check-window").textContent = `Splunk ölçüm zamanı: ${diagnostic.measurement_utc} · Pencere: ${diagnostic.window_start_utc} ≤ geliş < ${diagnostic.window_end_utc}`;
  $("check-error").textContent = diagnostic.error || "";
  $("check-error").hidden = !diagnostic.error;
  $("check-query").textContent = diagnostic.search;
  for (const source of diagnostic.sources) {
    const row = document.createElement("tr");
    [source.index, source.host, source.sourcetype, source.last_before_check_utc || source.error || "—", source.matched_events ?? "—"].forEach((value) => textCell(row, String(value), "td"));
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
  try {applyState(await api(path, data), !preserveTargets); if (busy) await poll(); if (["/api/import", "/api/discover", "/api/check", "/api/targets"].includes(path)) rememberLocal(); return true;}
  catch (error) {
    busy = false;
    let recovered = false;
    try {const latest = await api("/api/state"); applyState(latest, !preserveTargets); if (busy) await poll(); recovered = true;}
    catch { /* Asıl bağlantı hatası kullanıcıya gösterilir. */ }
    buttonStates();
    notice(recovered ? "İstek yanıtı kesildi; sunucunun son durumu yeniden okundu. İşlemin sonucunu ekranda doğrulayın." : error.message, recovered ? "info" : "error");
    return false;
  }
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
  try {if (file.size > 250000) throw new Error("Kontrol dosyası en fazla 250 KB olabilir."); const format = file.name.toLowerCase().endsWith(".csv") ? "csv" : "json"; if (await action("/api/health/import", {[format]: await file.text()}, true)) {rememberLocal(); notice("Sağlık kontrolleri yüklendi. Kaynak adlarını ve eşikleri inceleyin.", "success");}}
  catch (error) {notice(error.message, "error");} finally {event.target.value = "";}
});
$("health-run").addEventListener("click", () => action("/api/health/check", {}, true));
$("rules-from-targets").addEventListener("click", async () => {
  if (!targets.length) return notice("Önce Splunk'tan kaynakları getir veya hedef CSV yükle.", "info");
  const checks = [...state.health_checks];
  for (const target of targets) {
    if (checks.length >= 50) break;
    if (checks.some((rule) => rule.index === target.index && rule.host === target.host && rule.sourcetype === target.sourcetype && rule.kind === "presence" && !rule.source)) continue;
    const base = target.name.trim() || `${target.host} / ${target.sourcetype}`;
    let name = base, suffix = 2;
    while (checks.some((rule) => rule.name === name)) name = `${base} (${suffix++})`;
    checks.push({name, kind:"presence", index:target.index, host:target.host, sourcetype:target.sourcetype,
      window_minutes:Math.max(120, Math.ceil(Number(target.max_delay_minutes) || 30) + 1), availability:"intermittent", min_events:1});
  }
  if (checks.length === state.health_checks.length) return notice("Yeni kaynak bulunmadı veya 50 kontrol sınırına ulaşıldı.", "info");
  await saveConfig(checks, state.detections);
});
$("rule-new").addEventListener("click", () => showRuleForm());
$("rule-cancel").addEventListener("click", () => {$("rule-form").hidden = true;});
formField($("rule-form"), "kind").addEventListener("change", showKindFields);
formField($("rule-form"), "host").addEventListener("change", () => {
  const reference = formField($("rule-form"), "activity_check"); reference.replaceChildren(new Option("Yok", ""));
  for (const rule of state.health_checks) if (rule.name !== editingRule && rule.host === formField($("rule-form"), "host").value)
    reference.add(new Option(rule.name, rule.name));
});
$("rule-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget, kind = formField(form, "kind").value;
  const value = (key) => formField(form, key).value.trim();
  const rule = {name:value("name"), kind, index:value("index"), host:value("host"), sourcetype:value("sourcetype"), window_minutes:value("window_minutes"), availability:value("availability")};
  if (value("source")) rule.source = value("source");
  if (rule.availability === "intermittent" && value("activity_check")) rule.activity_check = value("activity_check");
  if (["presence", "event_id", "field", "route"].includes(kind)) rule.min_events = value("min_events");
  if (kind === "event_id") {rule.event_id_field = value("event_id_field"); rule.event_id = value("event_id");}
  if (kind === "field") {rule.field = value("field"); rule.min_present_percent = value("min_present_percent");}
  if (kind === "timestamp") {for (const key of ["timestamp_source", "max_bad_percent", "max_age_minutes", "max_future_minutes", "max_parse_diff_seconds"]) rule[key] = value(key); rule.min_events = value("min_events_timestamp");}
  if (kind === "volume") {rule.drop_percent = value("drop_percent"); rule.min_baseline_events = value("min_baseline_events");}
  const checks = state.health_checks.filter((item) => item.name !== editingRule);
  if (editingRule && editingRule !== rule.name) {
    for (const item of checks) if (item.activity_check === editingRule) item.activity_check = rule.name;
  }
  checks.push(rule);
  const detections = state.detections.map((item) => ({...item, checks:item.checks.map((name) => name === editingRule ? rule.name : name)}));
  if (await saveConfig(checks, detections)) form.hidden = true;
});
$("detection-new").addEventListener("click", () => showDetectionForm());
$("detection-cancel").addEventListener("click", () => {$("detection-form").hidden = true;});
$("detection-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  const checks = [...$("detection-check-options").querySelectorAll("input:checked")].map((input) => input.value);
  if (!checks.length) return notice("Detection için en az bir sağlık kontrolü seçin.", "error");
  const detection = {name:formField(form,"name").value.trim(), technique:formField(form,"technique").value.trim(),
    mode:formField(form,"mode").value, impact:formField(form,"impact").value.trim(), checks};
  const detections = state.detections.filter((item) => item.name !== editingDetection);
  detections.push(detection);
  if (await saveConfig(state.health_checks, detections)) form.hidden = true;
});
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
async function restoreLocal() {
  let saved;
  try {saved = JSON.parse(localStorage.getItem("siem-guardian-inventory") || "null");} catch {return;}
  if (!saved || busy) return;
  try {
    if (!state.targets.length && Array.isArray(saved.targets) && saved.targets.length)
      applyState(await api("/api/targets", {targets:saved.targets, window:saved.window || 120}));
    if (!state.health_checks.length && Array.isArray(saved.checks) && saved.checks.length)
      applyState(await api("/api/health/config", {checks:saved.checks, detections:saved.detections || []}));
    if ((saved.targets?.length || saved.checks?.length) && (state.targets.length || state.health_checks.length))
      notice("Yerel envanter tarayıcıdan geri yüklendi. Splunk bağlantısını yeniden kurup kontrolleri çalıştırın.", "info");
  } catch (error) { notice("Kaydedilen envanter geri yüklenemedi: " + error.message + " Dosyanızı tekrar yükleyebilirsiniz.", "error"); }
}
api("/api/state").then(async (next) => {applyState(next); if (busy) await poll(); else await restoreLocal();}).catch((error) => notice(error.message, "error"));
