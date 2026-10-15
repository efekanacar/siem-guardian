"""Splunk saved alert tanımlarını ve log bağımlılıklarını salt okunur analiz eder."""

from __future__ import annotations

import csv
import io
import math
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable

from .core import CheckError, as_utc
from .splunk import MAX_EPOCH, spl_string, stamp


MAX_ALERTS = 200
MAX_DEPENDENCIES = 32
MAX_UNIQUE_DEPENDENCIES = 500
FIELD = re.compile(
    r"(?i)(?<![\w.])(?P<field>index|host|sourcetype|source)\s*=\s*"
    r"(?P<value>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s()|,]+)"
)
EVENT = re.compile(
    r"(?i)(?<![\w.])(?:EventCode|EventID|event_id)\s*=\s*"
    r"(?P<value>\"[0-9]+\"|'[0-9]+'|[0-9]+)"
)
MACRO = re.compile(r"`[^`]+`")


def _bool(value, field: str) -> bool:
    if value in (True, 1, "1", "true", "True"):
        return True
    if value in (False, 0, "0", "false", "False", ""):
        return False
    raise ValueError(f"{field} değeri geçersiz.")


def _text(value, field: str, limit=8192, allow_empty=False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} metin olmalı.")
    value = value.strip()
    if (not value and not allow_empty) or len(value) > limit or any(ord(c) < 32 and c not in "\t\r\n" for c in value):
        raise ValueError(f"{field} geçersiz.")
    return value


def _literal(raw: str) -> str | None:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        quote = raw[0]
        raw = raw[1:-1].replace("\\" + quote, quote).replace("\\\\", "\\")
    if not raw or len(raw) > 4096 or any(ch in raw for ch in "*$[]{}"):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    return raw


@dataclass(frozen=True)
class AlertDependency:
    index: str = ""
    host: str = ""
    sourcetype: str = ""
    source: str = ""
    event_ids: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        parts = []
        for name in ("index", "host", "sourcetype", "source"):
            value = getattr(self, name)
            if value:
                parts.append(f"{name}={value}")
        if self.event_ids:
            parts.append("Event ID=" + ",".join(self.event_ids))
        return " · ".join(parts) or "Kaynak seçicisi bulunamadı"


@dataclass(frozen=True)
class AlertDefinition:
    key: str
    name: str
    app: str
    owner: str
    search: str
    alert_type: str
    cron: str
    earliest: str
    latest: str
    dependencies: tuple[AlertDependency, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class DependencyResult:
    dependency: AlertDependency
    status: str
    event_count: int | None
    last_seen_utc: str
    details: str
    search: str


@dataclass(frozen=True)
class AlertResult:
    alert: AlertDefinition
    status: str
    details: str
    dependencies: tuple[DependencyResult, ...]
    checked_at_utc: str


def extract_dependencies(search: str) -> tuple[tuple[AlertDependency, ...], tuple[str, ...]]:
    """Açık SPL alan eşitliklerini çıkarır; makro/datamodel içeriğini tahmin etmez."""
    search = _text(search, "Alert SPL")
    values: dict[str, list[str]] = {name: [] for name in ("index", "host", "sourcetype", "source")}
    occurrences: dict[str, list[tuple[str, int, int]]] = {name: [] for name in values}
    warnings = []
    for match in FIELD.finditer(search):
        field = match.group("field").lower()
        value = _literal(match.group("value"))
        if value is None:
            warnings.append(f"{field} seçicisi wildcard/token içeriyor; otomatik sağlık sorgusuna eklenmedi.")
        else:
            occurrences[field].append((value, match.start(), match.end()))
            if value not in values[field]:
                values[field].append(value)
    all_event_ids = tuple(dict.fromkeys(match.group("value").strip("\"'") for match in EVENT.finditer(search)))
    if MACRO.search(search):
        warnings.append("SPL makro içeriyor; makro içindeki kaynaklar otomatik çözümlenmedi.")
    if re.search(r"(?i)\|?\s*(?:from|datamodel|tstats)\b", search) and not (values["sourcetype"] or values["source"]):
        warnings.append("Veri modeli/tstats bağımlılığı açık sourcetype veya source içermiyor; manuel eşleme gerekli.")
    if not values["sourcetype"] and not values["source"]:
        warnings.append("Açık bir sourcetype veya source seçicisi bulunamadı.")
        return (), tuple(dict.fromkeys(warnings))

    indexes = values["index"] or [""]
    hosts = values["host"] or [""]
    sourcetypes = values["sourcetype"] or [""]
    sources = values["source"] or [""]
    combinations = len(indexes) * len(hosts) * len(sourcetypes) * len(sources)
    if combinations > MAX_DEPENDENCIES:
        warnings.append(f"Kaynak seçicileri {combinations} birleşim üretiyor; ilk {MAX_DEPENDENCIES} kontrol edilecek.")
    event_ids_by_type: dict[tuple[str, str], tuple[str, ...]] = {}
    selector_field = "sourcetype" if occurrences["sourcetype"] else "source"
    selector_occurrences = occurrences[selector_field]
    if len(selector_occurrences) == 1:
        event_ids_by_type[(selector_field, selector_occurrences[0][0])] = all_event_ids
    elif selector_occurrences:
        for position, (value, _start, end_pos) in enumerate(selector_occurrences):
            next_pos = selector_occurrences[position + 1][1] if position + 1 < len(selector_occurrences) else len(search)
            branch_ids = tuple(dict.fromkeys(
                match.group("value").strip("\"'") for match in EVENT.finditer(search[end_pos:next_pos])
            ))
            event_ids_by_type[(selector_field, value)] = branch_ids

    dependencies = []
    for index in indexes:
        for host in hosts:
            for sourcetype in sourcetypes:
                for source in sources:
                    event_ids = event_ids_by_type.get(
                        ("sourcetype", sourcetype) if sourcetype else ("source", source), all_event_ids
                    )
                    dependencies.append(AlertDependency(index, host, sourcetype, source, event_ids))
                    if len(dependencies) == MAX_DEPENDENCIES:
                        return tuple(dependencies), tuple(dict.fromkeys(warnings))
    return tuple(dependencies), tuple(dict.fromkeys(warnings))


def parse_alerts(payload: dict, owner: str | None = None) -> list[AlertDefinition]:
    """Yalnız etkin, zamanlanmış alertleri ve istenirse belirtilen sahibi döndürür."""
    entries = payload.get("entry")
    if not isinstance(entries, list):
        raise CheckError("Splunk saved search yanıtı geçersiz.")
    alerts = []
    for position, entry in enumerate(entries, 1):
        try:
            if not isinstance(entry, dict) or not isinstance(entry.get("content"), dict):
                raise ValueError("kayıt yapısı geçersiz.")
            content = entry["content"]
            if _bool(content.get("disabled", False), "disabled"):
                continue
            if not _bool(content.get("is_scheduled", True), "is_scheduled"):
                continue
            alert_type = _text(str(content.get("alert_type", "")), "alert_type", 128, True)
            if not alert_type or alert_type.lower() == "none":
                continue
            name = _text(entry.get("name", ""), "Alert adı", 512)
            search = _text(content.get("search", ""), "Alert SPL")
            acl = entry.get("acl") if isinstance(entry.get("acl"), dict) else {}
            app = _text(str(acl.get("app", "unknown")), "Uygulama", 256)
            alert_owner = _text(str(acl.get("owner", "unknown")), "Sahip", 256)
            if owner is not None and alert_owner.casefold() != owner.casefold():
                continue
            dependencies, warnings = extract_dependencies(search)
            alerts.append(AlertDefinition(
                f"{alert_owner}/{app}/{name}", name, app, alert_owner, search, alert_type,
                _text(str(content.get("cron_schedule", "")), "Cron", 256, True),
                _text(str(content.get("dispatch.earliest_time", "")), "Earliest", 256, True),
                _text(str(content.get("dispatch.latest_time", "")), "Latest", 256, True),
                dependencies, warnings,
            ))
        except (TypeError, ValueError) as exc:
            raise CheckError(f"Splunk alert kaydı {position} geçersiz: {exc}") from None
    if len(alerts) > MAX_ALERTS:
        raise CheckError(f"{len(alerts)} etkin alert bulundu; güvenli sınır {MAX_ALERTS}. Splunk tarafında kapsamı daraltın.")
    return alerts


def build_dependency_search(dependency: AlertDependency, now: datetime, window_minutes: int) -> str:
    now = as_utc(now)
    end = int(now.timestamp())
    start = end - window_minutes * 60
    if not 0 < start < end < MAX_EPOCH:
        raise CheckError("Alert kapsam kontrolü zaman sınırları geçersiz.")
    index = spl_string(dependency.index, "index") if dependency.index else "*"
    search = f"search index={index} earliest=0 latest=+10y _index_earliest={start} _index_latest={end}"
    clauses = []
    for field in ("host", "sourcetype", "source"):
        value = getattr(dependency, field)
        if value:
            clauses.append(f"{field}={spl_string(value, field)}")
    if clauses:
        search += " | where " + " AND ".join(clauses)
    search += f" | eval arrival_epoch=_indextime | where arrival_epoch>={start} AND arrival_epoch<{end}"
    if dependency.event_ids:
        choices = " OR ".join(
            f"tostring(coalesce(EventCode,EventID,xml_event_id))={spl_string(value, 'event_id')}"
            for value in dependency.event_ids
        )
        search += ' | rex field=_raw "<EventID>(?<xml_event_id>[0-9]+)</EventID>" | where ' + choices
    search += " | stats count AS event_count max(arrival_epoch) AS last_seen_epoch"
    return search


def _count(row: dict) -> int:
    try:
        value = float(row["event_count"])
        if not math.isfinite(value) or value < 0 or not value.is_integer():
            raise ValueError
        return int(value)
    except (KeyError, TypeError, ValueError):
        raise CheckError("Alert bağımlılığı olay sayısı geçersiz.") from None


def check_dependency(client, dependency: AlertDependency, now: datetime, window_minutes: int) -> DependencyResult:
    search = build_dependency_search(dependency, now, window_minutes)
    try:
        payload = client.run_search(search)
        rows = payload.get("results")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise CheckError("Alert bağımlılığı araması tek sonuç satırı üretmedi.")
        count = _count(rows[0])
        if count == 0:
            return DependencyResult(dependency, "NO_DATA", 0, "", "Kontrol aralığında eşleşen log görülmedi.", search)
        try:
            epoch = float(rows[0]["last_seen_epoch"])
            if not math.isfinite(epoch) or not 0 < epoch < now.timestamp():
                raise ValueError
            last_seen = stamp(datetime.fromtimestamp(epoch, timezone.utc))
        except (KeyError, TypeError, ValueError, OSError, OverflowError):
            raise CheckError("Alert bağımlılığı son geliş zamanı geçersiz.") from None
        return DependencyResult(dependency, "OK", count, last_seen, f"{count} eşleşen olay bulundu.", search)
    except CheckError as exc:
        return DependencyResult(dependency, "ERROR", None, "", str(exc), search)


def analyze_alerts(client, alerts: list[AlertDefinition], now: datetime, window_minutes: int,
                   progress: Callable[[int], None] | None = None,
                   cancel: Callable[[], bool] | None = None) -> list[AlertResult]:
    results = []
    checked_at = stamp(now)
    completed = 0
    unique = {dependency for alert in alerts for dependency in alert.dependencies}
    if len(unique) > MAX_UNIQUE_DEPENDENCIES:
        raise CheckError(f"Alertler {len(unique)} benzersiz log bağımlılığı üretiyor; güvenli sınır {MAX_UNIQUE_DEPENDENCIES}.")
    cache: dict[AlertDependency, DependencyResult] = {}
    for alert in alerts:
        dependency_results = []
        for dependency in alert.dependencies:
            if cancel and cancel():
                return results
            if dependency not in cache:
                cache[dependency] = check_dependency(client, dependency, now, window_minutes)
                completed += 1
                if progress:
                    progress(completed)
            dependency_results.append(cache[dependency])
        states = {item.status for item in dependency_results}
        if not dependency_results:
            status = "UNKNOWN"
            details = "SPL içinden kontrol edilebilir açık log kaynağı çıkarılamadı."
        elif states == {"OK"} and not alert.warnings:
            status, details = "COVERED", "Alertin açık log bağımlılıklarının tamamında veri görüldü."
        elif "OK" in states:
            status, details = "DEGRADED", "Alertin bazı log bağımlılıkları sağlıklı, bazıları eksik veya doğrulanamadı."
        elif states == {"NO_DATA"}:
            status, details = "BLIND", "Alertin açık log bağımlılıklarında kontrol aralığında veri görülmedi."
        elif "ERROR" in states:
            status, details = "ERROR", "Bir veya daha fazla bağımlılık sorgusu tamamlanamadı."
        else:
            status, details = "UNKNOWN", "Alert kapsamı kesin olarak değerlendirilemedi."
        if alert.warnings:
            details += " " + " ".join(alert.warnings)
        results.append(AlertResult(alert, status, details, tuple(dependency_results), checked_at))
    return results


def alert_dict(result: AlertResult) -> dict:
    return {
        "key": result.alert.key, "name": result.alert.name, "app": result.alert.app,
        "owner": result.alert.owner, "alert_type": result.alert.alert_type,
        "cron": result.alert.cron, "earliest": result.alert.earliest, "latest": result.alert.latest,
        "status": result.status, "details": result.details, "checked_at_utc": result.checked_at_utc,
        "spl": result.alert.search, "warnings": list(result.alert.warnings),
        "dependencies": [dict(asdict(item), dependency=asdict(item.dependency), label=item.dependency.label)
                         for item in result.dependencies],
    }


def csv_bytes(results: list[AlertResult]) -> bytes:
    fields = ["alert", "app", "owner", "status", "dependency", "dependency_status",
              "event_count", "last_seen_utc", "details", "checked_at_utc"]
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for result in results:
        rows = result.dependencies or (DependencyResult(AlertDependency(), "UNKNOWN", None, "", result.details, ""),)
        for item in rows:
            values = {
                "alert": result.alert.name, "app": result.alert.app, "owner": result.alert.owner,
                "status": result.status, "dependency": item.dependency.label,
                "dependency_status": item.status, "event_count": "" if item.event_count is None else item.event_count,
                "last_seen_utc": item.last_seen_utc, "details": item.details,
                "checked_at_utc": result.checked_at_utc,
            }
            writer.writerow({key: "'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@")) else value
                             for key, value in values.items()})
    return handle.getvalue().encode("utf-8-sig")
