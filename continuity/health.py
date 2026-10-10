"""Beklenen SIEM kapsamasını Splunk'ın tamamlanmış arama sonuçlarıyla ölçer."""

import csv
import io
import json
import math
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from .core import CheckError, as_utc, validate_text
from .splunk import MAX_EPOCH, SplunkClient, spl_string, stamp
from .dependencies import Detection, parse_detections


KINDS = ("presence", "event_id", "field", "timestamp", "volume", "route")
STATUSES = ("OK", "ALERT", "NO_DATA", "QUIET", "INSUFFICIENT_BASELINE", "ERROR")
RESULT_FIELDS = (
    "name", "check_type", "index", "host", "sourcetype", "source", "status",
    "observed", "threshold", "details", "checked_at_utc",
)
COMMON = {"name", "kind", "index", "host", "sourcetype", "source", "window_minutes", "availability", "activity_check"}
OPTIONAL_COMMON = {"source", "availability", "activity_check"}
EXTRA = {
    "presence": {"min_events"},
    "event_id": {"event_id_field", "event_id", "min_events"},
    "field": {"field", "min_present_percent", "min_events"},
    "timestamp": {"max_age_minutes", "max_future_minutes", "max_bad_percent", "min_events", "timestamp_source", "max_parse_diff_seconds"},
    "volume": {"drop_percent", "min_baseline_events"},
    "route": {"min_events"},
}
FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def finite_number(value, label: str, lower: float, upper: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label}: sayı gerekli.")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label}: sayı gerekli.") from None
    if not math.isfinite(number) or not lower <= number <= upper:
        raise ValueError(f"{label}: {lower:g}–{upper:g} aralığında olmalı.")
    return number


def integer(value, label: str, lower: int, upper: int) -> int:
    number = finite_number(value, label, lower, upper)
    if not number.is_integer():
        raise ValueError(f"{label}: tam sayı gerekli.")
    return int(number)


def field_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not FIELD_NAME.fullmatch(value):
        raise ValueError(f"{label}: yalnız harf, rakam ve alt çizgi içeren alan adı gerekli.")
    return value


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str
    index: str
    host: str
    sourcetype: str
    window_minutes: int
    source: str = ""
    availability: str = "continuous"
    activity_check: str = ""
    min_events: int = 1
    event_id_field: str = ""
    event_id: str = ""
    field: str = ""
    min_present_percent: float = 95.0
    max_age_minutes: float = 60.0
    max_future_minutes: float = 5.0
    max_bad_percent: float = 5.0
    timestamp_source: str = "index_gap"
    max_parse_diff_seconds: float = 60.0
    drop_percent: float = 80.0
    min_baseline_events: int = 20

    def __post_init__(self) -> None:
        validate_text(self.name, "name")
        if self.kind not in KINDS:
            raise ValueError("Bilinmeyen kontrol türü.")
        for label in ("index", "host", "sourcetype"):
            validate_text(getattr(self, label), label)
        if self.source:
            validate_text(self.source, "source")
        if self.availability not in {"continuous", "intermittent"}:
            raise ValueError("availability: continuous veya intermittent gerekli.")
        if self.activity_check:
            validate_text(self.activity_check, "activity_check")
            if self.availability != "intermittent":
                raise ValueError("activity_check yalnız intermittent kaynakta kullanılabilir.")
        integer(self.window_minutes, "window_minutes", 1, 10080)
        integer(self.min_events, "min_events", 1, 1000000000)
        integer(self.min_baseline_events, "min_baseline_events", 1, 1000000000)
        for label in ("min_present_percent", "max_bad_percent", "drop_percent"):
            finite_number(getattr(self, label), label, 0, 100)
        for label in ("max_age_minutes", "max_future_minutes"):
            finite_number(getattr(self, label), label, 0, 525600)
        finite_number(self.max_parse_diff_seconds, "max_parse_diff_seconds", 0, 86400)
        if self.timestamp_source not in {"index_gap", "apache_combined"}:
            raise ValueError("timestamp_source: index_gap veya apache_combined gerekli.")
        if self.kind == "event_id":
            if self.event_id_field != "auto":
                field_name(self.event_id_field, "event_id_field")
            validate_text(self.event_id, "event_id")
        if self.kind == "field":
            field_name(self.field, "field")


def parse_rules(value) -> list[Rule]:
    if not isinstance(value, dict) or "checks" not in value or set(value) - {"checks", "detections"} or not isinstance(value["checks"], list):
        raise ValueError("JSON biçimi: checks listesi ve isteğe bağlı detections gerekli.")
    rows = value["checks"]
    if not 1 <= len(rows) <= 50:
        raise ValueError("1–50 sağlık kontrolü gerekli.")
    rules, names = [], set()
    for position, item in enumerate(rows, 1):
        try:
            if not isinstance(item, dict) or not COMMON.difference(OPTIONAL_COMMON) <= set(item):
                raise ValueError("Zorunlu alanlar eksik.")
            kind = item["kind"]
            if kind not in KINDS:
                raise ValueError("Bilinmeyen kontrol türü.")
            if set(item) - COMMON - EXTRA[kind]:
                raise ValueError("Bu kontrol türüne ait olmayan alan var.")
            if kind == "event_id" and not {"event_id_field", "event_id"} <= set(item):
                raise ValueError("Event ID alanı ve değeri gerekli.")
            if kind == "field" and "field" not in item:
                raise ValueError("İzlenecek alan gerekli.")
            options = dict(item)
            options["window_minutes"] = integer(item["window_minutes"], "window_minutes", 1, 10080)
            for label in ("min_events", "min_baseline_events"):
                if label in options:
                    options[label] = integer(options[label], label, 1, 1000000000)
            for label in ("min_present_percent", "max_age_minutes", "max_future_minutes", "max_bad_percent", "drop_percent", "max_parse_diff_seconds"):
                if label in options:
                    upper = 525600 if "minutes" in label else 86400 if label == "max_parse_diff_seconds" else 100
                    options[label] = finite_number(options[label], label, 0, upper)
            rule = Rule(**options)
            if rule.name in names:
                raise ValueError("Kontrol adları benzersiz olmalı.")
            names.add(rule.name)
            rules.append(rule)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Kontrol {position}: {exc}") from None
    by_name = {rule.name: rule for rule in rules}
    for rule in rules:
        if rule.activity_check:
            reference = by_name.get(rule.activity_check)
            if reference is None or reference.name == rule.name or reference.host != rule.host:
                raise ValueError(f"{rule.name}: activity_check aynı hostta başka bir kontrole işaret etmeli.")
    return rules


def read_rules(text: str) -> list[Rule]:
    try:
        value = json.loads(text.lstrip("\ufeff"))
    except (ValueError, TypeError):
        raise ValueError("Geçerli UTF-8 JSON gerekli.") from None
    return parse_rules(value)


def load_rules(path: Path) -> list[Rule]:
    return read_rules(path.read_text(encoding="utf-8-sig"))


def read_config(text: str) -> tuple[list[Rule], list[Detection]]:
    try:
        value = json.loads(text.lstrip("\ufeff"))
    except (ValueError, TypeError):
        raise ValueError("Geçerli UTF-8 JSON gerekli.") from None
    rules = parse_rules(value)
    detections = parse_detections(value.get("detections", []), {rule.name for rule in rules})
    return rules, detections


def read_csv_rules(text: str) -> list[Rule]:
    try:
        reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff"), newline=""))
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("CSV başlıkları geçersiz veya yinelenmiş.")
        allowed = COMMON | set().union(*EXTRA.values())
        if set(reader.fieldnames) - allowed or not COMMON.difference(OPTIONAL_COMMON) <= set(reader.fieldnames):
            raise ValueError("CSV kontrol sütunları eksik veya geçersiz.")
        rows = []
        for row in reader:
            if None in row:
                raise ValueError("CSV satırında fazla sütun var.")
            rows.append({key: value for key, value in row.items() if value is not None and value.strip()})
    except csv.Error:
        raise ValueError("CSV dosyası okunamadı.") from None
    return parse_rules({"checks": rows})


def load_config(path: Path) -> tuple[list[Rule], list[Detection]]:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".csv":
        return read_csv_rules(text), []
    if path.suffix.lower() == ".json":
        return read_config(text)
    raise ValueError("Kontrol dosyası .json veya .csv olmalı.")


def rule_dict(rule: Rule) -> dict:
    """Yeniden içe aktarılabilir, türüne özgü JSON satırı."""
    values = asdict(rule)
    return {key: value for key, value in values.items() if key in COMMON | EXTRA[rule.kind] and (key not in {"source", "activity_check"} or value)}


def build_search(rule: Rule, now: datetime) -> str:
    now = as_utc(now)
    end = int(now.timestamp())
    start = end - rule.window_minutes * 60
    index_start = start - rule.window_minutes * 60 if rule.kind == "volume" else start
    if not 0 < index_start < end < MAX_EPOCH:
        raise CheckError("Sağlık kontrolünün zaman sınırları geçersiz.")
    # Event-time geçmişten 10 yıl ileriye: Splunk 12 haneli epoch latest değerini
    # reddeder; +10y bu ortamda canlı Search ile doğrulandı.
    # _index_* aramayı daraltır; where kesin [başlangıç, bitiş) sınırını uygular.
    index = "*" if rule.kind == "route" else spl_string(rule.index, "index")
    search = (
        f"search index={index} earliest=0 latest=+10y "
        f"_index_earliest={index_start} _index_latest={end} "
        f"| where host={spl_string(rule.host, 'host')} "
        f"AND sourcetype={spl_string(rule.sourcetype, 'sourcetype')}"
    )
    if rule.source:
        search += f" AND source={spl_string(rule.source, 'source')}"
    search += f" | eval arrival_epoch=_indextime | where arrival_epoch>={index_start} AND arrival_epoch<{end}"
    if rule.kind == "event_id":
        event_field = rule.event_id_field
        if event_field == "auto":
            search += ' | rex field=_raw "<EventID>(?<xml_event_id>[0-9]+)</EventID>"'
            event_field = "coalesce(EventCode,EventID,xml_event_id)"
        search += (
            f" | stats count AS total_count "
            f"sum(eval(if(tostring({event_field})={spl_string(rule.event_id, 'event_id')},1,0))) AS matching_count "
            "| eval matching_count=coalesce(matching_count,0)"
        )
    elif rule.kind == "field":
        search += (
            f" | stats count AS total_count "
            f"sum(eval(if(isnotnull({rule.field}) AND len(trim(tostring({rule.field})))>0,1,0))) AS present_count "
            "| eval present_count=coalesce(present_count,0)"
        )
    elif rule.kind == "timestamp":
        if rule.timestamp_source == "apache_combined":
            search += (
                ' | rex field=_raw "\\[(?<raw_event_time>[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:'
                '[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4})\\]"'
                ' | eval parsed_event_epoch=strptime(raw_event_time,"%d/%b/%Y:%H:%M:%S %z")'
                ' | stats count AS total_count '
                f'sum(eval(if(isnull(_time) OR isnull(parsed_event_epoch) OR abs(_time-parsed_event_epoch)>{rule.max_parse_diff_seconds:g},1,0))) AS bad_count '
                '| eval bad_count=coalesce(bad_count,0)'
            )
        else:
            age = rule.max_age_minutes * 60
            future = rule.max_future_minutes * 60
            search += (
                f" | stats count AS total_count "
                f"sum(eval(if(isnull(_time) OR _time < arrival_epoch-{age:g} "
                f"OR _time > arrival_epoch+{future:g},1,0))) AS bad_count "
                "| eval bad_count=coalesce(bad_count,0)"
            )
    elif rule.kind == "volume":
        search += (
            f" | stats count AS total_count "
            f"sum(eval(if(arrival_epoch>={start},1,0))) AS current_count "
            f"sum(eval(if(arrival_epoch<{start},1,0))) AS baseline_count "
            "| eval current_count=coalesce(current_count,0), baseline_count=coalesce(baseline_count,0)"
        )
    elif rule.kind == "route":
        search += (
            f" | stats count AS total_count "
            f"sum(eval(if(index={spl_string(rule.index, 'index')},1,0))) AS expected_count "
            "values(index) AS observed_indexes "
            "| eval expected_count=coalesce(expected_count,0)"
        )
    else:
        search += " | stats count AS total_count max(arrival_epoch) AS last_seen_epoch"
    return search


def count(row: dict, label: str) -> int:
    try:
        raw = row[label]
        if isinstance(raw, bool):
            raise ValueError
        value = float(raw)
        if not math.isfinite(value) or not value.is_integer() or value < 0:
            raise ValueError
        return int(value)
    except (KeyError, TypeError, ValueError):
        raise CheckError(f"Splunk {label} sayacı geçersiz.") from None


@dataclass(frozen=True)
class Result:
    rule: Rule
    status: str
    observed: str
    threshold: str
    details: str
    checked_at: datetime
    search: str = ""
    job: dict | None = None

    def row(self) -> dict[str, str]:
        return {
            "name": self.rule.name, "check_type": self.rule.kind,
            "index": self.rule.index, "host": self.rule.host,
            "sourcetype": self.rule.sourcetype, "source": self.rule.source,
            "status": self.status, "observed": self.observed,
            "threshold": self.threshold, "details": self.details,
            "checked_at_utc": stamp(self.checked_at),
        }


def evaluate(rule: Rule, row: dict, now: datetime, search: str = "", job: dict | None = None) -> Result:
    now = as_utc(now)
    if not isinstance(row, dict):
        raise CheckError("Splunk sağlık kontrolü sonucu geçersiz.")
    total = count(row, "total_count")
    status, observed, threshold, details = "OK", str(total), "", ""
    quiet = rule.availability == "intermittent"
    no_events = "Aralıklı kaynakta bu aralıkta olay yok; sistem kapalı olabilir, akış doğrulanamadı."
    if rule.kind == "presence":
        threshold = f"en az {rule.min_events} olay"
        if total == 0:
            status, details = ("QUIET", no_events) if quiet else ("NO_DATA", "Beklenen kaynakta kontrol aralığında olay görünmedi.")
        elif total < rule.min_events:
            status, details = "ALERT", "Olay sayısı beklenen asgari düzeyin altında."
        else:
            details = "Beklenen kaynakta veri var."
        if total:
            try:
                last = float(row["last_seen_epoch"])
                start = now - timedelta(minutes=rule.window_minutes)
                if not math.isfinite(last) or not start.timestamp() <= last < now.timestamp():
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise CheckError("Son indekslenme zamanı geçersiz.") from None
            details += " Son geliş: " + stamp(datetime.fromtimestamp(last, now.tzinfo)) + "."
    elif rule.kind in {"event_id", "field", "timestamp"}:
        label = {"event_id": "matching_count", "field": "present_count", "timestamp": "bad_count"}[rule.kind]
        value = count(row, label)
        if value > total:
            raise CheckError("Splunk sağlık kontrolü sayaçları tutarsız.")
        if total == 0:
            status, details = ("QUIET", no_events) if quiet else ("NO_DATA", "Kaynakta bu aralıkta olay yok; kapsam değerlendirilemedi.")
        elif rule.kind == "event_id":
            observed, threshold = str(value), f"en az {rule.min_events} Event ID {rule.event_id}"
            status = "OK" if value >= rule.min_events else "ALERT"
            details = f"{total} olayın {value} tanesi Event ID {rule.event_id}."
        elif total < rule.min_events:
            status, details = "INSUFFICIENT_BASELINE", f"Yalnız {total} olay var; en az {rule.min_events} gerekli."
        elif rule.kind == "field":
            percent = value / total * 100
            observed, threshold = f"%{percent:.2f}", f"en az %{rule.min_present_percent:g}"
            status = "OK" if percent >= rule.min_present_percent else "ALERT"
            details = f"{total} olayın {value} tanesinde {rule.field} dolu."
        else:
            percent = value / total * 100
            observed, threshold = f"%{percent:.2f}", f"en fazla %{rule.max_bad_percent:g}"
            status = "OK" if percent <= rule.max_bad_percent else "ALERT"
            if rule.timestamp_source == "apache_combined":
                details = f"{total} olayın {value} tanesinde Apache ham zamanı ayrıştırılamadı veya _time ile {rule.max_parse_diff_seconds:g} saniyeden fazla farklı."
            else:
                details = f"{total} olayın {value} tanesinde olay zamanı/indekslenme zamanı sapması var."
    elif rule.kind == "volume":
        current, baseline = count(row, "current_count"), count(row, "baseline_count")
        if current + baseline != total:
            raise CheckError("Splunk hacim sayaçları tutarsız.")
        observed = f"şimdi {current} / önceki {baseline}"
        threshold = f"en fazla %{rule.drop_percent:g} düşüş"
        if quiet and current == 0:
            status, details = "QUIET", no_events
        elif total == 0:
            status, details = "NO_DATA", "Karşılaştırılan iki aralıkta da olay görünmedi."
        elif baseline < rule.min_baseline_events:
            status = "INSUFFICIENT_BASELINE"
            details = f"Önceki aralıkta {baseline} olay var; en az {rule.min_baseline_events} gerekli."
        else:
            drop = max(0.0, (baseline - current) / baseline * 100)
            status = "ALERT" if drop >= rule.drop_percent else "OK"
            details = f"Önceki eşit aralığa göre %{drop:.2f} düşüş."
    else:
        expected = count(row, "expected_count")
        if expected > total:
            raise CheckError("Splunk yönlendirme sayaçları tutarsız.")
        indexes = row.get("observed_indexes", [])
        if isinstance(indexes, str):
            indexes = [indexes]
        if not isinstance(indexes, list) or any(not isinstance(x, str) or not x or len(x) > 256 for x in indexes):
            raise CheckError("Splunk görülen index listesi geçersiz.")
        if (total == 0 and indexes) or (total > 0 and (not indexes or rule.index not in indexes and expected > 0)):
            raise CheckError("Splunk yönlendirme sonucu tutarsız.")
        observed, threshold = f"beklenen {expected} / toplam {total}", f"en az {rule.min_events}; başka index 0"
        if total == 0:
            status, details = ("QUIET", no_events) if quiet else ("NO_DATA", "Bu host/sourcetype için erişilebilir indexlerde olay görünmedi.")
        elif expected < rule.min_events or expected < total:
            status = "ALERT"
            details = "Beklenen index dışında veri görüldü: " + ", ".join(sorted(set(indexes))) + "." if expected < total else "Beklenen indexte olay sayısı yetersiz."
        else:
            details = "Görülen olaylar beklenen indexte."
    return Result(rule, status, observed, threshold, details, now, search, job)


def run_checks(client: SplunkClient, rules: list[Rule], now: datetime, progress: Callable[[int], None] | None = None,
               cancel: Callable[[], bool] | None = None) -> list[Result]:
    now = as_utc(now)
    results = []
    for position, rule in enumerate(rules, 1):
        if cancel and cancel():
            break
        search = ""
        try:
            search = build_search(rule, now)
            payload = client.run_search(search)
            rows = payload.get("results")
            if not isinstance(rows, list) or len(rows) != 1:
                raise CheckError("Sağlık kontrolü tek sonuç satırı üretmedi; veri yok sayılmadı.")
            result = evaluate(rule, rows[0], now, search, dict(client.last_job))
        except CheckError as exc:
            result = Result(rule, "ERROR", "", "", str(exc), now, search, dict(client.last_job))
        except Exception:
            result = Result(rule, "ERROR", "", "", "Beklenmeyen veri işleme hatası.", now, search)
        results.append(result)
        if progress:
            progress(position)
    by_name = {result.rule.name: result for result in results}
    for position, result in enumerate(results):
        reference = by_name.get(result.rule.activity_check)
        if result.status == "QUIET" and reference and reference.status == "OK":
            results[position] = replace(
                result, status="ALERT",
                details=f"Bu kaynak sessizken aynı hostun '{reference.rule.name}' kontrolü OK; beklenen akış eksik olabilir.",
            )
    return results


def csv_bytes(results: list[Result]) -> bytes:
    def cell(value: str) -> str:
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value

    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS)
    writer.writeheader()
    writer.writerows({key: cell(value) for key, value in result.row().items()} for result in results)
    return handle.getvalue().encode("utf-8-sig")
