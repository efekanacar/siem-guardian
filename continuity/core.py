"""Hedef doğrulaması, UTC ölçümü ve raporlama; ağ bağımlılığı içermez."""

import csv
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, TextIO


TARGET_FIELDS = ["name", "index", "host", "sourcetype", "max_delay_minutes"]
REPORT_FIELDS = [
    "name", "index", "host", "sourcetype", "last_seen_utc",
    "delay_minutes", "threshold_minutes", "status",
]


class CheckError(Exception):
    """Yalnız güvenli, kimlik bilgisi içermeyen hata mesajları taşır."""


def positive_number(value: str, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field}: pozitif sayı gerekli.") from None
    if not math.isfinite(number) or not 0 < number <= 525600:
        raise ValueError(f"{field}: 0 ile 525600 arasında sonlu sayı gerekli.")
    return number


def validate_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"{field}: 1–256 karakter gerekli.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field}: kontrol karakteri kullanılamaz.")
    if field != "name" and any(char in value for char in "*?"):
        raise ValueError(f"{field}: wildcard desteklenmiyor.")
    if field != "name" and "`" in value:
        raise ValueError(f"{field}: SPL makro karakteri kullanılamaz.")
    if field == "index" and not re.fullmatch(r"[a-z0-9_][a-z0-9_-]*", value):
        raise ValueError("index: küçük harf, rakam, alt çizgi ve tire kullanılabilir.")
    return value


@dataclass(frozen=True)
class Target:
    name: str
    index: str
    host: str
    sourcetype: str
    max_delay_minutes: float

    def __post_init__(self) -> None:
        for field in TARGET_FIELDS[:-1]:
            validate_text(getattr(self, field), field)
        positive_number(str(self.max_delay_minutes), "max_delay_minutes")


def load_targets(path: Path, window_minutes: int) -> list[Target]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return read_targets(handle, window_minutes)


def read_targets(handle: TextIO, window_minutes: int) -> list[Target]:
    """Dosya veya arayüzden yüklenen CSV için ortak okuyucu."""
    targets = []
    names = set()
    reader = csv.DictReader(handle)
    if reader.fieldnames != TARGET_FIELDS:
        raise ValueError("CSV başlığı sırasıyla " + ",".join(TARGET_FIELDS) + " olmalı.")
    for line, row in enumerate(reader, 2):
        try:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("Eksik veya fazla sütun.")
            values = {key: value.strip() for key, value in row.items()}
            target = Target(
                **{key: values[key] for key in TARGET_FIELDS[:-1]},
                max_delay_minutes=positive_number(values["max_delay_minutes"], "max_delay_minutes"),
            )
            if target.name in names:
                raise ValueError("name benzersiz olmalı.")
            if window_minutes <= target.max_delay_minutes:
                raise ValueError("Kontrol aralığı her hedefin eşiğinden kesinlikle uzun olmalı.")
            targets.append(target)
            names.add(target.name)
        except ValueError as exc:
            raise ValueError(f"CSV satırı {line}: {exc}") from None
    if not targets:
        raise ValueError("CSV en az bir hedef içermeli.")
    return targets


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timezone-aware datetime gerekli.")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class NoData:
    note: str


@dataclass(frozen=True)
class Report:
    target: Target
    last_seen: datetime | None
    delay_minutes: float | None
    status: str
    error: str = ""
    note: str = ""

    def row(self) -> dict[str, str]:
        return {
            "name": self.target.name,
            "index": self.target.index,
            "host": self.target.host,
            "sourcetype": self.target.sourcetype,
            "last_seen_utc": as_utc(self.last_seen).isoformat().replace("+00:00", "Z") if self.last_seen else "",
            "delay_minutes": f"{self.delay_minutes:.6f}" if self.delay_minutes is not None else "",
            "threshold_minutes": f"{self.target.max_delay_minutes:g}",
            "status": self.status,
        }


def evaluate(target: Target, last_seen: datetime | NoData | None, now: datetime, start: datetime) -> Report:
    now, start = as_utc(now), as_utc(start)
    if isinstance(last_seen, NoData):
        return Report(target, None, None, "NO_DATA", note=last_seen.note)
    if last_seen is None:
        return Report(target, None, None, "NO_DATA")
    last_seen = as_utc(last_seen)
    if not start <= last_seen < now:
        raise CheckError("Son indekslenme zamanı kontrol aralığının dışında.")
    delay = (now - last_seen).total_seconds() / 60
    status = "OK" if delay <= target.max_delay_minutes else "DELAYED"
    return Report(target, last_seen, delay, status)


def check_targets(
    targets: list[Target], fetch: Callable[[Target, datetime, datetime], datetime | NoData | None],
    now: datetime, window_minutes: int,
) -> list[Report]:
    now = as_utc(now)
    start = now - timedelta(minutes=window_minutes)
    reports = []
    # Beklenen listeyi temel al: sonuçta hiç görünmeyen hedefler de raporlanır.
    for target in targets:
        try:
            reports.append(evaluate(target, fetch(target, start, now), now, start))
        except CheckError as exc:
            reports.append(Report(target, None, None, "ERROR", str(exc)))
        except Exception:
            # Ham istisnalar HTTP header/URL/parola içerebilir; asla yazdırma.
            reports.append(Report(target, None, None, "ERROR", "Beklenmeyen veri işleme hatası."))
    return reports


def table(reports: list[Report]) -> str:
    rows = [report.row() for report in reports]
    widths = {field: max(len(field), *(len(row[field]) for row in rows)) for field in REPORT_FIELDS}
    def format_row(row):
        return " | ".join(row[field].ljust(widths[field]) for field in REPORT_FIELDS)
    return "\n".join([
        format_row({field: field for field in REPORT_FIELDS}),
        "-+-".join("-" * widths[field] for field in REPORT_FIELDS),
        *(format_row(row) for row in rows),
    ])


def write_csv(path: Path, reports: list[Report]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(report.row() for report in reports)
