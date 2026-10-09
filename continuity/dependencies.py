"""Detection kurallarının beklenen log kontrollerine bağımlılığını değerlendirir."""

import csv
import io
from dataclasses import dataclass

from .core import validate_text


@dataclass(frozen=True)
class Detection:
    name: str
    technique: str
    mode: str
    checks: tuple[str, ...]
    impact: str


def parse_detections(value, check_names: set[str]) -> list[Detection]:
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError("detections: en fazla 50 kayıtlık liste gerekli.")
    detections, names = [], set()
    for position, row in enumerate(value, 1):
        try:
            if not isinstance(row, dict) or set(row) != {"name", "technique", "mode", "checks", "impact"}:
                raise ValueError("name, technique, mode, checks, impact gerekli.")
            name = validate_text(row["name"], "name")
            technique = validate_text(row["technique"], "name")
            impact = validate_text(row["impact"], "name")
            mode = row["mode"]
            if mode not in {"any", "all"}:
                raise ValueError("mode: any veya all gerekli.")
            raw = row["checks"]
            if not isinstance(raw, list) or not 1 <= len(raw) <= 20 or len(set(raw)) != len(raw):
                raise ValueError("checks: 1–20 benzersiz kontrol adı gerekli.")
            if any(not isinstance(check, str) or check not in check_names for check in raw):
                raise ValueError("checks: tanımlı sağlık kontrollerine başvurmalı.")
            if name in names:
                raise ValueError("Detection adları benzersiz olmalı.")
            names.add(name)
            detections.append(Detection(name, technique, mode, tuple(raw), impact))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Detection {position}: {exc}") from None
    return detections


def detection_dict(value: Detection) -> dict:
    return {"name": value.name, "technique": value.technique, "mode": value.mode,
            "checks": list(value.checks), "impact": value.impact}


def evaluate_detections(detections: list[Detection], results) -> list[dict]:
    statuses = {result.rule.name: result.status for result in results}
    output = []
    for detection in detections:
        evidence = {name: statuses.get(name, "PENDING") for name in detection.checks}
        values = set(evidence.values())
        if "PENDING" in values:
            status = "PENDING"
        elif detection.mode == "any":
            status = "COVERED" if "OK" in values else "IMPAIRED" if values <= {"ALERT", "NO_DATA"} else "UNKNOWN"
        else:
            status = "IMPAIRED" if values & {"ALERT", "NO_DATA"} else "COVERED" if values == {"OK"} else "UNKNOWN"
        output.append({"name": detection.name, "technique": detection.technique,
                       "mode": detection.mode, "status": status,
                       "impact": detection.impact if status == "IMPAIRED" else "",
                       "evidence": evidence})
    return output


def csv_bytes(rows: list[dict]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=["name", "technique", "mode", "status", "impact", "evidence"])
    writer.writeheader()
    for row in rows:
        evidence = "; ".join(f"{name}: {status}" for name, status in row["evidence"].items())
        values = dict(row, evidence=evidence)
        writer.writerow({key: "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
                         for key, value in values.items()})
    return handle.getvalue().encode("utf-8-sig")
