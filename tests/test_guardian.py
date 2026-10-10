"""Envanter, detection bağımlılığı ve isteğe bağlı bildirim testleri."""

import json
import unittest
from dataclasses import replace
from unittest.mock import MagicMock, patch

from continuity.core import CheckError
from continuity.dependencies import evaluate_detections, parse_detections
from continuity.health import Rule, Result, read_config, read_csv_rules, run_checks
from continuity.notify import issue_payload, send_issues
from datetime import datetime, timezone


NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
SYSMON = Rule("Sysmon 1", "event_id", "example_windows", "win.example.invalid", "XmlWinEventLog:Sysmon", 60,
              event_id_field="auto", event_id="1")
POWERSHELL = replace(SYSMON, name="PowerShell 4104", sourcetype="XmlWinEventLog:PowerShell", event_id="4104")
SPEC = {"name": "PowerShell tespiti", "technique": "T1059.001", "mode": "any",
        "checks": [SYSMON.name, POWERSHELL.name], "impact": "PowerShell tespit kabiliyeti etkilenmiş olabilir."}


def result(rule, status):
    return Result(rule, status, "0", "1", "Örnek", NOW)


class GuardianTests(unittest.TestCase):
    def test_any_of_dependency_distinguishes_alternative_coverage(self):
        detection = parse_detections([SPEC], {SYSMON.name, POWERSHELL.name})
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "NO_DATA"), result(POWERSHELL, "OK")])[0]["status"], "COVERED")
        impaired = evaluate_detections(detection, [result(SYSMON, "NO_DATA"), result(POWERSHELL, "ALERT")])[0]
        self.assertEqual(impaired["status"], "IMPAIRED")
        self.assertIn("PowerShell tespit", impaired["impact"])
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "ERROR"), result(POWERSHELL, "NO_DATA")])[0]["status"], "UNKNOWN")
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "QUIET"), result(POWERSHELL, "QUIET")])[0]["status"], "UNKNOWN")
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "OK")])[0]["status"], "PENDING")

    def test_all_of_dependency_and_unknown(self):
        detection = parse_detections([dict(SPEC, mode="all")], {SYSMON.name, POWERSHELL.name})
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "OK"), result(POWERSHELL, "ALERT")])[0]["status"], "IMPAIRED")
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "OK"), result(POWERSHELL, "ERROR")])[0]["status"], "UNKNOWN")
        self.assertEqual(evaluate_detections(detection, [result(SYSMON, "OK"), result(POWERSHELL, "OK")])[0]["status"], "COVERED")

    def test_rejects_missing_reference(self):
        with self.assertRaises(ValueError):
            parse_detections([dict(SPEC, checks=["not-defined"])], {SYSMON.name, POWERSHELL.name})
        with self.assertRaises(ValueError):
            read_config(json.dumps({"checks": [dict(name="x", kind="presence", index="test", host="h", sourcetype="s", window_minutes=60)],
                                    "detections": [SPEC]}))

    def test_csv_inventory_and_json_detection_example(self):
        from pathlib import Path
        csv_rules = read_csv_rules(Path("checks.example.csv").read_text(encoding="utf-8"))
        self.assertEqual(len(csv_rules), 2)
        self.assertEqual(csv_rules[1].event_id_field, "auto")
        rules, detections = read_config(Path("checks.example.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rules), 8)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].mode, "any")
        self.assertEqual(csv_rules[0].availability, "intermittent")

    def test_quiet_source_becomes_alert_only_when_same_host_reference_is_active(self):
        reference = Rule("Windows Security", "presence", "example_windows", "win.example.invalid", "XmlWinEventLog:Security", 60,
                         availability="intermittent")
        missing = replace(SYSMON, availability="intermittent", activity_check=reference.name)
        spec = {"checks": [dict(name=reference.name, kind=reference.kind, index=reference.index, host=reference.host,
                                sourcetype=reference.sourcetype, window_minutes=60, availability="intermittent"),
                           dict(name=missing.name, kind=missing.kind, index=missing.index, host=missing.host,
                                sourcetype=missing.sourcetype, window_minutes=60, availability="intermittent",
                                activity_check=reference.name, event_id_field="auto", event_id="1")]}
        self.assertEqual(len(read_config(json.dumps(spec))[0]), 2)
        with self.assertRaises(ValueError):
            read_config(json.dumps({"checks": [dict(spec["checks"][0]), dict(spec["checks"][1], activity_check="nonexistent")]}))

        class Client:
            last_job = {}
            def __init__(self, rows): self.rows = iter(rows)
            def run_search(self, search): return {"results": [next(self.rows)]}

        active = run_checks(Client([{"total_count": 1, "last_seen_epoch": NOW.timestamp()-30},
                                    {"total_count": 0, "matching_count": 0}]), [reference, missing], NOW)
        self.assertEqual([item.status for item in active], ["OK", "ALERT"])
        self.assertIn("Windows Security", active[1].details)
        inactive = run_checks(Client([{"total_count": 0}, {"total_count": 0, "matching_count": 0}]), [reference, missing], NOW)
        self.assertEqual([item.status for item in inactive], ["QUIET", "QUIET"])

    def test_notification_is_opt_in_and_uses_only_problem_summary(self):
        payload = issue_payload([result(SYSMON, "NO_DATA"), result(POWERSHELL, "OK")], [])
        self.assertEqual(len(payload["health_issues"]), 1)
        quiet_payload = issue_payload([result(SYSMON, "QUIET"), result(POWERSHELL, "ERROR")],
                                      [{"name": "PowerShell", "technique": "T1059.001", "status": "UNKNOWN", "impact": "Belirsiz"}])
        self.assertEqual(quiet_payload["health_issues"], [])
        self.assertEqual(quiet_payload["detection_issues"], [])
        self.assertEqual(send_issues({"health_issues": [], "detection_issues": []}, {}), 0)
        response = MagicMock()
        with patch("continuity.notify.requests.post", return_value=response) as post:
            self.assertEqual(send_issues(payload, {"GUARDIAN_WEBHOOK_URL": "https://notify.example.invalid/hook"}), 1)
            self.assertEqual(post.call_args.kwargs["timeout"], 10)
            self.assertEqual(post.call_args.kwargs["json"], payload)
        with self.assertRaises(CheckError):
            send_issues(payload, {"GUARDIAN_WEBHOOK_URL": "http://notify.example.invalid/hook"})
        smtp = MagicMock()
        smtp.return_value.__enter__.return_value = smtp.return_value
        with patch("continuity.notify.smtplib.SMTP", smtp):
            self.assertEqual(send_issues(payload, {
                "GUARDIAN_SMTP_HOST": "mail.example.invalid", "GUARDIAN_SMTP_PORT": "587",
                "GUARDIAN_SMTP_USER": "user", "GUARDIAN_SMTP_PASSWORD": "secret",
                "GUARDIAN_EMAIL_FROM": "from@example.invalid", "GUARDIAN_EMAIL_TO": "to@example.invalid",
            }), 1)
        smtp.return_value.starttls.assert_called_once()
        smtp.return_value.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
