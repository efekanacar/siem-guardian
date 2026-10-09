"""Beklenen SIEM kapsamı, aralık sınırları ve hata ayrımı testleri."""

import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
from urllib.parse import parse_qs, urlsplit
import requests
from requests.adapters import BaseAdapter
from dataclasses import replace
from datetime import datetime, timezone

from continuity.core import CheckError
from continuity.config import Config
from continuity.health import Rule, build_search, csv_bytes, evaluate, read_rules, rule_dict, run_checks
from continuity.splunk import SplunkClient
import healthcheck


NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
BASE = Rule("Kaynak", "presence", "example_linux", "host.example.invalid", "linux_secure", 60)


class FakeClient:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.searches = []
        self.last_job = {}

    def run_search(self, search):
        self.searches.append(search)
        self.last_job = {"sid": f"job-{len(self.searches)}", "resultCount": 1}
        value = next(self.rows)
        if isinstance(value, Exception):
            raise value
        return {"results": value}


class HealthAdapter(BaseAdapter):
    """Gerçek requests/job/result akışına yanıt veren yerel transport."""
    def __init__(self):
        self.jobs = {}
        self.searches = []

    def send(self, request, **kwargs):
        path = urlsplit(request.url).path
        if request.method == "POST":
            form = parse_qs(request.body)
            search = form["search"][0]
            self.searches.append(search)
            results = ([{"server_now": str(NOW.timestamp())}] if "server_now=now()" in search
                       else [{"total_count": "25", "matching_count": "0"}])
            sid = f"health-{len(self.jobs)}"
            self.jobs[sid] = results
            payload = {"sid": sid}
        elif path.endswith("/results"):
            payload = {"results": self.jobs[path.split("/")[-2]], "preview": False}
        else:
            payload = {"entry": [{"content": {"isDone": True, "isFailed": False,
                        "isFinalized": False, "dispatchState": "DONE",
                        "resultCount": str(len(self.jobs[path.split('/')[-1]]))}}]}
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(payload).encode()
        response.request = request
        return response

    def close(self):
        pass


class HealthTests(unittest.TestCase):
    def test_example_round_trip_and_fake_names(self):
        from pathlib import Path
        rules = read_rules(Path("checks.example.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rules), 7)
        self.assertEqual({r.kind for r in rules}, {"presence", "event_id", "field", "timestamp", "volume", "route"})
        self.assertEqual(read_rules(json.dumps({"checks": [rule_dict(r) for r in rules]})), rules)
        self.assertTrue(all("example" in r.host for r in rules))

    def test_rejects_injection_wildcard_duplicate_and_unknown_kind(self):
        base = rule_dict(BASE)
        for change in ({"host": "x*"}, {"index": "main | delete"}, {"source": "x`y"},
                       {"kind": "lookup"}, {"window_minutes": True}, {"window_minutes": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                read_rules(json.dumps({"checks": [dict(base, **change)]}))
        with self.assertRaises(ValueError):
            read_rules(json.dumps({"checks": [base, base]}))
        with self.assertRaises(ValueError):
            read_rules(json.dumps({"checks": [dict(base, field="src_ip")]}))
        with self.assertRaises(ValueError):
            read_rules(json.dumps({"checks": [dict(base, kind="field", field="x | table password")]}))

    def test_timezone_and_search_bounds(self):
        with self.assertRaises(ValueError):
            build_search(BASE, datetime(2026, 10, 10))
        search = build_search(BASE, NOW)
        self.assertIn("earliest=0 latest=253402300799", search)
        self.assertIn(f"_index_earliest={int(NOW.timestamp())-3600}", search)
        self.assertIn(f"_index_latest={int(NOW.timestamp())}", search)
        self.assertIn("| eval arrival_epoch=_indextime", search)
        self.assertIn("| where arrival_epoch>=", search)
        self.assertIn(f"arrival_epoch<{int(NOW.timestamp())}", search)

    def test_source_escaping_and_event_field_validation(self):
        rule = replace(BASE, source='C:\\logs\\"security"')
        self.assertIn('source="C:\\\\logs\\\\\\"security\\""', build_search(rule, NOW))
        event = Rule("Sysmon", "event_id", "example_windows", "win.example.invalid", "XmlWinEventLog:Sysmon", 60,
                     event_id_field="EventCode", event_id="1")
        self.assertIn('tostring(EventCode)="1"', build_search(event, NOW))
        with self.assertRaises(ValueError):
            replace(event, event_id_field="EventCode)| delete")

    def test_presence_no_data_and_exact_minimum(self):
        self.assertEqual(evaluate(BASE, {"total_count": "0"}, NOW).status, "NO_DATA")
        rule = replace(BASE, min_events=3)
        row = {"total_count": "2", "last_seen_epoch": str(NOW.timestamp()-60)}
        self.assertEqual(evaluate(rule, row, NOW).status, "ALERT")
        row["total_count"] = "3"
        self.assertEqual(evaluate(rule, row, NOW).status, "OK")
        row["last_seen_epoch"] = str(NOW.timestamp())
        with self.assertRaises(CheckError):
            evaluate(rule, row, NOW)

    def test_missing_sysmon_event_with_other_events(self):
        rule = Rule("Sysmon 1", "event_id", "example_windows", "win.example.invalid", "XmlWinEventLog:Sysmon", 60,
                    event_id_field="EventID", event_id="1")
        self.assertEqual(evaluate(rule, {"total_count": 70, "matching_count": 0}, NOW).status, "ALERT")
        self.assertEqual(evaluate(rule, {"total_count": 0, "matching_count": 0}, NOW).status, "NO_DATA")
        self.assertEqual(evaluate(rule, {"total_count": 70, "matching_count": 1}, NOW).status, "OK")

    def test_windows_xml_event_id_auto_fallback(self):
        raw = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID></System></Event>"
        self.assertIn("<EventID>4688</EventID>", raw)
        rule = Rule("Windows 4688", "event_id", "windows-1", "win.example.invalid", "XmlWinEventLog:Security", 1440,
                    event_id_field="auto", event_id="4688")
        search = build_search(rule, NOW)
        self.assertIn('rex field=_raw "<EventID>(?<xml_event_id>[0-9]+)</EventID>"', search)
        self.assertIn('tostring(coalesce(EventCode,EventID,xml_event_id))="4688"', search)
        self.assertEqual(evaluate(rule, {"total_count": 2700, "matching_count": 0}, NOW).status, "ALERT")

    def test_field_coverage_and_insufficient_sample(self):
        rule = Rule("Detection alanı", "field", "example_network", "fw.example.invalid", "example:firewall", 60,
                    field="src_ip", min_events=20, min_present_percent=95)
        self.assertEqual(evaluate(rule, {"total_count": 10, "present_count": 0}, NOW).status, "INSUFFICIENT_BASELINE")
        self.assertEqual(evaluate(rule, {"total_count": 20, "present_count": 18}, NOW).status, "ALERT")
        self.assertEqual(evaluate(rule, {"total_count": 20, "present_count": 19}, NOW).status, "OK")
        self.assertIn("src_ip", build_search(rule, NOW))

    def test_timestamp_anomalies_and_threshold_boundary(self):
        rule = Rule("Apache zamanı", "timestamp", "example_web", "web.example.invalid", "access_combined", 60,
                    min_events=20, max_bad_percent=5)
        self.assertEqual(evaluate(rule, {"total_count": 20, "bad_count": 1}, NOW).status, "OK")
        self.assertEqual(evaluate(rule, {"total_count": 20, "bad_count": 2}, NOW).status, "ALERT")
        search = build_search(rule, NOW)
        self.assertIn("_time < arrival_epoch-3600", search)
        self.assertIn("_time > arrival_epoch+300", search)

    def test_apache_raw_timestamp_comparison_uses_timezone(self):
        raw = '127.0.0.1 - - [08/Oct/2026:20:15:11 +0300] "GET / HTTP/1.1" 200 10927 "-" "sqlmap/1.0-lab-test"'
        import re
        from datetime import timezone as tz
        observed = datetime.strptime(re.search(r"\[([^]]+)\]", raw).group(1), "%d/%b/%Y:%H:%M:%S %z")
        self.assertEqual(observed.astimezone(tz.utc).isoformat(), "2026-10-08T17:15:11+00:00")
        rule = Rule("Apache parse", "timestamp", "example_web", "web.example.invalid", "access_combined", 60,
                    timestamp_source="apache_combined", max_parse_diff_seconds=60)
        search = build_search(rule, NOW)
        self.assertIn('strptime(raw_event_time,"%d/%b/%Y:%H:%M:%S %z")', search)
        self.assertIn("abs(_time-parsed_event_epoch)>60", search)
        self.assertIn("isnull(parsed_event_epoch)", search)
        self.assertEqual(evaluate(rule, {"total_count": 20, "bad_count": 2}, NOW).status, "ALERT")

    def test_volume_drop_exact_80_and_sparse_baseline(self):
        rule = Rule("Firewall hacmi", "volume", "example_network", "fw.example.invalid", "example:firewall", 60,
                    drop_percent=80, min_baseline_events=100)
        self.assertEqual(evaluate(rule, {"total_count": 120, "current_count": 20, "baseline_count": 100}, NOW).status, "ALERT")
        self.assertEqual(evaluate(rule, {"total_count": 121, "current_count": 21, "baseline_count": 100}, NOW).status, "OK")
        self.assertEqual(evaluate(rule, {"total_count": 20, "current_count": 20, "baseline_count": 0}, NOW).status, "INSUFFICIENT_BASELINE")
        self.assertEqual(evaluate(rule, {"total_count": 0, "current_count": 0, "baseline_count": 0}, NOW).status, "NO_DATA")
        self.assertIn(f"_index_earliest={int(NOW.timestamp())-7200}", build_search(rule, NOW))

    def test_wrong_index_and_no_visible_data(self):
        rule = Rule("Rota", "route", "expected_idx", "fw.example.invalid", "example:firewall", 60)
        self.assertEqual(evaluate(rule, {"total_count": 5, "expected_count": 0, "observed_indexes": ["other_idx"]}, NOW).status, "ALERT")
        self.assertEqual(evaluate(rule, {"total_count": 5, "expected_count": 4, "observed_indexes": ["expected_idx", "other_idx"]}, NOW).status, "ALERT")
        self.assertEqual(evaluate(rule, {"total_count": 5, "expected_count": 5, "observed_indexes": ["expected_idx"]}, NOW).status, "OK")
        self.assertEqual(evaluate(rule, {"total_count": 0, "expected_count": 0}, NOW).status, "NO_DATA")
        self.assertIn("search index=*", build_search(rule, NOW))

    def test_invalid_counters_are_errors_not_no_data(self):
        for row in ({"total_count": "nan"}, {"total_count": 2, "last_seen_epoch": ""}, {"total_count": -1}):
            with self.subTest(row=row), self.assertRaises(CheckError):
                evaluate(BASE, row, NOW)
        event = Rule("Event", "event_id", "example_windows", "win.example.invalid", "evt", 60,
                     event_id_field="EventCode", event_id="1")
        with self.assertRaises(CheckError):
            evaluate(event, {"total_count": 2, "matching_count": 3}, NOW)

    def test_run_checks_keeps_all_rules_and_separates_search_error(self):
        rules = [BASE, replace(BASE, name="İkinci")]
        client = FakeClient([[{"total_count": 0}], CheckError("Splunk araması tamamlanmadı.")])
        results = run_checks(client, rules, NOW)
        self.assertEqual([r.status for r in results], ["NO_DATA", "ERROR"])
        self.assertEqual(len(client.searches), 2)
        self.assertIn("Splunk araması", results[1].details)
        self.assertEqual(len(list(csv_bytes(results).decode("utf-8-sig").splitlines())), 3)

    def test_truncated_or_missing_stats_row_is_error(self):
        client = FakeClient([[], [{"total_count": 1}, {"total_count": 2}]])
        results = run_checks(client, [BASE, replace(BASE, name="İkinci")], NOW)
        self.assertEqual([r.status for r in results], ["ERROR", "ERROR"])

    def test_real_splunk_client_job_flow_for_missing_event_id(self):
        rule = Rule("Sysmon", "event_id", "example_windows", "win.example.invalid", "XmlWinEventLog:Sysmon", 60,
                    event_id_field="EventCode", event_id="1")
        adapter = HealthAdapter()
        config = Config("https://splunk.example.invalid:8089", "private-token", "", "", True, 5, 30, .01)
        client = SplunkClient(config)
        client.session.mount(config.base_url, adapter)
        try:
            now = client.get_server_time()
            results = run_checks(client, [rule], now)
            self.assertEqual([r.status for r in results], ["ALERT"])
            self.assertEqual(len(adapter.jobs), 2)
            self.assertIn("_index_earliest=", adapter.searches[1])
            self.assertIn("tostring(EventCode)", adapter.searches[1])
            self.assertNotIn("private-token", json.dumps(results[0].row()))
        finally:
            client.close()

    def test_cli_writes_csv_and_alert_exit_code(self):
        class CLIClient:
            def __init__(self, config):
                self.last_job = {}
            def get_server_time(self):
                return NOW
            def run_search(self, search):
                return {"results": [{"total_count": 0}]}
            def close(self):
                pass
        with tempfile.TemporaryDirectory() as temp:
            checks = Path(temp) / "checks.json"
            report = Path(temp) / "health.csv"
            checks.write_text(json.dumps({"checks": [rule_dict(BASE)]}), encoding="utf-8")
            output = StringIO()
            with patch.object(healthcheck, "SplunkClient", CLIClient), \
                 patch.object(healthcheck.Config, "from_env", return_value=Config("https://splunk.example.invalid:8089", "token", "", "", True, 5, 30, .01)), \
                 redirect_stdout(output):
                code = healthcheck.main(["--checks", str(checks), "--env-file", str(Path(temp) / "absent.env"), "--output", str(report)])
            self.assertEqual(code, 1)
            self.assertIn("NO_DATA", output.getvalue())
            self.assertIn("NO_DATA", report.read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
