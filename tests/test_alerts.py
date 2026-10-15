import csv
import io
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from continuity.alerts import (
    AlertDefinition, AlertDependency, analyze_alerts, build_dependency_search,
    csv_bytes, extract_dependencies, parse_alerts,
)
from continuity.core import CheckError
from continuity.config import Config
from continuity.splunk import SplunkClient
from continuity.web import Job, Session, run_job


NOW = datetime(2026, 10, 16, 9, 30, tzinfo=timezone.utc)


def entry(name, search, *, disabled="0", alert_type="number of events", app="search"):
    return {
        "name": name,
        "acl": {"app": app, "owner": "admin"},
        "content": {
            "disabled": disabled,
            "alert_type": alert_type,
            "search": search,
            "cron_schedule": "*/5 * * * *",
            "dispatch.earliest_time": "-15m@m",
            "dispatch.latest_time": "now",
        },
    }


class FakeClient:
    def __init__(self, counts):
        self.counts = counts
        self.searches = []

    def run_search(self, search):
        self.searches.append(search)
        for marker, value in self.counts.items():
            if marker in search:
                if isinstance(value, Exception):
                    raise value
                return {"results": [{"event_count": str(value),
                                      "last_seen_epoch": str(NOW.timestamp() - 60) if value else ""}]}
        raise AssertionError("Beklenmeyen SPL: " + search)


class AlertCoverageTests(unittest.TestCase):
    def test_extracts_exact_log_types_and_event_ids(self):
        dependencies, warnings = extract_dependencies(
            'search index="windows" (sourcetype="XmlWinEventLog:Security" EventCode=4688 '
            'OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1)'
        )
        self.assertEqual(len(dependencies), 2)
        self.assertEqual({item.sourcetype for item in dependencies}, {
            "XmlWinEventLog:Security", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
        })
        self.assertEqual(dependencies[0].index, "windows")
        by_type = {item.sourcetype: item.event_ids for item in dependencies}
        self.assertEqual(by_type["XmlWinEventLog:Security"], ("4688",))
        self.assertEqual(by_type["XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"], ("1",))
        self.assertEqual(warnings, ())

    def test_macro_and_wildcard_are_reported_without_guessing(self):
        dependencies, warnings = extract_dependencies(
            'index=windows sourcetype="XmlWinEventLog:*" `security_content_ctime(firstTime)`'
        )
        self.assertEqual(dependencies, ())
        self.assertTrue(any("wildcard" in warning for warning in warnings))
        self.assertTrue(any("makro" in warning for warning in warnings))
        self.assertTrue(any("sourcetype" in warning for warning in warnings))

    def test_saved_search_response_keeps_only_enabled_alerts(self):
        payload = {"entry": [
            entry("Process Creation", 'index=windows sourcetype="XmlWinEventLog:Security" EventCode=4688'),
            entry("Disabled", "index=main sourcetype=test", disabled="1"),
            entry("Report", "index=main sourcetype=test", alert_type=""),
        ]}
        alerts = parse_alerts(payload)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].key, "admin/search/Process Creation")
        self.assertEqual(alerts[0].earliest, "-15m@m")

    def test_client_reads_all_namespaces_without_modifying_alerts(self):
        client = SplunkClient(Config("https://splunk.invalid:8089", "token", "", "", True, 5, 30, .01))
        client.request = Mock(return_value={"entry": [entry("Auth", "index=linux sourcetype=linux_secure")]})
        alerts = client.list_alerts()
        self.assertEqual(alerts[0].name, "Auth")
        args, kwargs = client.request.call_args
        self.assertEqual(args[:2], ("GET", "/servicesNS/-/-/saved/searches"))
        self.assertEqual(kwargs["params"], {"output_mode": "json", "count": "0", "search": "disabled=0"})
        client.close()

    def test_bad_saved_search_payload_is_error(self):
        with self.assertRaises(CheckError):
            parse_alerts({"entry": [{"name": "Broken", "content": {"alert_type": "always"}}]})

    def test_dependency_search_uses_index_time_and_event_filter(self):
        dependency = AlertDependency("windows", "host-1", "XmlWinEventLog:Security", "WinEventLog:Security", ("4688",))
        search = build_dependency_search(dependency, NOW, 120)
        self.assertIn('index="windows"', search)
        self.assertIn('host="host-1"', search)
        self.assertIn('source="WinEventLog:Security"', search)
        self.assertIn("_index_earliest=", search)
        self.assertIn("arrival_epoch=_indextime", search)
        self.assertIn("coalesce(EventCode,EventID,xml_event_id)", search)
        self.assertIn('="4688"', search)

    def test_alert_result_distinguishes_covered_degraded_blind_and_error(self):
        def alert(name, sourcetypes, warnings=()):
            dependencies = tuple(AlertDependency("main", "", value) for value in sourcetypes)
            return AlertDefinition(name, name, "search", "admin", "search", "always", "", "-1h", "now", dependencies, warnings)

        alerts = [
            alert("Covered", ["good"]),
            alert("Degraded", ["good", "missing"]),
            alert("Blind", ["missing"]),
            alert("Error", ["broken"]),
            alert("Unknown", []),
        ]
        client = FakeClient({'sourcetype="good"': 4, 'sourcetype="missing"': 0,
                             'sourcetype="broken"': CheckError("arama hatası")})
        results = analyze_alerts(client, alerts, NOW, 60)
        self.assertEqual([result.status for result in results],
                         ["COVERED", "DEGRADED", "BLIND", "ERROR", "UNKNOWN"])
        self.assertEqual(results[0].dependencies[0].last_seen_utc, "2026-10-16T09:29:00Z")
        # Aynı bağımlılık birden fazla alertte kullanılsa da Splunk yalnız bir kez sorgulanır.
        self.assertEqual(sum('sourcetype="good"' in search for search in client.searches), 1)

    def test_csv_contains_one_row_per_dependency(self):
        alert = AlertDefinition("key", "=Formula Alert", "search", "admin", "search", "always", "", "", "",
                                (AlertDependency("main", "", "one"), AlertDependency("main", "", "two")), ())
        result = analyze_alerts(FakeClient({'sourcetype="one"': 1, 'sourcetype="two"': 0}), [alert], NOW, 60)
        rows = list(csv.DictReader(io.StringIO(csv_bytes(result).decode("utf-8-sig"))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["alert"], "'=Formula Alert")
        self.assertEqual({row["dependency_status"] for row in rows}, {"OK", "NO_DATA"})

    def test_web_background_job_fetches_and_analyzes_alerts(self):
        alert = parse_alerts({"entry": [entry("Auth", "index=linux sourcetype=linux_secure") ]})[0]
        client = FakeClient({'sourcetype="linux_secure"': 3})
        client.get_server_time = lambda: NOW
        client.list_alerts = lambda: [alert]
        client.close = lambda: None
        config = Config("https://splunk.invalid:8089", "token", "", "", True, 5, 30, .01)
        session = Session(config=config)
        job = Job("alerts")
        with patch("continuity.web.SplunkClient", return_value=client):
            run_job(session, job, config, [], 120)
        self.assertEqual(job.status, "DONE")
        self.assertEqual(job.completed, 1)
        self.assertEqual(session.snapshot()["alert_results"][0]["status"], "COVERED")


if __name__ == "__main__":
    unittest.main()
