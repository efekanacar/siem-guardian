import csv
import io
import json
import threading
import time
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests

from continuity.config import Config
from continuity.core import CheckError, NoData, Target
from continuity.web import LocalServer, Session, merge_targets, targets_value


TEST_TARGETS = [Target(str(i), "test", f"host-{i}.invalid", "test:app", 10) for i in range(4)]


def test_results(target, start, now):
    if target.name == "3":
        raise CheckError("Arama hatası.")
    return {"0": now - timedelta(minutes=5), "1": now - timedelta(minutes=20), "2": NoData("Görünür son geliş kontrol aralığının dışında.")}[target.name]


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = LocalServer(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.browser = requests.Session()
        self.browser.trust_env = False
        self.state = self.browser.get(self.url + "/api/state", timeout=3).json()

    def tearDown(self):
        self.browser.close()

    def post(self, path, data):
        response = self.browser.post(self.url + path, json=data, headers={"X-CSRF-Token": self.state["csrf"]}, timeout=3)
        if response.status_code < 300:
            self.state = response.json()
        return response

    def wait_done(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.state = self.browser.get(self.url + "/api/state", timeout=3).json()
            if self.state["job"] is None or self.state["job"]["status"] != "RUNNING":
                return self.state
            threading.Event().wait(0.01)
        self.fail("Web job tamamlanmadı")

    def connect(self):
        with patch("continuity.web.SplunkClient.test_connection"):
            self.assertEqual(self.post("/api/connect", {"SPLUNK_BASE_URL": "https://splunk.example.invalid:8089", "SPLUNK_TOKEN": "test-token"}).status_code, 202)
            self.wait_done()
        self.assertTrue(self.state["connected"])

    def test_splunk_check_and_csv_export(self):
        self.connect()
        targets = [asdict(t) for t in TEST_TARGETS]
        server_now = datetime(2026, 10, 8, 17, 56, 51, tzinfo=timezone.utc)
        with patch("continuity.web.SplunkClient.fetch_latest", side_effect=test_results), patch("continuity.web.SplunkClient.get_server_time", return_value=server_now), patch("continuity.web.SplunkClient.prepare_check"):
            self.assertEqual(self.post("/api/check", {"targets": targets, "window": 120}).status_code, 202)
            completed = self.wait_done()
        self.assertEqual(completed["job"]["completed"], 4)
        self.assertEqual(completed["checked_at"], "2026-10-08T17:56:51Z")
        self.assertEqual([r["status"] for r in completed["reports"]], ["OK", "DELAYED", "NO_DATA", "ERROR"])
        self.assertIn("aralığının dışında", completed["reports"][2]["note"])
        response = self.browser.get(self.url + "/api/report.csv", timeout=3)
        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[2]["last_seen_utc"], "")
        # Değişmeyen hedeflerin CSV indirilmesi kontrol sonuçlarını silmez.
        self.post("/api/targets", {"targets": targets, "window": 120})
        self.assertEqual(len(self.state["reports"]), 4)
        self.assertEqual(self.browser.get(self.url + "/api/targets.csv", timeout=3).status_code, 200)

    def test_clock_failure_does_not_publish_no_data(self):
        self.connect()
        with patch("continuity.web.SplunkClient.get_server_time", side_effect=CheckError("Splunk ölçüm saati alınamadı.")), patch("continuity.web.SplunkClient.fetch_latest") as fetch:
            self.assertEqual(self.post("/api/check", {"targets": [asdict(TEST_TARGETS[0])], "window": 120}).status_code, 202)
            completed = self.wait_done()
            self.assertEqual(completed["job"]["status"], "ERROR")
            self.assertEqual(completed["reports"], [])
            fetch.assert_not_called()

    def test_diagnostics_download_contains_only_safe_check_data(self):
        self.connect()
        sid = self.browser.cookies["continuity_session"]
        diagnostic = {"search": 'search index="test" earliest=0 | stats count BY index host sourcetype',
                      "measurement_utc": "2026-10-08T17:56:51Z", "returned_rows": 1,
                      "matched_targets": 1, "expected_targets": 1, "sources": [], "error": ""}
        self.server.sessions[sid].diagnostics = diagnostic
        response = self.browser.get(self.url + "/api/diagnostics.json", timeout=3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), diagnostic)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertNotIn("test-token", response.text)
        self.assertEqual(self.browser.get(self.url + "/api/report.csv", timeout=3).status_code, 409)
        self.post("/api/disconnect", {})
        self.assertEqual(self.state["diagnostics"], {})
        self.assertEqual(self.browser.get(self.url + "/api/diagnostics.json", timeout=3).status_code, 409)

    def test_diagnostics_are_session_isolated_and_target_edits_clear_them(self):
        sid = self.browser.cookies["continuity_session"]
        self.server.sessions[sid].diagnostics = {"search": "safe query"}
        other = requests.Session()
        other.trust_env = False
        try:
            self.assertEqual(other.get(self.url + "/api/diagnostics.json", timeout=3).status_code, 409)
        finally:
            other.close()
        self.post("/api/targets", {"targets": [asdict(TEST_TARGETS[0])], "window": 120})
        self.assertEqual(self.state["diagnostics"], {})

    def test_csrf_origin_and_host_are_checked(self):
        response = self.browser.post(self.url + "/api/connect", json={}, timeout=3)
        self.assertEqual(response.status_code, 403)
        for header in [{"Origin": "https://external.invalid"}, {"Host": "evil.invalid"}]:
            header["X-CSRF-Token"] = self.state["csrf"]
            response = self.browser.post(self.url + "/api/connect", json={}, headers=header, timeout=3)
            self.assertEqual(response.status_code, 403)

    def test_csv_import_and_threshold_validation(self):
        content = "\ufeffname,index,host,sourcetype,max_delay_minutes\nBeklenen,demo,missing.example.invalid,demo:app,30\n"
        self.assertEqual(self.post("/api/import", {"csv": content, "window": 120}).status_code, 200)
        self.assertEqual(self.state["targets"][0]["host"], "missing.example.invalid")
        self.assertEqual(self.post("/api/import", {"csv": content, "window": 30}).status_code, 400)
        self.assertEqual(self.post("/api/import", {"csv": "bad", "window": 120}).status_code, 400)

    def test_credentials_are_not_exposed_and_disconnect_clears_them(self):
        values = {"SPLUNK_BASE_URL": "https://splunk.example.invalid:8089", "SPLUNK_USERNAME": "lab-user", "SPLUNK_PASSWORD": "private-password"}
        with patch("continuity.web.SplunkClient.test_connection") as connect:
            self.assertEqual(self.post("/api/connect", values).status_code, 202)
            result = self.wait_done()
            connect.assert_called_once()
        self.assertTrue(result["connected"])
        self.assertNotIn("private-password", json.dumps(result))
        self.assertNotIn("lab-user", json.dumps(result))
        sid = self.browser.cookies["continuity_session"]
        self.assertIsNotNone(self.server.sessions[sid].config)
        self.assertEqual(self.post("/api/disconnect", {}).status_code, 200)
        self.assertFalse(self.state["connected"])
        self.assertIsNone(self.server.sessions[sid].config)

    def test_failed_login_never_marks_connection_verified(self):
        with patch("continuity.web.SplunkClient.test_connection", side_effect=CheckError("Management API HTTP 401 döndürdü.")):
            self.post("/api/connect", {"SPLUNK_TOKEN": "private-token"})
            result = self.wait_done()
        self.assertEqual(result["job"]["status"], "ERROR")
        self.assertFalse(result["connected"])
        self.assertNotIn("private-token", json.dumps(result))

    def test_sessions_are_isolated_and_expire(self):
        self.connect()
        sid = self.browser.cookies["continuity_session"]
        other = requests.get(self.url + "/api/state", timeout=3).json()
        self.assertFalse(other["connected"])
        self.assertEqual(other["targets"], [])
        self.server.sessions[sid].touched = time.monotonic() - 1801
        renewed = self.browser.get(self.url + "/api/state", timeout=3).json()
        self.assertNotEqual(renewed["csrf"], self.state["csrf"])
        self.assertFalse(renewed["connected"])

    def test_discovery_preserves_missing_expected_target(self):
        self.connect()
        target = asdict(Target("Beklenen kayıp hedef", "demo", "missing.invalid", "demo:missing", 10))
        with patch("continuity.web.SplunkClient.discover_targets", return_value=TEST_TARGETS):
            self.post("/api/discover", {"targets": [target], "window": 120})
            result = self.wait_done()
        self.assertEqual(len(result["targets"]), 5)
        self.assertEqual(result["targets"][0], target)

    def test_discovery_publishes_sources_and_warnings_without_changing_csv(self):
        self.connect()
        def discover(client):
            client.discovery_sources = [{"index": "test", "host": "host-0.invalid", "sourcetype": "test:app", "sources": ["/var/log/auth.log"], "event_count": 5}]
            client.discovery_warnings = ["Splunk kullanılan API veya özelliğin ileride kaldırılacağını bildirdi."]
            return TEST_TARGETS[:1]
        with patch("continuity.web.SplunkClient.discover_targets", autospec=True, side_effect=discover):
            self.post("/api/discover", {"targets": [], "window": 120})
            result = self.wait_done()
        self.assertEqual(result["job"]["status"], "DONE")
        self.assertEqual(result["discovery_sources"][0]["sources"], ["/var/log/auth.log"])
        self.assertEqual(len(result["discovery_warnings"]), 1)
        exported = self.browser.get(self.url + "/api/targets.csv", timeout=3).content.decode("utf-8-sig")
        self.assertEqual(exported.splitlines()[0], "name,index,host,sourcetype,max_delay_minutes")
        self.post("/api/disconnect", {})
        self.assertEqual(self.state["discovery_sources"], [])
        self.assertEqual(self.state["discovery_warnings"], [])

    def test_discovery_failure_preserves_expected_targets(self):
        self.connect()
        target = asdict(TEST_TARGETS[0])
        with patch("continuity.web.SplunkClient.discover_targets", side_effect=CheckError("Splunk arama uyarısı: indexer erişimini kontrol edin.")):
            self.post("/api/discover", {"targets": [target], "window": 120})
            result = self.wait_done()
        self.assertEqual(result["job"]["status"], "ERROR")
        self.assertEqual(result["targets"], [target])

    def test_static_allowlist_and_security_headers(self):
        response = self.browser.get(self.url + "/", timeout=3)
        self.assertEqual(response.status_code, 200)
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertNotIn('id="demo"', response.text)
        self.assertNotIn("v2.0", response.text)
        self.assertIn("Efekan Acar", response.text)
        self.assertIn("SIEM Guardian", response.text)
        self.assertIn("Sağlık ve kapsama kontrolleri", response.text)
        for path in ["/.env", "/continuity/config.py", "/../.env"]:
            self.assertEqual(self.browser.get(self.url + path, timeout=3).status_code, 404)

    def test_invalid_management_port_is_rejected(self):
        self.assertEqual(self.post("/api/connect", {"SPLUNK_BASE_URL": "https://192.168.3.131:8000", "SPLUNK_TOKEN": "x"}).status_code, 400)

    def test_demo_endpoint_removed_and_connection_required(self):
        self.assertEqual(self.post("/api/demo", {}).status_code, 404)
        self.assertNotIn("demo", self.state)
        with patch("continuity.web.SplunkClient") as client:
            for path in ["/api/check", "/api/discover"]:
                self.assertEqual(self.post(path, {"targets": [asdict(TEST_TARGETS[0])], "window": 120}).status_code, 400)
            client.assert_not_called()

    def test_health_import_check_and_csv_export(self):
        rule = {"name": "Sysmon 1", "kind": "event_id", "index": "example_windows",
                "host": "win.example.invalid", "sourcetype": "XmlWinEventLog:Sysmon",
                "window_minutes": 60, "event_id_field": "EventCode", "event_id": "1"}
        detection = {"name": "PowerShell tespiti", "technique": "T1059.001", "mode": "any",
                     "checks": ["Sysmon 1"], "impact": "PowerShell tespit kabiliyeti etkilenmiş olabilir."}
        self.assertEqual(self.post("/api/health/import", {"json": json.dumps({"checks": [rule], "detections": [detection]})}).status_code, 200)
        self.assertEqual(self.state["health_checks"][0]["name"], "Sysmon 1")
        self.assertEqual(self.state["detection_results"][0]["status"], "PENDING")
        self.assertEqual(self.post("/api/health/check", {}).status_code, 400)
        self.connect()
        now = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
        with patch("continuity.web.SplunkClient.get_server_time", return_value=now), patch(
            "continuity.web.SplunkClient.run_search", return_value={"results": [{"total_count": "20", "matching_count": "0"}]}
        ):
            self.assertEqual(self.post("/api/health/check", {}).status_code, 202)
            done = self.wait_done()
        self.assertEqual(done["job"]["status"], "DONE")
        self.assertEqual(done["job"]["completed"], 1)
        self.assertEqual(done["health_results"][0]["status"], "ALERT")
        self.assertEqual(done["detection_results"][0]["status"], "IMPAIRED")
        self.assertIn("PowerShell tespit", done["detection_results"][0]["impact"])
        self.assertIn("EventCode", done["health_results"][0]["search"])
        exported = self.browser.get(self.url + "/api/health-report.csv", timeout=3)
        self.assertEqual(exported.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0]["status"], "ALERT")
        self.assertEqual(self.browser.get(self.url + "/api/health-example.json", timeout=3).status_code, 200)
        saved = self.browser.get(self.url + "/api/health-checks.json", timeout=3).json()
        self.assertEqual(saved["checks"][0]["event_id"], "1")
        self.assertEqual(saved["detections"][0]["name"], "PowerShell tespiti")
        self.assertIn("IMPAIRED", self.browser.get(self.url + "/api/detection-report.csv", timeout=3).text)
        self.assertNotIn("private-token", json.dumps(done))

    def test_health_editor_config_validates_and_resets_results(self):
        rule = {"name": "Windows Security", "kind": "presence", "index": "example_windows",
                "host": "win.example.invalid", "sourcetype": "XmlWinEventLog:Security",
                "window_minutes": 120, "availability": "intermittent", "min_events": 1}
        detection = {"name": "Security coverage", "technique": "T1059.001", "mode": "all",
                     "checks": ["Windows Security"], "impact": "Tespit kabiliyeti etkilenmiş olabilir."}
        self.assertEqual(self.post("/api/health/config", {"checks": [rule], "detections": [detection]}).status_code, 200)
        self.assertEqual(self.state["health_checks"][0]["name"], "Windows Security")
        self.assertEqual(self.state["detection_results"][0]["status"], "PENDING")
        self.assertEqual(self.post("/api/health/config", {"checks": [], "detections": [detection]}).status_code, 400)
        self.assertEqual(len(self.state["health_checks"]), 1)
        self.assertEqual(self.post("/api/health/config", {"checks": [], "detections": []}).status_code, 200)
        self.assertEqual(self.state["health_checks"], [])
        self.assertEqual(self.state["detections"], [])

    def test_health_csv_inventory_import(self):
        from pathlib import Path
        content = Path("checks.example.csv").read_text(encoding="utf-8")
        self.assertEqual(self.post("/api/health/import", {"csv": content}).status_code, 200)
        self.assertEqual(len(self.state["health_checks"]), 2)
        self.assertEqual(self.state["detections"], [])

    def test_health_rule_validation_rejects_spl_injection(self):
        rule = {"name": "Unsafe", "kind": "field", "index": "example_linux", "host": "host.invalid",
                "sourcetype": "linux_secure", "window_minutes": 60, "field": "src | delete"}
        self.assertEqual(self.post("/api/health/import", {"json": json.dumps({"checks": [rule]})}).status_code, 400)
        self.assertEqual(self.state["health_checks"], [])


class WebLogicTests(unittest.TestCase):
    def test_discovery_does_not_replace_name_or_threshold(self):
        old = Target("Özel ad", "demo", "host", "type", 12)
        found = Target("Keşif adı", "demo", "host", "type", 30)
        self.assertEqual(merge_targets([old], [found]), [old])

    def test_target_wildcards_and_duplicate_names_rejected(self):
        row = asdict(Target("Hedef", "demo", "host", "type", 10))
        with self.assertRaises(ValueError):
            targets_value([row, row], 120)
        row["host"] = "*"
        with self.assertRaises(ValueError):
            targets_value([row], 120)

    def test_form_settings_use_shared_config_validation(self):
        settings = Config.from_values({"SPLUNK_TOKEN": "x", "SPLUNK_VERIFY_TLS": "false"})
        self.assertFalse(settings.verify_tls)
        with self.assertRaises(ValueError):
            Config.from_values({"SPLUNK_TOKEN": "x", "SPLUNK_VERIFY_TLS": "maybe"})


if __name__ == "__main__":
    unittest.main()
