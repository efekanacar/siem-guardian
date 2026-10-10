"""SPL üretiminden HTTP/job protokolüne ve rapora kadar istemci testleri.

Adapter yalnız REST sözleşmesini taklit eder; gerçek Splunk/SPL motoru değildir.
"""

import json
import csv
import io
import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests
from requests.adapters import BaseAdapter

from continuity.config import Config
from continuity.cli import main
from continuity.core import CheckError, Target, check_targets
from continuity.splunk import SplunkClient
from continuity.web import Job, Session, run_job


NOW = datetime(2026, 10, 8, 17, 56, 51, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=120)
SETTINGS = Config("https://splunk.example.invalid:8089", "private-token", "", "", True, 5, 60, .01)
TARGETS = [Target("Yeni", "linux", "host.invalid", "linux_secure", 30),
           Target("Geciken", "windows", "host.invalid", "XmlWinEventLog:Security", 10),
           Target("Eski", "linux", "host.invalid", "linux_messages", 30),
           Target("Beklenen kayıp", "windows", "missing.invalid", "XmlWinEventLog:System", 30)]


def row(target, seconds=60, **overrides):
    data = dict(index=target.index, host=target.host, sourcetype=target.sourcetype,
                matched_count="12", last_seen_epoch=str(NOW.timestamp() - seconds))
    data.update(overrides)
    return data


class SplunkAdapter(BaseAdapter):
    """Gerçek requests Session/Auth/Form/JSON yollarını kullanan sahte transport."""

    def __init__(self, rows, *, result_count=None, event_count=0):
        self.rows = rows
        self.result_count = result_count
        self.event_count = event_count
        self.jobs = {}
        self.calls = []
        self.searches = []

    def send(self, request, **kwargs):
        self.calls.append((request.method, request.url, kwargs))
        self.assertions(request, kwargs)
        path = urlsplit(request.url).path
        if request.method == "POST":
            form = parse_qs(request.body)
            search = form["search"][0]
            self.searches.append(search)
            if "server_now=now()" in search:
                results = [{"server_now": str(NOW.timestamp())}]
            else:
                results = self.rows
                assert "latest=+10y" in search
                assert f"_index_earliest={int(START.timestamp())}" in search
                assert f"_index_latest={int(NOW.timestamp())}" in search
                assert "BY index host sourcetype" in search
                assert form["adhoc_search_level"] == ["verbose"]
                assert form["allow_partial_results"] == ["false"]
            sid = f"job-{len(self.jobs)}"
            self.jobs[sid] = results
            payload = {"sid": sid}
        elif path.endswith("/results"):
            results = self.jobs[path.split("/")[-2]]
            assert parse_qs(urlsplit(request.url).query)["count"] == ["0"]
            payload = {"results": results, "preview": False}
        else:
            sid = path.split("/")[-1]
            results = self.jobs[sid]
            count = len(results) if self.result_count is None or "server_now" in (results[0] if results else {}) else self.result_count
            payload = {"entry": [{"content": dict(isDone=True, isFailed=False, isFinalized=False,
                       dispatchState="DONE", resultCount=str(count), eventCount=str(self.event_count))}]}
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(payload).encode()
        response.headers["Content-Type"] = "application/json"
        response.request = request
        return response

    def assertions(self, request, kwargs):
        assert request.headers["Authorization"] == "Bearer private-token"
        assert kwargs["verify"] is True
        assert 0 < kwargs["timeout"] <= 5

    def close(self):
        pass


def client_with(adapter):
    client = SplunkClient(SETTINGS)
    client.session.mount("https://splunk.example.invalid:8089", adapter)
    return client


class SplunkFlowTests(unittest.TestCase):
    def test_clock_job_grouped_data_job_and_expected_targets(self):
        adapter = SplunkAdapter([row(TARGETS[0]), row(TARGETS[1], 1200), row(TARGETS[2], 9000)])
        with self.make_client(adapter) as client:
            now = client.get_server_time()
            client.prepare_check(TARGETS, START, now)
            reports = check_targets(TARGETS, client.fetch_latest, now, 120)
            self.assertEqual([r.status for r in reports], ["OK", "DELAYED", "NO_DATA", "NO_DATA"])
            self.assertEqual(reports[0].delay_minutes, 1)
            self.assertIn("150.0 dakika", reports[2].note)
            self.assertIn("Bu hosttan", reports[3].note)
            self.assertEqual(len(adapter.jobs), 2)
            self.assertEqual(len(adapter.calls), 6)
            self.assertIn('(index="linux" OR index="windows") earliest=0 latest=+10y', adapter.searches[1])
            diagnostic = client.check_diagnostics
            self.assertEqual((diagnostic["returned_rows"], diagnostic["matched_targets"]), (3, 3))
            self.assertNotIn("private-token", json.dumps(diagnostic))
            self.assertEqual(diagnostic["sources"][0]["last_before_check_utc"], "2026-10-08T17:55:51Z")

    def test_nonzero_job_result_count_with_empty_api_body_is_error(self):
        # Eski istemci bu boş sonuçları NO_DATA olarak yorumluyordu.
        adapter = SplunkAdapter([], result_count=15)
        with self.make_client(adapter) as client:
            with self.assertRaises(CheckError) as raised:
                client.prepare_check(TARGETS, START, NOW)
            self.assertIn("satır sayısı uyuşmuyor", str(raised.exception))
            self.assertEqual(client.check_diagnostics["job"]["resultCount"], 15)
            self.assertIsNone(client.snapshot)

    def test_corrupt_bucket_failure_does_not_claim_zero_matching_sources(self):
        from unittest.mock import Mock
        with self.make_client(SplunkAdapter([])) as client:
            client.run_search = Mock(side_effect=CheckError("Splunk bazı bucket'lardaki ham olayları okuyamadı."))
            with self.assertRaises(CheckError):
                client.prepare_check(TARGETS, START, NOW)
            self.assertIsNone(client.check_diagnostics["returned_rows"])
            self.assertIsNone(client.check_diagnostics["matched_targets"])
            self.assertIsNone(client.snapshot)

    def test_truncated_result_page_is_error(self):
        with self.make_client(SplunkAdapter([row(TARGETS[0])], result_count=2)) as client:
            with self.assertRaises(CheckError):
                client.prepare_check(TARGETS, START, NOW)

    def test_exact_case_and_all_three_fields_are_required(self):
        actual = [row(TARGETS[0], host="HOST.invalid"), row(TARGETS[1], index="another_index")]
        with self.make_client(SplunkAdapter(actual)) as client:
            client.prepare_check(TARGETS, START, NOW)
            reports = check_targets(TARGETS, client.fetch_latest, NOW, 120)
            self.assertTrue(all(r.status == "NO_DATA" for r in reports))
            self.assertEqual(client.check_diagnostics["matched_targets"], 0)
            self.assertEqual(client.check_diagnostics["returned_rows"], 2)

    def test_missing_target_explains_wrong_index_and_missing_sourcetype(self):
        same_host_and_type = row(TARGETS[1], index="linux")
        with self.make_client(SplunkAdapter([same_host_and_type, row(TARGETS[0])])) as client:
            client.prepare_check(TARGETS[:2], START, NOW)
            missing = check_targets(TARGETS[1:2], client.fetch_latest, NOW, 120)[0]
            self.assertEqual(missing.status, "NO_DATA")
            self.assertIn("başka index'te görüldü: linux", missing.note)
        with self.make_client(SplunkAdapter([row(TARGETS[0])])) as client:
            client.prepare_check(TARGETS[:2], START, NOW)
            missing = check_targets(TARGETS[1:2], client.fetch_latest, NOW, 120)[0]
            self.assertEqual(missing.status, "NO_DATA")
            self.assertIn("başka loglar geliyor", missing.note)

    def test_bad_time_on_one_source_does_not_hide_good_source(self):
        actual = [row(TARGETS[0], last_seen_epoch=""), row(TARGETS[1], 1200)]
        with self.make_client(SplunkAdapter(actual)) as client:
            client.prepare_check(TARGETS, START, NOW)
            reports = check_targets(TARGETS, client.fetch_latest, NOW, 120)
            self.assertEqual([r.status for r in reports], ["ERROR", "DELAYED", "NO_DATA", "NO_DATA"])

    def test_events_without_grouped_results_are_processing_error(self):
        with self.make_client(SplunkAdapter([], event_count=12)) as client:
            with self.assertRaises(CheckError):
                client.prepare_check(TARGETS, START, NOW)

    def test_duplicate_group_is_error(self):
        with self.make_client(SplunkAdapter([row(TARGETS[0]), row(TARGETS[0])])) as client:
            with self.assertRaises(CheckError):
                client.prepare_check(TARGETS, START, NOW)

    def test_same_triple_with_two_names_keeps_thresholds(self):
        duplicate = Target("İkinci eşik", *[TARGETS[0].index, TARGETS[0].host, TARGETS[0].sourcetype], 1)
        targets = [TARGETS[0], duplicate]
        with self.make_client(SplunkAdapter([row(TARGETS[0], 120)])) as client:
            client.prepare_check(targets, START, NOW)
            reports = check_targets(targets, client.fetch_latest, NOW, 120)
            self.assertEqual([r.status for r in reports], ["OK", "DELAYED"])
            self.assertEqual(client.check_diagnostics["matched_targets"], 2)

    def test_real_web_job_uses_batch_and_keeps_diagnostics(self):
        from unittest.mock import patch
        adapter = SplunkAdapter([row(TARGETS[0])])
        session = Session(config=SETTINGS)
        job = Job("check", total=len(TARGETS))
        with self.make_client(adapter) as client, patch("continuity.web.SplunkClient", return_value=client):
            run_job(session, job, SETTINGS, TARGETS, 120)
        self.assertEqual(job.status, "DONE")
        self.assertEqual(job.completed, len(TARGETS))
        self.assertEqual([r.status for r in session.reports], ["OK", "NO_DATA", "NO_DATA", "NO_DATA"])
        self.assertEqual(session.snapshot()["diagnostics"]["matched_targets"], 1)
        self.assertEqual(len(adapter.jobs), 2)

    def test_four_statuses_through_real_cli_pipeline_and_csv(self):
        from contextlib import redirect_stdout, redirect_stderr
        from unittest.mock import patch
        adapter = SplunkAdapter([row(TARGETS[0]), row(TARGETS[1], 1200),
                                 row(TARGETS[2], last_seen_epoch="")])
        with tempfile.TemporaryDirectory() as folder, self.make_client(adapter) as client:
            path = Path(folder) / "targets.csv"
            output = Path(folder) / "report.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(asdict(TARGETS[0])))
                writer.writeheader()
                writer.writerows(asdict(t) for t in TARGETS)
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("continuity.cli.SplunkClient", return_value=client), patch("continuity.cli.Config.from_env", return_value=SETTINGS), redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(["--targets", str(path), "--output", str(output)])
            self.assertEqual(result, 2)
            with output.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([r["status"] for r in rows], ["OK", "DELAYED", "ERROR", "NO_DATA"])
            self.assertEqual(len(adapter.jobs), 2)
            self.assertNotIn("private-token", stdout.getvalue() + stderr.getvalue())

    def test_window_boundaries_old_event_and_post_start_arrival(self):
        # _time kasıtlı olarak eski: değerlendirme _indextime maksimumuna dayanır.
        old_event = row(TARGETS[0], 7200, _time="946684800")
        with self.make_client(SplunkAdapter([old_event])) as client:
            client.prepare_check(TARGETS, START, NOW)
            report = check_targets(TARGETS[:1], client.fetch_latest, NOW, 120)[0]
            self.assertEqual(report.status, "DELAYED")
            self.assertEqual(report.delay_minutes, 120)
        only_after = row(TARGETS[0], seconds=0)
        with self.make_client(SplunkAdapter([only_after])) as client:
            client.prepare_check(TARGETS, START, NOW)
            self.assertEqual(check_targets(TARGETS[:1], client.fetch_latest, NOW, 120)[0].status, "ERROR")

    @staticmethod
    def make_client(adapter):
        from contextlib import closing
        return closing(client_with(adapter))


if __name__ == "__main__":
    unittest.main()
