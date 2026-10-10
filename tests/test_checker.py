import contextlib
import csv
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from continuity.cli import main
from continuity.config import Config
from continuity.core import (
    CheckError, NoData, Target, check_targets, evaluate, load_targets,
)
from continuity.splunk import DISCOVERY_SEARCH, ManagementHTTPError, SplunkClient, build_search, parse_results, reject_messages, spl_string


NOW = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=120)


def target(name="test", **kwargs):
    values = dict(name=name, index="demo_apps", host="app.example.invalid",
                  sourcetype="demo:app", max_delay_minutes=10)
    values.update(kwargs)
    return Target(**values)


def config():
    return Config("https://splunk.example.invalid:8089", "secret-token", "", "", True, 5, 60, 0.01)


def state(done=False, **kwargs):
    content = dict(isDone=done, isFailed=False, isFinalized=False,
                   dispatchState="DONE" if done else "RUNNING")
    content.update(kwargs)
    return {"entry": [{"content": content}]}


def arrival(t, seconds=60, **overrides):
    return dict(index=t.index, host=t.host, sourcetype=t.sourcetype,
                matched_count="2", index_time_count="2", before_check_count="2",
                last_seen_epoch=str(NOW.timestamp() - seconds),
                latest_any_epoch=str(NOW.timestamp() - seconds), **overrides)


class MeasurementTests(unittest.TestCase):
    def test_threshold_equality_is_ok_and_one_second_over_is_delayed(self):
        for seconds, expected in [(599, "OK"), (600, "OK"), (601, "DELAYED")]:
            with self.subTest(seconds=seconds):
                report = evaluate(target(), NOW - timedelta(seconds=seconds), NOW, START)
                self.assertEqual(report.status, expected)

    def test_timezone_converts_to_utc(self):
        istanbul = timezone(timedelta(hours=3))
        last = (NOW - timedelta(minutes=5)).astimezone(istanbul)
        report = evaluate(target(), last, NOW.astimezone(istanbul), START)
        self.assertEqual(report.delay_minutes, 5)
        self.assertEqual(report.row()["last_seen_utc"], "2026-10-03T11:55:00Z")

    def test_naive_datetime_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(target(), None, NOW.replace(tzinfo=None), START)

    def test_missing_target_stays_in_report(self):
        targets = [target("found"), target("missing")]
        results = {"found": NOW - timedelta(minutes=2)}
        reports = check_targets(targets, lambda t, s, e: results.get(t.name), NOW, 120)
        self.assertEqual([r.target.name for r in reports], ["found", "missing"])
        self.assertEqual([r.status for r in reports], ["OK", "NO_DATA"])
        self.assertEqual(reports[1].row()["last_seen_utc"], "")
        self.assertEqual(reports[1].row()["delay_minutes"], "")

    def test_error_does_not_become_no_data_and_next_target_runs(self):
        def fetch(t, s, e):
            if t.name == "bad":
                raise RuntimeError("Authorization: Bearer secret-token")
            return NOW - timedelta(minutes=2)
        reports = check_targets([target("bad"), target("good")], fetch, NOW, 120)
        self.assertEqual([r.status for r in reports], ["ERROR", "OK"])
        self.assertNotIn("secret-token", reports[0].error)

    def test_window_lower_inclusive_upper_exclusive(self):
        self.assertEqual(evaluate(target(), START, NOW, START).status, "DELAYED")
        for value in [START - timedelta(seconds=1), NOW, NOW + timedelta(seconds=1)]:
            with self.subTest(value=value), self.assertRaises(CheckError):
                evaluate(target(), value, NOW, START)

    def test_api_results_cover_all_four_states(self):
        targets = [target(str(i)) for i in range(4)]
        fetch = Mock(side_effect=[NOW - timedelta(minutes=5), NOW - timedelta(minutes=20), None, CheckError("Arama hatası.")])
        reports = check_targets(targets, fetch, NOW, 120)
        self.assertEqual([r.status for r in reports], ["OK", "DELAYED", "NO_DATA", "ERROR"])


class ValidationTests(unittest.TestCase):
    def load_csv(self, row, window=120):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "targets.csv"
            path.write_text("name,index,host,sourcetype,max_delay_minutes\n" + row, encoding="utf-8")
            return load_targets(path, window)

    def test_window_must_exceed_every_threshold(self):
        for window in [9, 10]:
            with self.subTest(window=window), self.assertRaises(ValueError):
                self.load_csv("x,demo,h,demo:app,10\n", window)
        self.assertEqual(len(self.load_csv("x,demo,h,demo:app,10\n", 11)), 1)

    def test_required_exact_fields_and_finite_threshold(self):
        for row in ["x,,h,s,10\n", "x,demo,,s,10\n", "x,demo,h,,10\n",
                    "x,demo,h*,s,10\n", "x,demo,h,s?,10\n", "x,demo,h,s,nan\n",
                    "x,demo,h,s,inf\n", "x,demo,h,s,0\n", "x,demo,h,s,10,extra\n"]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.load_csv(row)

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            self.load_csv("x,demo,h,s,10\nx,demo,h2,s,10\n")

    def test_query_escapes_indexes_and_does_not_inject_host_or_type(self):
        t = target(host='lab\\node" | stats count')
        search = build_search([t], START, NOW)
        self.assertEqual(spl_string(t.host, "host"), '"lab\\\\node\\" | stats count"')
        self.assertNotIn("lab", search)
        self.assertIn('search (index="demo_apps") earliest=0 latest=+10y', search)
        self.assertIn("eval arrival_epoch=_indextime", search)
        self.assertIn("AS index_time_count", search)
        self.assertNotIn("max(_time)", search)
        self.assertIn(f"_index_earliest={int(START.timestamp())}", search)
        self.assertIn(f"_index_latest={int(NOW.timestamp())}", search)
        self.assertIn(f"arrival_epoch>={int(START.timestamp())} AND arrival_epoch<{int(NOW.timestamp())}", search)
        self.assertIn("BY index host sourcetype", search)

    def test_macro_and_control_characters_rejected(self):
        for host in ["`macro`", "host\n| delete", "host\x00"]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                target(host=host)

    def test_configuration_auth_tls_and_port(self):
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "secret-token"}, clear=True):
            settings = Config.from_env()
            self.assertTrue(settings.verify_tls)
            self.assertNotIn("secret-token", repr(settings))
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "x", "SPLUNK_VERIFY_TLS": "false"}, clear=True):
            self.assertFalse(Config.from_env().verify_tls)
        for url in ["http://example.invalid:8089", "https://example.invalid:8000",
                    "https://user:secret@example.invalid:8089", "https://example.invalid:8089/path"]:
            with self.subTest(url=url), patch.dict(os.environ, {"SPLUNK_TOKEN": "x", "SPLUNK_BASE_URL": url}, clear=True):
                with self.assertRaises(ValueError):
                    Config.from_env()


class SplunkTests(unittest.TestCase):
    def test_server_clock_is_utc_and_does_not_use_client_clock(self):
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": [{"server_now": str(NOW.timestamp() + 0.75)}]})
        self.assertEqual(client.get_server_time(), NOW)
        self.assertIn("server_now=now()", client.run_search.call_args.args[0])
        client.close()

    def test_invalid_server_clock_fails_instead_of_empty_results(self):
        client = SplunkClient(config())
        for payload in [{}, {"results": []}, {"results": [{"server_now": "nan"}]},
                        {"results": [{"server_now": "0"}]}, {"results": [{"server_now": "secret"}]}]:
            client.run_search = Mock(return_value=payload)
            with self.subTest(payload=payload), self.assertRaises(CheckError):
                client.get_server_time()
        client.close()

    def test_batch_reads_arrival_with_index_time_search_bounds(self):
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": [arrival(target())]})
        self.assertEqual(client.fetch_latest(target(), START, NOW), NOW - timedelta(minutes=1))
        search = client.run_search.call_args.args[0]
        self.assertIn(f"_index_earliest={int(START.timestamp())}", search)
        self.assertIn(f"_index_latest={int(NOW.timestamp())}", search)
        self.assertIn(f"arrival_epoch<{int(NOW.timestamp())}", search)
        self.assertNotIn("253402300799", search)
        client.run_search.assert_called_once()
        client.close()

    def test_old_arrival_is_no_data_with_explanation_not_delayed(self):
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": [arrival(target(), 7260)]})
        report = evaluate(target(), client.fetch_latest(target(), START, NOW), NOW, START)
        self.assertEqual(report.status, "NO_DATA")
        self.assertIn("2026-10-03T09:59:00Z", report.note)
        self.assertEqual(report.row()["last_seen_utc"], "")
        client.close()

    def test_missing_target_has_no_data_note_and_search_failure_is_error(self):
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": []})
        result = client.fetch_latest(target(), START, NOW)
        self.assertIsInstance(result, NoData)
        self.assertIn("index yetkisini", result.note)
        client.snapshot_window = None
        client.run_search = Mock(side_effect=CheckError("Timeout."))
        reports = check_targets([target()], client.fetch_latest, NOW, 120)
        self.assertEqual(reports[0].status, "ERROR")
        client.close()

    def test_missing_index_time_and_inconsistent_counts_are_errors(self):
        for updates in [dict(index_time_count="0"), dict(matched_count="1"), dict(matched_count="nan")]:
            row = dict(arrival(target()), **updates)
            with self.subTest(row=row):
                values = parse_results({"results": [row]}, NOW)
                self.assertIsInstance(values[(target().index, target().host, target().sourcetype)], CheckError)

    def test_future_indextime_clock_skew_is_error(self):
        client = SplunkClient(config())
        row = dict(arrival(target(), -600), before_check_count="0", last_seen_epoch="")
        client.run_search = Mock(return_value={"results": [row]})
        with self.assertRaises(CheckError):
            client.fetch_latest(target(), START, NOW)
        client.close()

    def test_fifteen_source_snapshot_does_not_become_all_no_data(self):
        # Anonim gecikme örüntüsü: 13 kaynak pencere içinde, 2 kaynak dışında.
        # Gerçek host/index değerleri veya kullanıcının CSV'si pakete eklenmez.
        delays = [2500, 3, 82, 384, 988, 23, 276113, 53, 992, 22,
                  6997, 7018, 7011, 7431, 7020]
        targets = [target(f"source-{i}", host=f"host-{i}.invalid", max_delay_minutes=30) for i in range(15)]
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": [arrival(t, seconds) for t, seconds in zip(targets, delays)]})
        client.prepare_check(targets, START, NOW)
        reports = check_targets(targets, client.fetch_latest, NOW, 120)
        self.assertEqual(len(reports), 15)
        self.assertEqual([sum(r.status == s for r in reports) for s in ("OK", "DELAYED", "NO_DATA", "ERROR")], [8, 5, 2, 0])
        client.run_search.assert_called_once()
        client.close()

    def test_discovery_uses_index_metadata_and_keeps_source_values(self):
        client = SplunkClient(config())
        client.run_search = Mock(return_value={"results": [
            {"index": "main", "host": "windows.invalid", "sourcetype": "XmlWinEventLog:Security", "event_count": "12", "sources": "WinEventLog:Security"},
            {"index": "linux", "host": "linux.invalid", "sourcetype": "linux_secure", "event_count": "3", "sources": ["/var/log/auth.log", "/var/log/auth.log.1"]},
        ]})
        found = client.discover_targets()
        self.assertEqual(len(found), 2)
        self.assertEqual(found[0].host, "windows.invalid")
        self.assertEqual(client.discovery_sources[0]["sources"], ["WinEventLog:Security"])
        self.assertEqual(client.discovery_sources[1]["event_count"], 3)
        self.assertIn("BY index host source sourcetype", DISCOVERY_SEARCH)
        self.assertIn("earliest=0 latest=now", DISCOVERY_SEARCH)
        self.assertNotIn("253402300799", DISCOVERY_SEARCH)
        client.run_search.assert_called_once_with(DISCOVERY_SEARCH, warnings=client.discovery_warnings)
        client.close()

    def test_discovery_warn_does_not_fail_but_is_reported_without_secret_text(self):
        client = SplunkClient(config())
        warning = {"type": "WARN", "text": "This endpoint is deprecated secret-token"}
        client.request = Mock(side_effect=[{"sid": "job", "messages": [warning]}, state(True, messages=[warning]),
                                          {"results": [], "messages": [warning]}])
        self.assertEqual(client.discover_targets(), [])
        self.assertEqual(len(client.discovery_warnings), 1)
        self.assertIn("kaldırılacağını", client.discovery_warnings[0])
        self.assertNotIn("secret-token", client.discovery_warnings[0])
        client.close()

    def test_discovery_critical_warn_and_error_never_return_partial_targets(self):
        for severity, text in [("WARN", "Partial results from search peer secret-token"),
                               ("WARN", "Search result limit exceeded"), ("ERROR", "Invalid search secret-token")]:
            client = SplunkClient(config())
            client.request = Mock(side_effect=[{"sid": "job"}, state(True, messages=[{"type": severity, "text": text}])])
            with self.subTest(severity=severity, text=text), self.assertRaises(CheckError) as raised:
                client.discover_targets()
            self.assertNotIn("secret-token", str(raised.exception))
            self.assertEqual(client.request.call_count, 2)
            client.close()

    def test_discovery_rejects_invalid_rows_and_duplicate_targets(self):
        row = {"index": "main", "host": "host", "sourcetype": "type", "event_count": "1", "sources": ["source"]}
        for rows in [[dict(row, event_count="nan")], [dict(row, sources=[123])], [row, row], [None]]:
            client = SplunkClient(config())
            client.run_search = Mock(return_value={"results": rows})
            with self.subTest(rows=rows), self.assertRaises(CheckError):
                client.discover_targets()
            client.close()

    def test_continuity_warn_is_still_error_and_raw_messages_are_not_published(self):
        with self.assertRaises(CheckError):
            reject_messages({"messages": [{"type": "WARN", "text": "Endpoint deprecated"}]})
        warnings = []
        reject_messages({"messages": [{"type": "WARN", "text": "Unknown warning password=private"}]}, warnings)
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("private", warnings[0])
        rawdata = "Failed to read size=35 event(s) from rawdata in bucket='main~secret'. Rawdata may be corrupt. Results may be incomplete!"
        with self.assertRaises(CheckError) as raised:
            reject_messages({"messages": [{"type": "ERROR", "text": rawdata}]})
        self.assertIn("bucket", str(raised.exception))
        self.assertNotIn("main~secret", str(raised.exception))

    def test_waits_for_done_before_fetching_results(self):
        client = SplunkClient(config())
        client.request = Mock(side_effect=[
            {"sid": "job-1"}, state(), state(True),
            {"results": [arrival(target())]},
        ])
        with patch("continuity.splunk.time.sleep"):
            last = client.fetch_latest(target(), START, NOW)
        self.assertEqual(last, NOW - timedelta(minutes=1))
        paths = [call.args[1] for call in client.request.call_args_list]
        self.assertEqual(paths, ["/services/search/jobs", "/services/search/jobs/job-1",
                                 "/services/search/jobs/job-1", "/services/search/v2/jobs/job-1/results"])
        self.assertEqual([c.args[0] for c in client.request.call_args_list], ["POST", "GET", "GET", "GET"])
        client.close()

    def test_results_endpoint_fallback_only_when_unavailable(self):
        for code in [404, 405]:
            client = SplunkClient(config())
            client.request = Mock(side_effect=[{"sid": "job"}, state(True), ManagementHTTPError(code), {"results": []}])
            with self.subTest(code=code):
                self.assertEqual(client.run_search("| makeresults"), {"results": []})
                self.assertEqual(client.request.call_args_list[2].args[1], "/services/search/v2/jobs/job/results")
                self.assertEqual(client.request.call_args_list[3].args[1], "/services/search/jobs/job/results")
                self.assertEqual(client.results_prefix, "/services/search/jobs/")
            client.close()

    def test_results_endpoint_errors_do_not_trigger_fallback(self):
        for error in [ManagementHTTPError(401), ManagementHTTPError(403), ManagementHTTPError(500), CheckError("TLS doğrulaması başarısız.")]:
            client = SplunkClient(config())
            client.request = Mock(side_effect=[{"sid": "job"}, state(True), error])
            with self.subTest(error=error), self.assertRaises(CheckError):
                client.fetch_latest(target(), START, NOW)
            self.assertEqual(client.request.call_count, 3)
            client.close()

    def test_failed_finalized_warning_jobs_never_fetch_results(self):
        for content in [dict(isFailed=True), dict(isFinalized=True),
                        dict(messages=[{"type": "WARN", "text": "secret-token"}])]:
            with self.subTest(content=content):
                client = SplunkClient(config())
                client.request = Mock(side_effect=[{"sid": "job"}, state(True, **content)])
                with self.assertRaises(CheckError) as raised:
                    client.fetch_latest(target(), START, NOW)
                self.assertNotIn("secret-token", str(raised.exception))
                self.assertEqual(client.request.call_count, 2)
                client.close()

    def test_search_deadline_expires_before_results(self):
        client = SplunkClient(config())
        client.request = Mock(side_effect=[{"sid": "job"}, state()])
        with patch("continuity.splunk.time.monotonic", side_effect=[0, 61]):
            with self.assertRaises(CheckError):
                client.fetch_latest(target(), START, NOW)
        self.assertEqual(client.request.call_count, 2)
        client.close()

    def test_empty_is_no_data_but_malformed_is_error(self):
        self.assertEqual(parse_results({"results": []}, NOW), {})
        values = parse_results({"results": [dict(arrival(target()), last_seen_epoch="nan")]}, NOW)
        self.assertIsInstance(next(iter(values.values())), CheckError)
        for payload in [{}, {"results": [{}]}, {"results": [None]},
                        {"results": [], "preview": True},
                        {"results": [], "messages": [{"type": "ERROR", "text": "secret-token"}]}]:
            with self.subTest(payload=payload), self.assertRaises(CheckError):
                parse_results(payload, NOW)

    def test_http_errors_are_sanitized_and_redirects_disabled(self):
        client = SplunkClient(config())
        client.session.request = Mock(side_effect=requests.ConnectionError("secret-token"))
        with self.assertRaises(CheckError) as raised:
            client.request("GET", "/services/search/jobs/job", float("inf"))
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertFalse(client.session.request.call_args.kwargs["allow_redirects"])
        self.assertTrue(client.session.request.call_args.kwargs["verify"])
        client.close()

    def test_http_401_tls_timeout_and_invalid_json_are_errors(self):
        client = SplunkClient(config())
        response = Mock(status_code=401)
        for effect in [response, requests.exceptions.SSLError("secret"), requests.Timeout("secret")]:
            client.session.request = Mock(side_effect=effect) if isinstance(effect, Exception) else Mock(return_value=effect)
            with self.subTest(effect=effect), self.assertRaises(CheckError):
                client.request("GET", "/services/search/jobs/job", float("inf"))
        response.status_code = 200
        response.json.side_effect = ValueError("secret")
        client.session.request = Mock(return_value=response)
        with self.assertRaises(CheckError):
            client.request("GET", "/services/search/jobs/job", float("inf"))
        client.close()


class CLITests(unittest.TestCase):
    def test_clock_failure_is_safe_error_without_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.csv"
            with patch("continuity.cli.SplunkClient") as client, patch("continuity.cli.Config.from_env", return_value=config()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                client.return_value.get_server_time.side_effect = CheckError("Splunk ölçüm saati alınamadı.")
                self.assertEqual(main(["--targets", "targets.example.csv", "--output", str(path)]), 2)
                client.return_value.fetch_latest.assert_not_called()
            self.assertFalse(path.exists())

    def test_cli_writes_csv_using_splunk_client(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.csv"
            def results(t, start, now):
                if t.name.endswith("hatasi"):
                    raise CheckError("Arama hatası.")
                return None if t.name.endswith("kaynak") else now - timedelta(minutes=5 if t.name.endswith("uygulama") else 60)
            with patch("continuity.cli.SplunkClient") as client, patch("continuity.cli.Config.from_env", return_value=config()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                client.return_value.fetch_latest.side_effect = results
                client.return_value.get_server_time.return_value = NOW
                result = main(["--targets", "targets.example.csv", "--output", str(path), "--window-minutes", "120"])
            self.assertEqual(result, 2)
            client.assert_called_once()
            client.return_value.close.assert_called_once()
            with path.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["status"] for row in rows], ["OK", "DELAYED", "NO_DATA", "ERROR"])

    def test_demo_option_is_not_available(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["--demo"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
