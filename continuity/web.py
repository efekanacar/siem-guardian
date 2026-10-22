"""Tek kullanıcılı, localhost'a bağlı arayüz; kimlik bilgileri bellektedir."""

import argparse
import csv
import io
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config
from .core import (
    CheckError, REPORT_FIELDS, TARGET_FIELDS, Report, Target,
    evaluate, positive_number, read_targets,
)
from .splunk import SplunkClient
from .health import Rule, Result, csv_bytes as health_csv_bytes, read_config, read_csv_rules, rule_dict, run_checks
from .dependencies import Detection, csv_bytes as detection_csv_bytes, detection_dict, evaluate_detections
from .alerts import AlertResult, alert_dict, analyze_alerts, csv_bytes as alert_csv_bytes


ASSETS = Path(__file__).resolve().parent / "static"
SESSION_TTL = 1800


def window_value(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Kontrol aralığı tam sayı olmalı.")
    try:
        number = int(value)
    except ValueError:
        raise ValueError("Kontrol aralığı tam sayı olmalı.") from None
    if not 1 <= number <= 525600:
        raise ValueError("Kontrol aralığı 1–525600 dakika olmalı.")
    return number


def targets_value(rows, window: int, allow_empty=False) -> list[Target]:
    if not isinstance(rows, list) or len(rows) > 500 or (not rows and not allow_empty):
        raise ValueError("1–500 hedef gerekli.")
    targets, names = [], set()
    for position, row in enumerate(rows, 1):
        try:
            if not isinstance(row, dict) or set(row) != set(TARGET_FIELDS):
                raise ValueError("Hedef sütunları geçersiz.")
            if any(not isinstance(row[key], str) for key in TARGET_FIELDS[:-1]):
                raise ValueError("Hedef alanları metin olmalı.")
            target = Target(
                **{key: row[key].strip() for key in TARGET_FIELDS[:-1]},
                max_delay_minutes=positive_number(str(row["max_delay_minutes"]), "Eşik"),
            )
            if target.name in names:
                raise ValueError("Hedef adları benzersiz olmalı.")
            if window <= target.max_delay_minutes:
                raise ValueError("Kontrol aralığı bütün eşiklerden uzun olmalı.")
            names.add(target.name)
            targets.append(target)
        except ValueError as exc:
            raise ValueError(f"Hedef {position}: {exc}") from None
    return targets


def merge_targets(existing: list[Target], discovered: list[Target]) -> list[Target]:
    merged = list(existing)
    keys = {(t.index, t.host, t.sourcetype) for t in merged}
    names = {t.name for t in merged}
    for target in discovered:
        key = (target.index, target.host, target.sourcetype)
        if key in keys:
            continue
        name, suffix = target.name, 2
        while name in names:
            name = target.name[:240] + f" ({suffix})"
            suffix += 1
        merged.append(Target(name, *key, target.max_delay_minutes))
        names.add(name)
        keys.add(key)
    if len(merged) > 500:
        raise ValueError("Birleşik hedef listesi 500 satırı aşıyor.")
    return merged


def csv_bytes(fields, rows) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue().encode("utf-8-sig")


@dataclass
class Job:
    kind: str
    status: str = "RUNNING"
    completed: int = 0
    total: int = 0
    error: str = ""
    cancel: threading.Event = field(default_factory=threading.Event, repr=False)


@dataclass
class Session:
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    config: Config | None = field(default=None, repr=False)
    targets: list[Target] = field(default_factory=list)
    discovery_sources: list[dict] = field(default_factory=list)
    discovery_warnings: list[str] = field(default_factory=list)
    reports: list[Report] = field(default_factory=list)
    checked_at: str | None = None
    diagnostics: dict = field(default_factory=dict)
    health_rules: list[Rule] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    health_results: list[Result] = field(default_factory=list)
    health_checked_at: str | None = None
    alert_results: list[AlertResult] = field(default_factory=list)
    alert_checked_at: str | None = None
    window: int = 1440
    job: Job | None = None
    touched: float = field(default_factory=time.monotonic)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "csrf": self.csrf, "connected": self.config is not None,
                "address": self.config.base_url if self.config else "",
                "verify_tls": self.config.verify_tls is not False if self.config else True,
                "targets": [asdict(t) for t in self.targets], "window": self.window,
                "discovery_sources": self.discovery_sources,
                "discovery_warnings": self.discovery_warnings,
                "reports": [dict(r.row(), error=r.error, note=r.note) for r in self.reports],
                "checked_at": self.checked_at,
                "diagnostics": self.diagnostics,
                "health_checks": [rule_dict(rule) for rule in self.health_rules],
                "detections": [detection_dict(value) for value in self.detections],
                "detection_results": evaluate_detections(self.detections, self.health_results),
                "health_results": [dict(result.row(), search=result.search, job=result.job) for result in self.health_results],
                "health_checked_at": self.health_checked_at,
                "alert_results": [alert_dict(result) for result in self.alert_results],
                "alert_checked_at": self.alert_checked_at,
                "job": {"kind": self.job.kind, "status": self.job.status,
                        "completed": self.job.completed, "total": self.job.total,
                        "error": self.job.error} if self.job else None,
            }


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=8787):
        self.sessions: dict[str, Session] = {}
        self.sessions_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)

    def handle_error(self, request, client_address):
        # HTTP veya Splunk istisnalarının ham gövdelerini terminale yazdırma.
        pass

    def session(self, cookie: str) -> tuple[str, Session]:
        parsed = SimpleCookie()
        try:
            parsed.load(cookie)
            sid = parsed["continuity_session"].value if "continuity_session" in parsed else ""
        except Exception:
            sid = ""
        now = time.monotonic()
        with self.sessions_lock:
            expired = [key for key, s in self.sessions.items() if now - s.touched > SESSION_TTL]
            for key in expired:
                old = self.sessions.pop(key)
                with old.lock:
                    old.config = None
                    if old.job:
                        old.job.cancel.set()
            if sid not in self.sessions:
                if len(self.sessions) >= 32:
                    raise ValueError("Çok fazla oturum açık. Eski oturumların kapanmasını bekleyin.")
                sid = secrets.token_urlsafe(32)
                self.sessions[sid] = Session()
            current = self.sessions[sid]
            current.touched = now
            return sid, current


def run_job(session: Session, job: Job, config: Config, targets: list[Target], window: int):
    client = None
    try:
        client = SplunkClient(config)
        if job.kind == "connect":
            client.test_connection()
            with session.lock:
                if not job.cancel.is_set():
                    session.config = config
                    session.discovery_sources, session.discovery_warnings = [], []
                    session.reports, session.checked_at = [], None
                    session.diagnostics = {}
                    session.health_results, session.health_checked_at = [], None
                    session.alert_results, session.alert_checked_at = [], None
        elif job.kind == "discover":
            discovered = client.discover_targets()
            merged = merge_targets(targets, discovered)
            # Keşfedilen eşiklerin de pencereye uygun olması gerekir.
            targets_value([asdict(t) for t in merged], window, allow_empty=True)
            with session.lock:
                if not job.cancel.is_set():
                    session.targets = merged
                    session.discovery_sources = client.discovery_sources
                    session.discovery_warnings = client.discovery_warnings
                    session.reports, session.checked_at = [], None
                    session.diagnostics = {}
        elif job.kind == "health":
            now = client.get_server_time()
            with session.lock:
                rules = list(session.health_rules)
                session.health_results, session.health_checked_at = [], None
            def progress(position):
                with session.lock:
                    job.completed = position
            results = run_checks(client, rules, now, progress, job.cancel.is_set)
            with session.lock:
                if not job.cancel.is_set():
                    session.health_results = results
                    session.health_checked_at = now.isoformat().replace("+00:00", "Z")
        elif job.kind == "alerts":
            now = client.get_server_time()
            alerts = client.list_alerts()
            with session.lock:
                session.alert_results, session.alert_checked_at = [], None
                job.total = len({dependency for alert in alerts for dependency in alert.dependencies})
            def alert_progress(position):
                with session.lock:
                    job.completed = position
            results = analyze_alerts(client, alerts, now, window, alert_progress, job.cancel.is_set)
            with session.lock:
                if not job.cancel.is_set():
                    session.alert_results = results
                    session.alert_checked_at = now.isoformat().replace("+00:00", "Z")
                    job.completed = job.total
        else:
            now = client.get_server_time()
            start = now - timedelta(minutes=window)
            fetch = client.fetch_latest
            with session.lock:
                if job.cancel.is_set():
                    job.status = "CANCELLED"
                    return
                session.reports = []
                session.checked_at = now.isoformat().replace("+00:00", "Z")
            client.prepare_check(targets, start, now)
            for target in targets:
                if job.cancel.is_set():
                    break
                try:
                    report = evaluate(target, fetch(target, start, now), now, start)
                except CheckError as exc:
                    report = Report(target, None, None, "ERROR", str(exc))
                except Exception:
                    report = Report(target, None, None, "ERROR", "Beklenmeyen veri işleme hatası.")
                with session.lock:
                    if not job.cancel.is_set():
                        session.reports.append(report)
                        job.completed += 1
        with session.lock:
            if client and job.kind == "check" and not job.cancel.is_set():
                session.diagnostics = client.check_diagnostics
            job.status = "CANCELLED" if job.cancel.is_set() else "DONE"
    except (CheckError, ValueError) as exc:
        with session.lock:
            if client and job.kind == "check" and not job.cancel.is_set():
                session.diagnostics = client.check_diagnostics
            job.status, job.error = "ERROR", str(exc)
    except Exception:
        with session.lock:
            if client and job.kind == "check" and not job.cancel.is_set():
                session.diagnostics = client.check_diagnostics
            job.status, job.error = "ERROR", "İşlem tamamlanamadı. Bağlantı ve dosya ayarlarını kontrol edin."
    finally:
        if client:
            client.close()


class Handler(BaseHTTPRequestHandler):
    server: LocalServer

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def allowed(self) -> bool:
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host") in hosts and (not origin or origin in {f"http://{h}" for h in hosts})

    def send(self, code: int, data, mime="application/json; charset=utf-8", sid=None, filename=None):
        body = json.dumps(data, ensure_ascii=False).encode() if isinstance(data, dict) else data
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if sid:
            self.send_header("Set-Cookie", f"continuity_session={sid}; HttpOnly; SameSite=Strict; Path=/")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.allowed():
            return self.send(403, {"error": "Yalnız yerel arayüz erişimi kabul edilir."})
        path = urlsplit(self.path).path
        files = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                 "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path in files:
            filename, mime = files[path]
            return self.send(200, (ASSETS / filename).read_bytes(), mime)
        sid, session = self.server.session(self.headers.get("Cookie", ""))
        with session.lock:
            if path == "/api/state":
                return self.send(200, session.snapshot(), sid=sid)
            if path == "/api/targets.csv":
                return self.send(200, csv_bytes(TARGET_FIELDS, [asdict(t) for t in session.targets]),
                                 "text/csv; charset=utf-8", sid, "targets.csv")
            if path == "/api/report.csv":
                if not session.reports or (session.job and session.job.status == "RUNNING"):
                    return self.send(409, {"error": "Önce kontrolün tamamlanmasını bekleyin."}, sid=sid)
                return self.send(200, csv_bytes(REPORT_FIELDS, [r.row() for r in session.reports]),
                                 "text/csv; charset=utf-8", sid, "continuity-report.csv")
            if path == "/api/diagnostics.json":
                if not session.diagnostics or (session.job and session.job.status == "RUNNING"):
                    return self.send(409, {"error": "Önce kontrolün tamamlanmasını bekleyin."}, sid=sid)
                return self.send(200, session.diagnostics, "application/json; charset=utf-8", sid, "search-diagnostics.json")
            if path == "/api/health-report.csv":
                if not session.health_results or (session.job and session.job.status == "RUNNING"):
                    return self.send(409, {"error": "Önce sağlık kontrolünü tamamlayın."}, sid=sid)
                return self.send(200, health_csv_bytes(session.health_results), "text/csv; charset=utf-8", sid, "siem-health-report.csv")
            if path == "/api/detection-report.csv":
                if not session.health_results or (session.job and session.job.status == "RUNNING"):
                    return self.send(409, {"error": "Önce sağlık kontrolünü tamamlayın."}, sid=sid)
                return self.send(200, detection_csv_bytes(evaluate_detections(session.detections, session.health_results)),
                                 "text/csv; charset=utf-8", sid, "siem-detections.csv")
            if path == "/api/alert-report.csv":
                if not session.alert_results or (session.job and session.job.status == "RUNNING"):
                    return self.send(409, {"error": "Önce Splunk alert analizini tamamlayın."}, sid=sid)
                return self.send(200, alert_csv_bytes(session.alert_results),
                                 "text/csv; charset=utf-8", sid, "splunk-alert-coverage.csv")
            if path == "/api/health-checks.json":
                return self.send(200, {"checks": [rule_dict(rule) for rule in session.health_rules],
                                       "detections": [detection_dict(value) for value in session.detections]}, sid=sid, filename="checks.json")
        self.send(404, {"error": "Sayfa bulunamadı."})

    def do_POST(self):
        if not self.allowed():
            return self.send(403, {"error": "Yalnız yerel arayüz erişimi kabul edilir."})
        sid, session = self.server.session(self.headers.get("Cookie", ""))
        if not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), session.csrf):
            return self.send(403, {"error": "Oturumu yenilemek için sayfayı tekrar açın."}, sid=sid)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1048576 or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("Geçerli JSON gerekli; en fazla 1 MB kabul edilir.")
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("İstek biçimi geçersiz.")
            path = urlsplit(self.path).path
            with session.lock:
                if path == "/api/disconnect":
                    if session.job:
                        session.job.cancel.set()
                    session.config, session.job = None, None
                    session.discovery_sources, session.discovery_warnings = [], []
                    session.reports, session.checked_at = [], None
                    session.diagnostics = {}
                    session.health_results, session.health_checked_at = [], None
                    session.alert_results, session.alert_checked_at = [], None
                    return self.send(200, session.snapshot(), sid=sid)
                if session.job and session.job.status == "RUNNING":
                    return self.send(409, {"error": "Devam eden işlemin tamamlanmasını bekleyin."}, sid=sid)
                if path == "/api/connect":
                    config = Config.from_values(data)
                    return self.start(session, sid, "connect", config, [], session.window)
                elif path == "/api/health/import":
                    content = data.get("json", data.get("csv"))
                    if not isinstance(content, str) or len(content) > 262144:
                        raise ValueError("En fazla 256 KB JSON/CSV metni gerekli.")
                    if "json" in data and "csv" not in data:
                        rules, detections = read_config(content)
                    elif "csv" in data and "json" not in data:
                        rules, detections = read_csv_rules(content), []
                    else:
                        raise ValueError("Yalnız bir JSON veya CSV içeriği gerekli.")
                    session.health_rules, session.detections = rules, detections
                    session.health_results, session.health_checked_at = [], None
                    return self.send(200, session.snapshot(), sid=sid)
                elif path == "/api/health/config":
                    # Arayüz düzenleyicisi aynı dosya doğrulamasını kullanır.
                    if set(data) != {"checks", "detections"}:
                        raise ValueError("checks ve detections listeleri gerekli.")
                    if data == {"checks": [], "detections": []}:
                        rules, detections = [], []
                    else:
                        rules, detections = read_config(json.dumps(data, ensure_ascii=False))
                    session.health_rules, session.detections = rules, detections
                    session.health_results, session.health_checked_at = [], None
                    return self.send(200, session.snapshot(), sid=sid)
                elif path == "/api/health/check":
                    if session.config is None:
                        raise ValueError("Önce Splunk'a bağlanın.")
                    if not session.health_rules:
                        raise ValueError("Önce sağlık kontrollerini JSON ile yükleyin.")
                    return self.start(session, sid, "health", session.config, [], session.window)
                elif path == "/api/alerts/analyze":
                    if session.config is None:
                        raise ValueError("Önce Splunk'a bağlanın.")
                    window = window_value(data.get("window", session.window))
                    session.window = window
                    return self.start(session, sid, "alerts", session.config, [], window)
                elif path in {"/api/targets", "/api/import", "/api/check", "/api/discover"}:
                    window = window_value(data.get("window", 120))
                    if path == "/api/import":
                        content = data.get("csv")
                        if not isinstance(content, str):
                            raise ValueError("CSV metni gerekli.")
                        targets = read_targets(io.StringIO(content.lstrip("\ufeff"), newline=""), window)
                        if len(targets) > 500:
                            raise ValueError("En fazla 500 hedef kabul edilir.")
                    else:
                        targets = targets_value(data.get("targets"), window, path in {"/api/discover", "/api/targets"})
                    if path in {"/api/check", "/api/discover"} and session.config is None:
                        raise ValueError("Önce Splunk'a bağlanın.")
                    changed = targets != session.targets or window != session.window
                    session.targets, session.window = targets, window
                    if changed or path != "/api/targets":
                        session.reports, session.checked_at, session.job = [], None, None
                        session.diagnostics = {}
                    if path in {"/api/check", "/api/discover"}:
                        kind = "check" if path == "/api/check" else "discover"
                        return self.start(session, sid, kind, session.config, targets, window)
                else:
                    return self.send(404, {"error": "İşlem bulunamadı."}, sid=sid)
                return self.send(200, session.snapshot(), sid=sid)
        except (ValueError, csv.Error, UnicodeError) as exc:
            message = "İstek geçerli JSON değil." if isinstance(exc, json.JSONDecodeError) else str(exc)
            self.send(400, {"error": message}, sid=sid)
        except Exception:
            self.send(500, {"error": "İşlem tamamlanamadı."}, sid=sid)

    def start(self, session, sid, kind, config, targets, window):
        job = Job(kind, total=len(session.health_rules) if kind == "health" else len(targets) if kind == "check" else 0)
        session.job = job
        threading.Thread(target=run_job, args=(session, job, config, list(targets), window), daemon=True).start()
        return self.send(202, session.snapshot(), sid=sid)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SIEM Health & Log Coverage Monitor yerel arayüz")
    parser.add_argument("--port", type=int, default=8787, help="Yerel arayüz portu (varsayılan: 8787)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port 1–65535 arasında olmalı.")
    try:
        server = LocalServer(args.port)
    except OSError:
        print("Arayüz başlatılamadı. Port kullanımda olabilir; --port ile başka bir port seçin.")
        return 2
    print(f"Arayüz hazır: http://127.0.0.1:{args.port}", flush=True)
    print("Durdurmak için Ctrl+C. Giriş bilgileri yalnız oturum belleğinde tutulur.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for session in server.sessions.values():
            with session.lock:
                session.config = None
                if session.job:
                    session.job.cancel.set()
        server.server_close()
    return 0
