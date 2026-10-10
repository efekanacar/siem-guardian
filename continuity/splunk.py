"""Yalnız okuma SPL'si çalıştırır; tamamlanan search job sonuçlarını alır."""

import math
import hashlib
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from .config import Config
from .core import CheckError, NoData, Target, as_utc, validate_text


# Yalnız datetime dönüşümünün güvenlik sınırı; SPL'ye üst sınır olarak eklenmez.
MAX_EPOCH = 253402300799

# Keşif yalnız envanter içindir; geliş zamanı ölçümü ayrı ham olay sorgusudur.
DISCOVERY_SEARCH = (
    "| tstats count AS event_count WHERE index=* earliest=0 latest=now "
    "BY index host source sourcetype "
    "| stats sum(event_count) AS event_count values(source) AS sources BY index host sourcetype "
    "| sort 0 index host sourcetype"
)


class ManagementHTTPError(CheckError):
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Management API HTTP {status} döndürdü.")


def message_detail(text: str) -> tuple[str, bool]:
    """Ham Splunk mesajını yayımlamadan anlaşılır bir teşhis üretir."""
    categories = [
        (r"rawdata|corrupt|failed to read .*event.*bucket",
         "Splunk bazı bucket'lardaki ham olayları okuyamadı; sonuç eksik olabilir. İlgili search.log ve bucket sağlığını kontrol edin.", True),
        (r"partial|incomplete|truncat|skipp|search.?peer|peer.*(?:fail|unavail)|bucket.*(?:missing|reduc)",
         "Arama bazı verileri veya indexer'ları kapsamıyor. Splunk Search mesajlarını ve indexer erişimini kontrol edin.", True),
        (r"limit|exceed|memory|finaliz|maximum|timed? ?out",
         "Splunk arama limiti veya kaynak sınırı bildirdi. Arama yetkilerini, limitlerini ve timeout ayarını kontrol edin.", True),
        (r"permission|authoriz|forbidden|denied|license|licence",
         "Splunk yetki veya lisans uyarısı bildirdi. Hesabın index erişimini ve Splunk lisans durumunu kontrol edin.", True),
        (r"deprecated|deprecat",
         "Splunk kullanılan API veya özelliğin ileride kaldırılacağını bildirdi.", False),
        (r"time.*(?:range|bound)|(?:earliest|latest).*time|timestamp|invalid.*time",
         "Splunk zaman aralığı uyarısı bildirdi. Splunk Search ekranındaki arama zaman sınırlarını kontrol edin.", True),
    ]
    for pattern, detail, critical in categories:
        if re.search(pattern, text, re.IGNORECASE):
            return detail, critical
    return "Splunk bir uyarı bildirdi. Ayrıntı için Splunk Search işinin mesajlarını inceleyin.", False


def spl_string(value: str, field: str) -> str:
    validate_text(value, field)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_search(targets: list[Target], start: datetime, end: datetime) -> str:
    """Kontrol penceresindeki gelişleri toplar; tam üçlü eşleşme Python'dadır."""
    start, end = as_utc(start), as_utc(end)
    lower, upper = int(start.timestamp()), int(end.timestamp())
    if not targets or not 0 < lower < upper < MAX_EPOCH:
        raise CheckError("Arama hedefleri veya ölçüm zamanı geçersiz.")
    indexes = " OR ".join("index=" + spl_string(index, "index") for index in sorted({t.index for t in targets}))
    # Geniş event-time aralığı, yeni indekslenen eski/geç tarihli olayları tutar.
    # Index-time sınırları eski, bozuk bucket'ları ve gereksiz tüm zaman taramasını
    # dışlar. where üst sınırı kesin [start, end) biçimine getirir.
    return (
        f"search ({indexes}) earliest=0 latest=+10y "
        f"_index_earliest={lower} _index_latest={upper} "
        f"| eval arrival_epoch=_indextime | where arrival_epoch>={lower} AND arrival_epoch<{upper} "
        "| stats count AS matched_count max(arrival_epoch) AS last_seen_epoch "
        "BY index host sourcetype"
    )


def reject_messages(payload: dict, warnings: list[str] | None = None) -> None:
    messages = payload.get("messages", [])
    if not isinstance(messages, list):
        raise CheckError("Splunk mesaj yapısı geçersiz.")
    for message in messages:
        if not isinstance(message, dict):
            raise CheckError("Splunk mesaj yapısı geçersiz.")
        severity = str(message.get("type", "")).upper()
        if severity in {"INFO", "DEBUG"}:
            continue
        text = message.get("text", "")
        if not isinstance(text, str):
            raise CheckError("Splunk mesaj metni geçersiz.")
        detail, critical = message_detail(text)
        if severity in {"WARN", "WARNING"}:
            if warnings is not None and not critical:
                if detail not in warnings:
                    warnings.append(detail)
                continue
            raise CheckError("Splunk arama uyarısı: " + detail + " Sonuç güvenilir kabul edilmedi.")
        if severity in {"ERROR", "FATAL"}:
            raise CheckError("Splunk araması başarısız: " + detail)
        raise CheckError("Splunk mesaj seviyesi geçersiz; sonuç güvenilir kabul edilmedi.")


def flag(value, field: str) -> bool:
    if value in (True, 1, "1"):
        return True
    if value in (False, 0, "0"):
        return False
    raise CheckError(f"Splunk {field} bayrağı geçersiz.")


def number(value, *, count=False) -> float:
    try:
        n = float(value)
        if not math.isfinite(n) or n < 0 or (count and not n.is_integer()):
            raise ValueError
        return n
    except (TypeError, ValueError):
        raise CheckError("Splunk indekslenme zamanı/sayacı geçersiz.") from None


def stamp(value) -> str:
    return value.isoformat().replace("+00:00", "Z") if value else ""


@dataclass(frozen=True)
class Arrival:
    last_seen: datetime
    matched_count: int


def parse_results(payload: dict, end: datetime) -> dict[tuple[str, str, str], Arrival | CheckError]:
    reject_messages(payload)
    if "preview" in payload and flag(payload["preview"], "preview"):
        raise CheckError("Tamamlanmamış arama sonucu alındı.")
    rows = payload.get("results")
    if not isinstance(rows, list):
        raise CheckError("Splunk sonuç listesi geçersiz.")
    found = {}
    for row in rows:
        try:
            key = tuple(row[field] for field in ("index", "host", "sourcetype"))
            for value in key:
                validate_text(value, "name")
            if key in found:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise CheckError("Splunk hedef alanları eksik, geçersiz veya yinelenmiş; sonuç kabul edilmedi.") from None
        try:
            matched = number(row["matched_count"], count=True)
            if matched == 0:
                raise CheckError("Splunk olay sayacı tutarsız.")
            last = datetime.fromtimestamp(number(row["last_seen_epoch"]), timezone.utc)
            if last >= as_utc(end):
                raise CheckError("Splunk son geliş zamanı ölçüm sınırı/sayacıyla tutarsız.")
            found[key] = Arrival(last, int(matched))
        except CheckError as exc:
            found[key] = exc
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            found[key] = CheckError("Splunk indekslenme zamanı/sayacı geçersiz.")
    return found


class SplunkClient:
    def __init__(self, config: Config):
        self.config = config
        self.discovery_sources: list[dict] = []
        self.discovery_warnings: list[str] = []
        self.results_prefix = "/services/search/v2/jobs/"
        self.check_diagnostics: dict = {}
        self.last_job: dict = {}
        self.snapshot = None
        self.snapshot_window = None
        self.snapshot_indexes: set[str] = set()
        self.session = requests.Session()
        # .netrc kimlik bilgisini ve ortam proxy'sini otomatik kullanma.
        self.session.trust_env = False
        if config.token:
            self.session.headers["Authorization"] = f"Bearer {config.token}"
        else:
            self.session.auth = (config.username, config.password)

    def close(self) -> None:
        self.session.close()

    def request(self, method: str, path: str, deadline: float, *, warnings=None, **kwargs) -> dict:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CheckError("Arama zaman aşımına uğradı.")
        timeout = min(self.config.http_timeout, remaining)
        try:
            response = self.session.request(
                method, self.config.base_url + path, timeout=timeout,
                verify=self.config.verify_tls, allow_redirects=False, **kwargs,
            )
            # Deadline yanıt geldikten sonra da kontrol edilir. requests timeout
            # bağlantı/okuma beklemesidir; katı process wall-clock kesmesi değildir.
            if time.monotonic() >= deadline:
                raise CheckError("Arama zaman aşımına uğradı.")
            if not 200 <= response.status_code < 300:
                raise ManagementHTTPError(response.status_code)
            payload = response.json()
        except requests.exceptions.SSLError:
            raise CheckError("TLS doğrulaması/bağlantısı başarısız; CA ayarını kontrol edin.") from None
        except requests.exceptions.Timeout:
            raise CheckError("HTTP isteği zaman aşımına uğradı.") from None
        except requests.exceptions.RequestException:
            raise CheckError("Management API bağlantısı başarısız.") from None
        except ValueError:
            raise CheckError("Management API geçerli JSON döndürmedi.") from None
        if not isinstance(payload, dict):
            raise CheckError("Management API yanıt yapısı geçersiz.")
        reject_messages(payload, warnings)
        return payload

    def get_server_time(self) -> datetime:
        """Kontrol penceresi istemci saati yerine Splunk search head saatini kullanır."""
        payload = self.run_search("| makeresults | eval server_now=now() | fields server_now")
        try:
            rows = payload["results"]
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                raise ValueError
            epoch = float(rows[0]["server_now"])
            if not math.isfinite(epoch) or not 0 < epoch < MAX_EPOCH:
                raise ValueError
            return datetime.fromtimestamp(math.floor(epoch), timezone.utc)
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            raise CheckError("Splunk ölçüm saati alınamadı; kontrol başlatılmadı.") from None

    def prepare_check(self, targets: list[Target], start: datetime, end: datetime) -> None:
        start, end = as_utc(start), as_utc(end)
        if not 0 < start.timestamp() < end.timestamp():
            raise CheckError("Kontrol zaman sınırları geçersiz.")
        self.snapshot, self.snapshot_window = None, None
        self.snapshot_indexes = set()
        search = build_search(targets, start, end)
        self.check_diagnostics = {"measurement_utc": stamp(end), "window_start_utc": stamp(start),
                                  "window_end_utc": stamp(end), "search": search,
                                  "expected_targets": len(targets), "returned_rows": None,
                                  "matched_targets": None, "sources": [], "error": ""}
        try:
            payload = self.run_search(search)
            if payload.get("results") == [] and self.last_job.get("eventCount", 0) > 0:
                raise CheckError("Splunk olay buldu ancak index/host/sourcetype özeti boş; veri işleme hatası, NO_DATA kabul edilmedi.")
            self.snapshot = parse_results(payload, end)
        except CheckError as exc:
            self.check_diagnostics.update(error=str(exc), job=dict(self.last_job))
            raise
        self.snapshot_window = (start, end)
        self.snapshot_indexes = {t.index for t in targets}
        expected = [(t.index, t.host, t.sourcetype) for t in targets]
        sources = []
        for key, value in self.snapshot.items():
            sources.append(dict(zip(("index", "host", "sourcetype"), key),
                                last_before_check_utc=stamp(value.last_seen) if isinstance(value, Arrival) else "",
                                matched_events=value.matched_count if isinstance(value, Arrival) else None,
                                error=str(value) if isinstance(value, CheckError) else ""))
        self.check_diagnostics.update(returned_rows=len(self.snapshot),
            matched_targets=sum(key in self.snapshot for key in expected), sources=sources, job=dict(self.last_job))

    def fetch_latest(self, target: Target, start: datetime, end: datetime) -> datetime | NoData:
        start, end = as_utc(start), as_utc(end)
        if self.snapshot_window != (start, end) or self.snapshot is None or target.index not in self.snapshot_indexes:
            self.prepare_check([target], start, end)
        value = self.snapshot.get((target.index, target.host, target.sourcetype))
        if isinstance(value, CheckError):
            raise value
        if value is None:
            other_indexes = sorted({index for (index, host, sourcetype), result in self.snapshot.items()
                                    if host == target.host and sourcetype == target.sourcetype
                                    and index != target.index and isinstance(result, Arrival)})
            if other_indexes:
                return NoData("Bu host/sourcetype kontrol penceresinde başka index'te görüldü: "
                              + ", ".join(other_indexes[:3]) + ". Hedef index değerini doğrulayın.")
            same_host = any(host == target.host and isinstance(result, Arrival)
                            for (_, host, _), result in self.snapshot.items())
            if same_host:
                return NoData("Bu hosttan başka loglar geliyor; beklenen sourcetype bu kontrol penceresinde görünmedi. Kanalı, düşük hacmi ve hedef alanlarını doğrulayın.")
            return NoData("Bu hosttan kontrol penceresinde hedef indexlerde log görünmedi. Makine açık olsa bile forwarder, yönlendirme, index yetkisi veya zaman aralığı etkili olabilir.")
        last = value.last_seen
        if last >= start:
            return last
        window = (end - start).total_seconds() / 60
        delay = (end - last).total_seconds() / 60
        return NoData(f"Görünür son geliş: {stamp(last)} ({delay:.1f} dakika önce). Kontrol aralığı {window:g} dakika; son geliş aralığın dışında.")

    def test_connection(self) -> None:
        payload = self.request("GET", "/services/authentication/current-context",
                               time.monotonic() + self.config.http_timeout,
                               params={"output_mode": "json"})
        try:
            username = payload["entry"][0]["content"]["username"]
            if not isinstance(username, str) or not username:
                raise ValueError
        except (KeyError, IndexError, TypeError, ValueError):
            raise CheckError("Splunk kimlik doğrulama yanıtı geçersiz.") from None

    def discover_targets(self, threshold: float = 30) -> list[Target]:
        self.discovery_sources = []
        self.discovery_warnings = []
        payload = self.run_search(DISCOVERY_SEARCH, warnings=self.discovery_warnings)
        rows = payload.get("results")
        if not isinstance(rows, list):
            raise CheckError("Hedef keşif sonucu geçersiz.")
        if len(rows) > 500:
            raise CheckError("500'den fazla birleşim bulundu. İzlenecek hedefleri CSV ile seçin.")
        targets = []
        seen = set()
        for row in rows:
            try:
                if not isinstance(row, dict):
                    raise ValueError
                values = tuple(row[field] for field in ("index", "host", "sourcetype"))
                if any(not isinstance(value, str) for value in values):
                    raise ValueError
                if values in seen:
                    raise ValueError
                count = float(row["event_count"])
                if not math.isfinite(count) or count < 1 or not count.is_integer():
                    raise ValueError
                sources = row.get("sources", [])
                if isinstance(sources, str):
                    sources = [sources]
                if not isinstance(sources, list) or any(not isinstance(s, str) or not s or len(s) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in s) for s in sources):
                    raise ValueError
                name = " / ".join(values)
                if len(name) > 256:
                    name = name[:239] + "-" + hashlib.sha256(name.encode()).hexdigest()[:16]
                targets.append(Target(name, *values, threshold))
                self.discovery_sources.append(dict(zip(("index", "host", "sourcetype"), values), sources=sorted(set(sources)), event_count=int(count)))
                seen.add(values)
            except (KeyError, TypeError, ValueError):
                raise CheckError("Keşif sonucu geçersiz hedef alanları içeriyor; CSV ile tanımlayın.") from None
        return targets

    def run_search(self, search: str, *, warnings=None) -> dict:
        """Uygulamanın oluşturduğu okuma SPL'sini tamamlanana kadar bekler."""
        self.last_job = {}
        deadline = time.monotonic() + self.config.search_timeout
        created = self.request("POST", "/services/search/jobs", deadline, warnings=warnings, data={
            "search": search,
            "output_mode": "json",
            "exec_mode": "normal",
            "max_time": str(math.ceil(self.config.search_timeout)),
            "status_buckets": "0",
            "adhoc_search_level": "verbose",
            "allow_partial_results": "false",
        })
        reject_messages(created, warnings)
        sid = created.get("sid")
        if not isinstance(sid, str) or not sid or len(sid) > 1024:
            raise CheckError("Splunk geçerli arama kimliği döndürmedi.")
        self.last_job = {"sid": sid}
        job_path = "/services/search/jobs/" + quote(sid, safe="")
        while True:
            state = self.request("GET", job_path, deadline, warnings=warnings, params={"output_mode": "json"})
            reject_messages(state, warnings)
            try:
                content = state["entry"][0]["content"]
                if not isinstance(content, dict):
                    raise TypeError
                done = flag(content["isDone"], "isDone")
                dispatch = content["dispatchState"]
                failed = flag(content["isFailed"], "isFailed")
            except (KeyError, IndexError, TypeError):
                raise CheckError("Splunk arama durumu geçersiz.") from None
            reject_messages(content, warnings)
            self.last_job["dispatch_state"] = dispatch if dispatch in {"DONE", "RUNNING", "FAILED", "INTERNAL_CANCEL", "QUEUED", "PARSING", "FINALIZING"} else "UNKNOWN"
            if (failed or dispatch in {"FAILED", "INTERNAL_CANCEL"}
                    or flag(content.get("isFinalized", False), "isFinalized")
                    or flag(content.get("isZombie", False), "isZombie")):
                raise CheckError("Splunk araması başarısız veya erken sonlandırılmış.")
            if done:
                if dispatch != "DONE":
                    raise CheckError("Splunk araması normal tamamlanmadı.")
                for name in ("resultCount", "scanCount", "eventCount"):
                    if name in content:
                        self.last_job[name] = int(number(content[name], count=True))
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CheckError("Arama tamamlanmadan zaman aşımına uğradı.")
            time.sleep(min(self.config.poll_interval, remaining))
        results_path = self.results_prefix + quote(sid, safe="") + "/results"
        try:
            result = self.request("GET", results_path, deadline, warnings=warnings,
                                  params={"output_mode": "json", "count": "0"})
        except ManagementHTTPError as exc:
            # Eski Splunk kurulumları için yalnız endpoint yoksa geri dön.
            # Yetki, timeout veya TLS hatasında endpoint değiştirerek hatayı gizleme.
            if exc.status not in {404, 405} or self.results_prefix != "/services/search/v2/jobs/":
                raise
            self.results_prefix = "/services/search/jobs/"
            result = self.request("GET", job_path + "/results", deadline, warnings=warnings,
                                  params={"output_mode": "json", "count": "0"})
        reject_messages(result, warnings)
        if "preview" in result and flag(result["preview"], "preview"):
            raise CheckError("Tamamlanmamış arama sonucu alındı.")
        rows = result.get("results")
        if not isinstance(rows, list):
            raise CheckError("Splunk sonuç listesi geçersiz.")
        self.last_job["returned_rows"] = len(rows)
        self.last_job["results_endpoint"] = self.results_prefix + "{sid}/results"
        if "resultCount" in self.last_job and self.last_job["resultCount"] != len(rows):
            raise CheckError("Splunk işi sonuç üretti, ancak API'den alınan satır sayısı uyuşmuyor; NO_DATA kabul edilmedi.")
        return result
