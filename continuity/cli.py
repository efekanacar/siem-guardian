"""Manuel CLI: Splunk management API üzerinden kontrol."""

import argparse
import csv
import os
import sys
from datetime import timedelta
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from .config import Config
from .core import CheckError, check_targets, load_targets, table, write_csv
from .splunk import SplunkClient


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Splunk Log Continuity Checker")
    parser.add_argument("--targets", type=Path, help="Hedef CSV (varsayılan: targets.csv)")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help=".env dosyası")
    parser.add_argument("--window-minutes", type=int, help="Kontrol aralığı; tüm eşiklerden uzun olmalı")
    parser.add_argument("--output", type=Path, help="CSV rapor yolu; varsayılan reports/ altında zaman damgalı")
    args = parser.parse_args(argv)
    client = None
    try:
        load_dotenv(args.env_file, override=False)
        try:
            window = args.window_minutes if args.window_minutes is not None else int(os.getenv("CHECK_WINDOW_MINUTES", "120"))
        except ValueError:
            raise ValueError("CHECK_WINDOW_MINUTES tam sayı olmalı.") from None
        if not 1 <= window <= 525600:
            raise ValueError("Kontrol aralığı 1–525600 dakika olmalı.")
        targets_path = args.targets or Path("targets.csv")
        targets = load_targets(targets_path, window)
        config = Config.from_env()
        if config.verify_tls is False:
            print("UYARI: Lab ayarı SPLUNK_VERIFY_TLS=false; TLS doğrulaması kapalı.", file=sys.stderr)
        client = SplunkClient(config)
        fetch = client.fetch_latest
        # Bütün hedefler için Splunk'tan alınmış aynı UTC ölçüm zamanı/pencere.
        now = client.get_server_time()
        client.prepare_check(targets, now - timedelta(minutes=window), now)
        output = args.output or Path("reports") / f"report-{now:%Y%m%dT%H%M%SZ}.csv"
        # Kaynak hedef dosyasının yanlışlıkla raporla ezilmesini engelle.
        protected = {targets_path.resolve(), args.env_file.resolve(), Path("targets.example.csv").resolve()}
        if output.suffix.lower() != ".csv" or output.resolve() in protected:
            raise ValueError("--output ayrı bir .csv rapor dosyası olmalı.")
        reports = check_targets(targets, fetch, now, window)
        print(f"Ölçüm (UTC): {now.isoformat()} | Kontrol aralığı: {window} dakika")
        print(table(reports))
        counts = Counter(report.status for report in reports)
        print("Durumlar: " + ", ".join(f"{status}={counts[status]}" for status in ("OK", "DELAYED", "NO_DATA", "ERROR")))
        for position, report in enumerate(reports, 1):
            if report.error:
                print(f"Hedef #{position} ERROR: {report.error}", file=sys.stderr)
            if report.note:
                print(f"Hedef #{position}: {report.note}")
        write_csv(output, reports)
        print(f"CSV raporu: {output}")
        print("NO_DATA: bu aralıkta veri yok; kaynağın durduğu kesin olarak söylenemez.")
        return 2 if counts["ERROR"] else (1 if counts["DELAYED"] or counts["NO_DATA"] else 0)
    except CheckError as exc:
        print(f"Splunk hatası: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Yapılandırma hatası: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, csv.Error):
        print("Dosya okuma/yazma hatası; yolları, kodlamayı ve izinleri kontrol edin.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Kontrol kullanıcı tarafından kesildi.", file=sys.stderr)
        return 130
    finally:
        if client is not None:
            client.close()
