"""SIEM Guardian CLI giriş noktası."""

import argparse
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from continuity.config import Config
from continuity.core import CheckError
from continuity.health import RESULT_FIELDS, build_search, csv_bytes, load_config, run_checks
from continuity.dependencies import csv_bytes as detection_csv_bytes, evaluate_detections
from continuity.notify import issue_payload, send_issues
from continuity.splunk import SplunkClient, stamp


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SIEM Guardian")
    parser.add_argument("--checks", type=Path, default=Path("checks.json"), help="Beklenen kontrollerin JSON dosyası")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="Splunk bağlantı ayarları")
    parser.add_argument("--output", type=Path, help="CSV raporu yolu")
    parser.add_argument("--show-spl", action="store_true", help="Çalıştırılan SPL sorgularını terminale yaz")
    parser.add_argument("--notify", action="store_true", help="Sorun varsa yapılandırılmış webhook/e-posta bildirimi gönder")
    args = parser.parse_args(argv)
    client = None
    try:
        load_dotenv(args.env_file, override=False)
        rules, detections = load_config(args.checks)
        config = Config.from_env()
        if not config.verify_tls:
            print("UYARI: Lab ayarı nedeniyle TLS doğrulaması kapalı.", file=sys.stderr)
        client = SplunkClient(config)
        now = client.get_server_time()
        if args.show_spl:
            for rule in rules:
                print(f"SPL [{rule.name}]: {build_search(rule, now)}")
        results = run_checks(client, rules, now)
        output = args.output or Path("reports") / f"health-{now:%Y%m%dT%H%M%SZ}.csv"
        protected = {args.checks.resolve(), args.env_file.resolve(), Path("checks.example.json").resolve()}
        if output.suffix.lower() != ".csv" or output.resolve() in protected:
            raise ValueError("Rapor yolu ayrı bir .csv dosyası olmalı.")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(csv_bytes(results))
        detection_results = evaluate_detections(detections, results)
        if detection_results:
            detection_output = output.with_name(output.stem + "-detections.csv")
            detection_output.write_bytes(detection_csv_bytes(detection_results))
        print("Ölçüm (UTC): " + stamp(now))
        print(" | ".join(RESULT_FIELDS))
        for result in results:
            row = result.row()
            print(" | ".join(row[field] for field in RESULT_FIELDS))
        counts = Counter(result.status for result in results)
        print("Durumlar: " + ", ".join(f"{status}={counts[status]}" for status in ("OK", "ALERT", "NO_DATA", "QUIET", "INSUFFICIENT_BASELINE", "ERROR")))
        print(f"CSV raporu: {output}")
        for detection in detection_results:
            print(f"Detection {detection['technique']} / {detection['name']}: {detection['status']}"
                  + (f" — {detection['impact']}" if detection["impact"] else ""))
        if detection_results:
            print(f"Detection raporu: {detection_output}")
        if args.notify:
            delivered = send_issues(issue_payload(results, detection_results))
            print(f"Gönderilen bildirim kanalı: {delivered}")
        return 2 if counts["ERROR"] else (1 if counts["ALERT"] or counts["NO_DATA"] or
                                          any(value["status"] == "IMPAIRED" for value in detection_results) else 0)
    except (CheckError, ValueError) as exc:
        print(f"Kontrol hatası: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("Dosya okuma/yazma hatası; yolları ve izinleri kontrol edin.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Kontrol kesildi.", file=sys.stderr)
        return 130
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
