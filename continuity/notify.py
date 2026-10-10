"""Yalnız açık --notify seçimiyle sorun özetini webhook veya SMTP'ye yollar."""

import os
import smtplib
from email.message import EmailMessage
from urllib.parse import urlsplit

import requests

from .core import CheckError


def issue_payload(results, detections: list[dict]) -> dict:
    return {
        "tool": "SIEM Guardian",
        "health_issues": [{"name": result.rule.name, "status": result.status, "details": result.details}
                          for result in results if result.status in {"ALERT", "NO_DATA"}],
        "detection_issues": [{"name": value["name"], "technique": value["technique"],
                              "status": value["status"], "impact": value["impact"]}
                             for value in detections if value["status"] == "IMPAIRED"],
    }


def send_issues(payload: dict, environ=None) -> int:
    if not payload["health_issues"] and not payload["detection_issues"]:
        return 0
    env = os.environ if environ is None else environ
    webhook = env.get("GUARDIAN_WEBHOOK_URL", "").strip()
    smtp_host = env.get("GUARDIAN_SMTP_HOST", "").strip()
    if not webhook and not smtp_host:
        raise CheckError("Bildirim için GUARDIAN_WEBHOOK_URL veya GUARDIAN_SMTP_HOST ayarlayın.")
    delivered = 0
    if webhook:
        parts = urlsplit(webhook)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise CheckError("Webhook adresi geçerli bir HTTPS URL olmalı.")
        try:
            response = requests.post(webhook, json=payload, timeout=10)
            response.raise_for_status()
        except requests.RequestException:
            raise CheckError("Webhook bildirimi başarısız; adresi ve bağlantıyı kontrol edin.") from None
        delivered += 1
    if smtp_host:
        sender = env.get("GUARDIAN_EMAIL_FROM", "").strip()
        recipient = env.get("GUARDIAN_EMAIL_TO", "").strip()
        username = env.get("GUARDIAN_SMTP_USER", "").strip()
        password = env.get("GUARDIAN_SMTP_PASSWORD", "")
        if not sender or not recipient or not username or not password or any("\n" in x or "\r" in x for x in (sender, recipient)):
            raise CheckError("SMTP için gönderen, alıcı, kullanıcı ve parola gerekli.")
        try:
            port = int(env.get("GUARDIAN_SMTP_PORT", "587"))
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise CheckError("SMTP portu geçersiz.") from None
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = "SIEM Guardian: kapsama uyarısı"
        lines = ["SIEM Guardian kontrolünde sorun bulundu."]
        lines += [f"{item['name']}: {item['status']} — {item['details']}" for item in payload["health_issues"]]
        lines += [f"{item['technique']} / {item['name']}: {item['status']} — {item['impact']}" for item in payload["detection_issues"]]
        message.set_content("\n".join(lines))
        try:
            with smtplib.SMTP(smtp_host, port, timeout=10) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(message)
        except (OSError, smtplib.SMTPException):
            raise CheckError("E-posta bildirimi başarısız; SMTP ayarlarını kontrol edin.") from None
        delivered += 1
    return delivered
