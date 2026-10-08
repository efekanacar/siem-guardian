""".env üzerinden bağlantı ayarları; gizli değerler repr içinde gösterilmez."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .core import positive_number


@dataclass(frozen=True)
class Config:
    base_url: str
    token: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    verify_tls: bool | str
    http_timeout: float
    search_timeout: float
    poll_interval: float

    @classmethod
    def from_env(cls):
        return cls.from_values({
            key: os.getenv(key, default) for key, default in {
                "SPLUNK_BASE_URL": "https://192.168.3.131:8089",
                "SPLUNK_TOKEN": "", "SPLUNK_USERNAME": "", "SPLUNK_PASSWORD": "",
                "SPLUNK_VERIFY_TLS": "true", "SPLUNK_CA_BUNDLE": "",
                "HTTP_TIMEOUT_SECONDS": "10", "SEARCH_TIMEOUT_SECONDS": "60",
                "POLL_INTERVAL_SECONDS": "1",
            }.items()
        })

    @classmethod
    def from_values(cls, values: dict[str, str]):
        """CLI ortamından veya arayüz formundan aynı doğrulamayı kullanır."""
        if not isinstance(values, dict) or any(not isinstance(v, str) for v in values.values()):
            raise ValueError("Bağlantı ayarları metin olmalı.")
        base_url = values.get("SPLUNK_BASE_URL", "https://192.168.3.131:8089").strip().rstrip("/")
        try:
            url = urlsplit(base_url)
            port = url.port
        except ValueError:
            raise ValueError("SPLUNK_BASE_URL geçersiz.") from None
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or url.path or port == 8000):
            raise ValueError("SPLUNK_BASE_URL: kimlik bilgisi içermeyen HTTPS management adresi gerekli; :8000 kullanılamaz.")
        token = values.get("SPLUNK_TOKEN", "").strip()
        username = values.get("SPLUNK_USERNAME", "").strip()
        password = values.get("SPLUNK_PASSWORD", "")
        if not token and not (username and password):
            raise ValueError("Token veya kullanıcı adı/parola gerekli.")
        if any(char in token + username + password for char in "\r\n"):
            raise ValueError("Kimlik bilgilerinde satır sonu kullanılamaz.")
        tls = values.get("SPLUNK_VERIFY_TLS", "true").strip().lower()
        if tls not in {"true", "false"}:
            raise ValueError("SPLUNK_VERIFY_TLS true veya false olmalı.")
        ca_bundle = values.get("SPLUNK_CA_BUNDLE", "").strip()
        if ca_bundle and (tls == "false" or not Path(ca_bundle).is_file()):
            raise ValueError("SPLUNK_CA_BUNDLE: mevcut bir dosya ve TLS doğrulaması gerekli.")
        return cls(
            base_url, token, username, password, ca_bundle or tls == "true",
            positive_number(values.get("HTTP_TIMEOUT_SECONDS", "10"), "HTTP_TIMEOUT_SECONDS"),
            positive_number(values.get("SEARCH_TIMEOUT_SECONDS", "60"), "SEARCH_TIMEOUT_SECONDS"),
            positive_number(values.get("POLL_INTERVAL_SECONDS", "1"), "POLL_INTERVAL_SECONDS"),
        )
