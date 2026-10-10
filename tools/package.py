"""Kimlik bilgisi ve yerel ortam içermeyen ZIP üretir."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


root = Path(__file__).resolve().parent.parent
files = [
    "checker.py", "healthcheck.py", "webapp.py", "README.md", "requirements.txt", ".env.example",
    ".gitignore", "targets.example.csv", "checks.example.csv", "checks.example.json", "docs/ARAYUZ_KULLANIM.md", "docs/arayuz.png", "docs/siem-guardian.png", "tools/package.py",
    "tests/test_checker.py", "tests/test_web.py", "tests/test_splunk_flow.py", "tests/test_health.py", "tests/test_guardian.py",
    "continuity/__init__.py", "continuity/cli.py", "continuity/core.py",
    "continuity/config.py", "continuity/splunk.py", "continuity/health.py", "continuity/dependencies.py", "continuity/notify.py", "continuity/web.py",
    "continuity/static/index.html", "continuity/static/style.css", "continuity/static/app.js",
]
output = root / "output" / "SIEM_Guardian.zip"
output.parent.mkdir(exist_ok=True)
with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=9) as archive:
    for name in files:
        archive.write(root / name, "siem-guardian/" + name)
with ZipFile(output) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(files)
print(f"Hazır: {output.name} ({len(files)} dosya, {output.stat().st_size} bayt)")
