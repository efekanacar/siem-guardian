"""Kimlik bilgisi ve yerel ortam içermeyen ZIP üretir."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


root = Path(__file__).resolve().parent.parent
files = [
    "checker.py", "webapp.py", "README.md", "requirements.txt", ".env.example",
    ".gitignore", "targets.example.csv", "docs/ARAYUZ_KULLANIM.md", "docs/arayuz.png", "tools/package.py",
    "tests/test_checker.py", "tests/test_web.py", "tests/test_splunk_flow.py",
    "continuity/__init__.py", "continuity/cli.py", "continuity/core.py",
    "continuity/config.py", "continuity/splunk.py", "continuity/web.py",
    "continuity/static/index.html", "continuity/static/style.css", "continuity/static/app.js",
]
output = root / "output" / "Splunk_Log_Continuity_Checker.zip"
output.parent.mkdir(exist_ok=True)
with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=9) as archive:
    for name in files:
        archive.write(root / name, "splunk-log-continuity-checker/" + name)
with ZipFile(output) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == len(files)
print(f"Hazır: {output.name} ({len(files)} dosya, {output.stat().st_size} bayt)")
