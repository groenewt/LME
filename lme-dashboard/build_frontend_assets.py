#!/usr/bin/env python3
"""Rebuild pinned local frontend assets and verify every downloaded byte."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
LOCK = ROOT / "frontend-assets.lock.json"


def fetch(entry: dict, destination: Path) -> None:
    with urlopen(entry["source"], timeout=60) as response:
        payload = response.read(64 * 1024 * 1024 + 1)
    if len(payload) > 64 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
        raise RuntimeError("pinned frontend asset digest mismatch")
    destination.write_bytes(payload)


def main() -> int:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="lme-frontend-") as directory:
        temporary = Path(directory)
        cli = temporary / "tailwindcss"
        fetch(lock["assets"]["tailwindcss-cli"], cli)
        cli.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        alpine = temporary / "alpine-csp.min.js"
        fetch(lock["assets"]["alpine-csp"], alpine)
        vendor = ROOT / "static/vendor"
        vendor.mkdir(mode=0o755, exist_ok=True)
        shutil.copyfile(alpine, vendor / "alpine-csp.min.js")
        subprocess.run([
            str(cli), "-c", str(ROOT / "tailwind.config.js"),
            "-i", str(ROOT / "frontend.css"), "-o", str(ROOT / "static/app.css"), "--minify",
        ], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
