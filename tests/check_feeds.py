#!/usr/bin/env python3
"""Check that every blocklist feed still downloads and is not empty.

Run by the weekly GitHub Actions health check (.github/workflows/health.yml) so that a
feed that moves or shuts down (e.g. HTTP 410) is noticed quickly.
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ["SAFE_URL_GUARD_CACHE"] = tempfile.mkdtemp()
os.environ.setdefault("SAFE_URL_GUARD_LANG", "en")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json  # noqa: E402

import safe_url_guard  # noqa: E402

MIN_DOMAINS = 10

safe_url_guard.update_feeds()
failed = []
for name in safe_url_guard.FEEDS:
    path = safe_url_guard.CACHE_DIR / f"{name}.json"
    n = len(json.loads(path.read_text())["hosts"]) if path.exists() else 0
    print(f"{name}: {n} domains")
    if n < MIN_DOMAINS:
        failed.append(name)
if failed:
    print(f"::error::Feed(s) broken or nearly empty: {', '.join(failed)}")
    sys.exit(1)
