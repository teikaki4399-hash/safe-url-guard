#!/usr/bin/env python3
"""qr_check - read the URL inside a QR-code image and check it before you open it.

Requires OpenCV:  pip install opencv-python-headless

Usage:
    python3 qr_check.py image.png [image2.jpg ...]
    python3 qr_check.py --online image.png     # also look up the URL's registration date
"""

from __future__ import annotations

import argparse
import sys

import safe_url_guard
from i18n import t


def decode(path: str) -> list[str]:
    try:
        import cv2
    except ImportError:
        sys.exit(t("qr_need_cv"))
    img = cv2.imread(path)
    if img is None:
        raise ValueError(t("qr_cant_read", p=path))
    det = cv2.QRCodeDetector()
    ok, texts, _pts, _ = det.detectAndDecodeMulti(img)
    out = [x for x in (texts if ok else []) if x]
    if not out:
        single, _pts, _ = det.detectAndDecode(img)
        if single:
            out = [single]
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=t("qr_desc"))
    p.add_argument("images", nargs="+")
    p.add_argument("--online", action="store_true", help=t("qr_online"))
    a = p.parse_args(argv)

    db, stale = safe_url_guard.load_blocklist()
    if stale:
        print(t("stale"), file=sys.stderr)
    allow = safe_url_guard.read_domain_file(safe_url_guard.ALLOWLIST_FILE)
    worst = 0
    for img in a.images:
        try:
            texts = decode(img)
        except ValueError as e:
            print(t("qr_error", e=e))
            continue
        if not texts:
            print(t("qr_none", img=img))
            continue
        for text in texts:
            print(t("qr_content", img=img, t=text))
            if "://" not in text and not text.lower().startswith("www."):
                print(t("qr_not_url"))
                continue
            verdict, reasons = safe_url_guard.check_url(text, db, allow)
            print(f"    [{safe_url_guard.label(verdict)}]")
            for r in reasons:
                print(f"    - {r}")
            if a.online:
                import domain_age
                print(f"    - {domain_age.describe(domain_age.check(safe_url_guard.host_of(t)))}")
            worst = max(worst, {"OK": 0, "WARN": 1, "DANGER": 2}[verdict])
    return worst


if __name__ == "__main__":
    sys.exit(main())
