#!/usr/bin/env python3
"""qr_check - 读取二维码图片里的网址，先检查再决定要不要打开（防扫码诈骗）。

需要 OpenCV:  pip install opencv-python-headless

用法:
    python3 qr_check.py 图片.png [图片2.jpg ...]
    python3 qr_check.py --online 图片.png     # 同时查询网址的注册时间
"""

from __future__ import annotations

import argparse
import sys

import safe_url_guard


def decode(path: str) -> list[str]:
    try:
        import cv2
    except ImportError:
        sys.exit("需要 OpenCV，请先运行: pip install opencv-python-headless")
    img = cv2.imread(path)
    if img is None:
        raise ValueError(f"无法读取图片: {path}")
    det = cv2.QRCodeDetector()
    ok, texts, _pts, _ = det.detectAndDecodeMulti(img)
    out = [t for t in (texts if ok else []) if t]
    if not out:
        t, _pts, _ = det.detectAndDecode(img)
        if t:
            out = [t]
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="读取二维码并检查其中的网址")
    p.add_argument("images", nargs="+")
    p.add_argument("--online", action="store_true", help="查询网址的注册时间 (RDAP)")
    a = p.parse_args(argv)

    db, stale = safe_url_guard.load_blocklist()
    if stale:
        print("※ 黑名单未下载或已过期，请先运行: python3 safe_url_guard.py update\n",
              file=sys.stderr)
    allow = safe_url_guard.read_domain_file(safe_url_guard.ALLOWLIST_FILE)
    worst = 0
    for img in a.images:
        try:
            texts = decode(img)
        except ValueError as e:
            print(f"[错误] {e}")
            continue
        if not texts:
            print(f"{img}: 没有识别到二维码")
            continue
        for t in texts:
            print(f"{img}: 二维码内容 → {t}")
            if "://" not in t and not t.lower().startswith("www."):
                print("    （不是网址，未检查）")
                continue
            verdict, reasons = safe_url_guard.check_url(t, db, allow)
            print(f"    [{safe_url_guard.LABEL[verdict]}]")
            for r in reasons:
                print(f"    - {r}")
            if a.online:
                import domain_age
                print(f"    - {domain_age.describe(domain_age.check(safe_url_guard.host_of(t)))}")
            worst = max(worst, {"OK": 0, "WARN": 1, "DANGER": 2}[verdict])
    return worst


if __name__ == "__main__":
    sys.exit(main())
