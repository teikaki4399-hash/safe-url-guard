#!/usr/bin/env python3
"""domain_age - 通过 RDAP 查询域名注册了多久。

很多假购物网站、假投资网站刚注册不久就开始骗人，被举报后又换新域名。
所以“注册不到几个月”是一个重要的警示信号（但老域名也不代表一定安全）。

RDAP（Registration Data Access Protocol, RFC 9082/9083）是 WHOIS 的
后继协议。查询哪个服务器，按 IANA 公布的 bootstrap 文件
(https://data.iana.org/rdap/dns.json, RFC 9224) 决定。

用法:
    python3 domain_age.py example.com https://shop.example.net/xxx
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import safe_url_guard

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE = safe_url_guard.CACHE_DIR / "rdap_dns.json"
DANGER_DAYS = 30
WARN_DAYS = 180


def _get_json(url: str):
    req = urllib.request.Request(url, headers={
        "User-Agent": safe_url_guard.USER_AGENT, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_bootstrap() -> dict:
    if BOOTSTRAP_CACHE.exists() and time.time() - BOOTSTRAP_CACHE.stat().st_mtime < 7 * 86400:
        return json.loads(BOOTSTRAP_CACHE.read_text(encoding="utf-8"))
    data = _get_json(BOOTSTRAP_URL)
    BOOTSTRAP_CACHE.parent.mkdir(parents=True, exist_ok=True)
    BOOTSTRAP_CACHE.write_text(json.dumps(data), encoding="utf-8")
    return data


def rdap_base(domain: str, bootstrap: dict) -> str | None:
    """按最长匹配找出该域名后缀对应的 RDAP 服务器"""
    best, best_len = None, -1
    for tlds, urls in bootstrap.get("services", []):
        for tld in tlds:
            if (domain == tld or domain.endswith("." + tld)) and len(tld) > best_len:
                https = [u for u in urls if u.startswith("https://")]
                best, best_len = (https or urls)[0], len(tld)
    return best


def candidates(host: str):
    """a.b.example.co.jp -> example.co.jp?, co.jp ... 从短到长尝试（不依赖 Public Suffix List）"""
    parts = host.split(".")
    for n in range(2, len(parts) + 1):
        yield ".".join(parts[-n:])


def registration_date(rdap: dict) -> datetime | None:
    for ev in rdap.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            s = ev["eventDate"].replace("Z", "+00:00")
            try:
                d = datetime.fromisoformat(s)
            except ValueError:
                return None
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


def check(host: str, bootstrap: dict | None = None, fetch=_get_json, now=None) -> dict:
    """返回 {domain, registered(ISO或None), days, verdict(DANGER/WARN/OK/UNKNOWN), note}"""
    host = safe_url_guard.normalize_host(host)
    now = now or datetime.now(timezone.utc)
    try:
        bootstrap = bootstrap or load_bootstrap()
    except Exception as e:  # noqa: BLE001
        return {"domain": host, "verdict": "UNKNOWN", "note": f"无法获取 RDAP 服务器列表: {e}"}
    base = rdap_base(host, bootstrap)
    if not base:
        return {"domain": host, "verdict": "UNKNOWN",
                "note": "IANA 的 RDAP 列表中没有这个域名后缀，请在 https://lookup.icann.org/ 或该后缀注册局的 WHOIS 上查询"}
    if not base.endswith("/"):
        base += "/"
    last_err = None
    for dom in candidates(host):
        try:
            data = fetch(base + "domain/" + dom)
        except urllib.error.HTTPError as e:
            last_err = e
            continue
        except Exception as e:  # noqa: BLE001
            return {"domain": host, "verdict": "UNKNOWN", "note": f"查询失败: {e}"}
        reg = registration_date(data)
        if not reg:
            return {"domain": dom, "verdict": "UNKNOWN", "note": "RDAP 数据中没有注册日期"}
        days = (now - reg).days
        verdict = "DANGER" if days < DANGER_DAYS else "WARN" if days < WARN_DAYS else "OK"
        return {"domain": dom, "registered": reg.date().isoformat(), "days": days, "verdict": verdict}
    return {"domain": host, "verdict": "UNKNOWN", "note": f"RDAP 中找不到该域名 ({last_err})"}


def describe(info: dict) -> str:
    if info["verdict"] == "UNKNOWN":
        return f"注册时间: 未知（{info['note']}）"
    msg = f"{info['domain']} 注册于 {info['registered']}（{info['days']} 天前）"
    if info["verdict"] == "DANGER":
        return msg + " ⚠ 注册不到 1 个月，非常可疑"
    if info["verdict"] == "WARN":
        return msg + " ⚠ 注册不到半年，请小心"
    return msg


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(__doc__)
        return 64
    worst = 0
    for a in args:
        info = check(safe_url_guard.host_of(a))
        print(f"{a}\n    {describe(info)}")
        worst = max(worst, {"OK": 0, "UNKNOWN": 0, "WARN": 1, "DANGER": 2}[info["verdict"]])
    return worst


if __name__ == "__main__":
    sys.exit(main())
