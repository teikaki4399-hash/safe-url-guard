#!/usr/bin/env python3
"""domain_age - look up how long ago a domain was registered, via RDAP.

Many fake shops and fake investment sites start scamming right after the domain is
registered, then switch to a new domain once reported. "Registered only a few months
ago" is therefore an important warning sign (an old domain is not proof of safety).

RDAP (Registration Data Access Protocol, RFC 9082/9083) is the successor of WHOIS.
The server to query is taken from IANA's bootstrap file
(https://data.iana.org/rdap/dns.json, RFC 9224).

Usage:
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
from i18n import t

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
    """Find the RDAP server for the domain's ending (longest match)."""
    best, best_len = None, -1
    for tlds, urls in bootstrap.get("services", []):
        for tld in tlds:
            if (domain == tld or domain.endswith("." + tld)) and len(tld) > best_len:
                https = [u for u in urls if u.startswith("https://")]
                best, best_len = (https or urls)[0], len(tld)
    return best


def candidates(host: str):
    """a.b.example.co.jp -> co.jp, example.co.jp, ... shortest first (no Public Suffix List needed)."""
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
    """Return {domain, registered (ISO date), days, verdict (DANGER/WARN/OK/UNKNOWN), note}."""
    host = safe_url_guard.normalize_host(host)
    now = now or datetime.now(timezone.utc)
    try:
        bootstrap = bootstrap or load_bootstrap()
    except Exception as e:  # noqa: BLE001
        return {"domain": host, "verdict": "UNKNOWN", "note": t("da_no_bootstrap", e=e)}
    base = rdap_base(host, bootstrap)
    if not base:
        return {"domain": host, "verdict": "UNKNOWN",
                "note": t("da_no_tld")}
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
            return {"domain": host, "verdict": "UNKNOWN", "note": t("da_failed", e=e)}
        reg = registration_date(data)
        if not reg:
            return {"domain": dom, "verdict": "UNKNOWN", "note": t("da_no_date")}
        days = (now - reg).days
        verdict = "DANGER" if days < DANGER_DAYS else "WARN" if days < WARN_DAYS else "OK"
        return {"domain": dom, "registered": reg.date().isoformat(), "days": days, "verdict": verdict}
    return {"domain": host, "verdict": "UNKNOWN", "note": t("da_not_found", e=last_err)}


def describe(info: dict) -> str:
    if info["verdict"] == "UNKNOWN":
        return t("da_unknown", note=info["note"])
    msg = t("da_registered", d=info["domain"], date=info["registered"], days=info["days"])
    if info["verdict"] == "DANGER":
        return msg + t("da_danger")
    if info["verdict"] == "WARN":
        return msg + t("da_warn")
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
