#!/usr/bin/env python3
"""safe_url_guard - check URLs before opening them, to avoid malware and scam (phishing) sites.

Python standard library only (Python 3.8+).

Usage:
    python3 safe_url_guard.py update            # download / update the public blocklists
    python3 safe_url_guard.py check URL [...]   # check URLs
    python3 safe_url_guard.py open URL          # open in the browser only if the check passes
    python3 safe_url_guard.py hosts > block.txt # print the blocklist in hosts-file format
    python3 safe_url_guard.py lang zh           # switch the language (en / zh)

Blocklist sources (public, free):
    - OpenPhish Community : phishing sites              https://openphish.com/
    - HaGeZi TIF (mini)   : malware / phishing / scam   https://github.com/hagezi/dns-blocklists (GPL-3.0)
    - built-in list       : confirmed scam sites        extension/builtin_blocklist.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

from i18n import t

FEEDS = {
    # URLhaus (abuse.ch) was removed in Nov 2026: all of its public download URLs
    # (hostfile, text_online, text_recent, csv_online, rpz) now return HTTP 410 Gone.
    # one URL per line
    "openphish": ("https://openphish.com/feed.txt", "urls"),
    # HaGeZi Threat Intelligence Feeds, mini version (malware, phishing, scam domains;
    # GPL-3.0; the header says it expires after 8 hours). One domain per line; subdomains are covered.
    "hagezi_tif": ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", "domains"),
}

CACHE_DIR = Path(os.environ.get("SAFE_URL_GUARD_CACHE",
                                Path.home() / ".cache" / "safe_url_guard"))
STALE_SECONDS = 24 * 60 * 60  # lists older than 24 hours count as stale
USER_AGENT = "safe-url-guard/1.0"

# local allowlist / custom denylist (one domain per line, # starts a comment)
ALLOWLIST_FILE = CACHE_DIR / "allowlist.txt"
DENYLIST_FILE = CACHE_DIR / "denylist.txt"
# built-in list of confirmed scam sites, shared with the browser extension
BUILTIN_BLOCKLIST = Path(__file__).resolve().parent / "extension" / "builtin_blocklist.txt"


# ---------------------------------------------------------------- helpers
def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def host_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return normalize_host(urlsplit(url).hostname or "")


def parent_domains(host: str):
    """a.b.example.com -> a.b.example.com, b.example.com, example.com"""
    parts = host.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


def read_domain_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(normalize_host(line))
    return out


# ---------------------------------------------------------------- blocklists
def parse_feed(text: str, kind: str) -> set[str]:
    hosts = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind == "hosts":
            parts = line.split()
            if len(parts) >= 2:
                hosts.add(normalize_host(parts[1]))
        else:
            h = host_of(line)
            if h:
                hosts.add(h)
    hosts.discard("localhost")
    return hosts


def update_feeds() -> int:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ok = 0
    for name, (url, kind) in FEEDS.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            hosts = parse_feed(text, kind)
            (CACHE_DIR / f"{name}.json").write_text(
                json.dumps({"updated": time.time(), "source": url,
                            "hosts": sorted(hosts)}), encoding="utf-8")
            print(t("feed_ok", name=name, n=len(hosts)))
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(t("feed_fail", name=name, err=e), file=sys.stderr)
    return 0 if ok else 1


def load_blocklist() -> tuple[dict[str, str], bool]:
    """Return ({domain: source}, whether any list is stale or missing)."""
    db: dict[str, str] = {}
    stale = False
    for name in FEEDS:
        path = CACHE_DIR / f"{name}.json"
        if not path.exists():
            stale = True
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("updated", 0) > STALE_SECONDS:
            stale = True
        for h in data.get("hosts", []):
            db.setdefault(h, name)
    for h in read_domain_file(BUILTIN_BLOCKLIST):
        db[h] = t("src_builtin")
    for h in read_domain_file(DENYLIST_FILE):
        db[h] = t("src_custom")
    return db, stale


# ---------------------------------------------------------------- heuristics
def heuristics(url: str) -> list[str]:
    """Common suspicious traits. A hit does not prove the site is malicious; it is a warning."""
    warn = []
    raw = url if "://" in url else "http://" + url
    parts = urlsplit(raw)
    host = parts.hostname or ""

    if parts.scheme == "http":
        warn.append(t("h_http"))
    try:
        ipaddress.ip_address(host)
        warn.append(t("h_ip"))
    except ValueError:
        pass
    if "xn--" in host or not host.isascii():
        warn.append(t("h_idn"))
    if parts.username or "@" in parts.netloc:
        warn.append(t("h_at"))
    if host.count(".") >= 4:
        warn.append(t("h_sub"))
    if len(raw) > 200:
        warn.append(t("h_long"))
    if parts.port and parts.port not in (80, 443):
        warn.append(t("h_port", port=parts.port))
    return warn


# ---------------------------------------------------------------- verdict
def check_url(url: str, db: dict[str, str], allow: set[str]) -> tuple[str, list[str]]:
    """Return (verdict, reasons). verdict is DANGER / WARN / OK."""
    host = host_of(url)
    if not host:
        return "DANGER", [t("bad_host")]
    if any(d in allow for d in parent_domains(host)) or host in allow:
        return "OK", [t("allowlisted")]
    for d in [host, *parent_domains(host)]:
        if d in db:
            return "DANGER", [t("blocklisted", d=d, src=db[d])]
    warn = heuristics(url)
    return ("WARN", warn) if warn else ("OK", [t("no_threat")])


def label(verdict: str) -> str:
    return t("label_" + verdict)


def cmd_check(urls: list[str]) -> int:
    db, stale = load_blocklist()
    if stale:
        print(t("stale"), file=sys.stderr)
    allow = read_domain_file(ALLOWLIST_FILE)
    worst = 0
    for url in urls:
        verdict, reasons = check_url(url, db, allow)
        print(f"[{label(verdict)}] {url}")
        for r in reasons:
            print(f"    - {r}")
        worst = max(worst, {"OK": 0, "WARN": 1, "DANGER": 2}[verdict])
    return worst  # exit code: 0=OK 1=WARNING 2=DANGER


def cmd_open(url: str, force: bool) -> int:
    code = cmd_check([url])
    if code == 2:
        print(t("open_blocked"))
        return 2
    if code == 1 and not force:
        ans = input(t("open_ask")).strip().lower()
        if ans != "y":
            print(t("cancelled"))
            return 1
    webbrowser.open(url if "://" in url else "https://" + url)
    return 0


def cmd_hosts() -> int:
    db, stale = load_blocklist()
    if stale:
        print(t("hosts_stale"), file=sys.stderr)
    print(t("hosts_header"))
    for h in sorted(db):
        try:
            ipaddress.ip_address(h)
            continue  # a hosts file cannot block IP addresses
        except ValueError:
            print(f"0.0.0.0 {h}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=t("cli_desc"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("update", help=t("cli_update"))
    c = sub.add_parser("check", help=t("cli_check"))
    c.add_argument("urls", nargs="+")
    o = sub.add_parser("open", help=t("cli_open"))
    o.add_argument("url")
    o.add_argument("-f", "--force", action="store_true", help=t("cli_force"))
    sub.add_parser("hosts", help=t("cli_hosts"))
    lg = sub.add_parser("lang", help=t("cli_lang"))
    lg.add_argument("lang", choices=["en", "zh"])
    a = p.parse_args(argv)

    if a.cmd == "lang":
        import i18n
        i18n.set_lang(a.lang)
        print(t("lang_set"))
        return 0

    if a.cmd == "update":
        return update_feeds()
    if a.cmd == "check":
        return cmd_check(a.urls)
    if a.cmd == "open":
        return cmd_open(a.url, a.force)
    return cmd_hosts()


if __name__ == "__main__":
    sys.exit(main())
