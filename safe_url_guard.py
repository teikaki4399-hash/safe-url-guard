#!/usr/bin/env python3
"""safe_url_guard - 访问前检查 URL，避免打开病毒 / 诈骗（钓鱼）网站。

只使用 Python 标准库（Python 3.8+）。

用法:
    python3 safe_url_guard.py update            # 下载 / 更新公开黑名单
    python3 safe_url_guard.py check URL [...]   # 检查 URL
    python3 safe_url_guard.py open URL          # 检查通过后才用浏览器打开
    python3 safe_url_guard.py hosts > block.txt # 生成 hosts 格式的拦截列表

黑名单来源（公开、免费）:
    - URLhaus (abuse.ch)  : 恶意软件分发站点  https://urlhaus.abuse.ch/
    - OpenPhish Community : 钓鱼网站          https://openphish.com/
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

FEEDS = {
    # hosts 格式: "127.0.0.1\tdomain"
    "urlhaus": ("https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"),
    # 每行一个 URL
    "openphish": ("https://openphish.com/feed.txt", "urls"),
}

CACHE_DIR = Path(os.environ.get("SAFE_URL_GUARD_CACHE",
                                Path.home() / ".cache" / "safe_url_guard"))
STALE_SECONDS = 24 * 60 * 60  # 黑名单超过 24 小时视为过期
USER_AGENT = "safe-url-guard/1.0"

# 本地白名单 / 自定义黑名单（每行一个域名，# 开头为注释）
ALLOWLIST_FILE = CACHE_DIR / "allowlist.txt"
DENYLIST_FILE = CACHE_DIR / "denylist.txt"


# ---------------------------------------------------------------- 工具函数
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


# ---------------------------------------------------------------- 黑名单
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
            print(f"[OK]   {name}: {len(hosts)} 个域名")
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"[失败] {name}: {e}", file=sys.stderr)
    return 0 if ok else 1


def load_blocklist() -> tuple[dict[str, str], bool]:
    """返回 ({域名: 来源}, 是否有过期/缺失的列表)"""
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
    for h in read_domain_file(DENYLIST_FILE):
        db[h] = "自定义黑名单"
    return db, stale


# ---------------------------------------------------------------- 启发式检查
def heuristics(url: str) -> list[str]:
    """常见的可疑特征。命中不代表一定是恶意网站，只是提醒注意。"""
    warn = []
    raw = url if "://" in url else "http://" + url
    parts = urlsplit(raw)
    host = parts.hostname or ""

    if parts.scheme == "http":
        warn.append("未使用 HTTPS（通信未加密）")
    try:
        ipaddress.ip_address(host)
        warn.append("直接使用 IP 地址而不是域名")
    except ValueError:
        pass
    if "xn--" in host or not host.isascii():
        warn.append("域名含有特殊字符（punycode / xn--），可能是用相似字符仿冒的网站")
    if parts.username or "@" in parts.netloc:
        warn.append("URL 中含有 '@'，真实目标可能与看起来的不同")
    if host.count(".") >= 4:
        warn.append("子域名层级过多")
    if len(raw) > 200:
        warn.append("URL 异常地长")
    if parts.port and parts.port not in (80, 443):
        warn.append(f"使用非标准端口 {parts.port}")
    return warn


# ---------------------------------------------------------------- 判定
def check_url(url: str, db: dict[str, str], allow: set[str]) -> tuple[str, list[str]]:
    """返回 (判定, 理由列表)。判定为 DANGER / WARN / OK"""
    host = host_of(url)
    if not host:
        return "DANGER", ["无法解析域名"]
    if any(d in allow for d in parent_domains(host)) or host in allow:
        return "OK", ["在白名单中"]
    for d in [host, *parent_domains(host)]:
        if d in db:
            return "DANGER", [f"命中黑名单: {d}（来源: {db[d]}）"]
    warn = heuristics(url)
    return ("WARN", warn) if warn else ("OK", ["未发现已知威胁"])


LABEL = {"DANGER": "危险", "WARN": "注意", "OK": "安全?"}


def cmd_check(urls: list[str]) -> int:
    db, stale = load_blocklist()
    if stale:
        print("※ 黑名单未下载或已过期，请先运行: python3 safe_url_guard.py update\n",
              file=sys.stderr)
    allow = read_domain_file(ALLOWLIST_FILE)
    worst = 0
    for url in urls:
        verdict, reasons = check_url(url, db, allow)
        print(f"[{LABEL[verdict]}] {url}")
        for r in reasons:
            print(f"    - {r}")
        worst = max(worst, {"OK": 0, "WARN": 1, "DANGER": 2}[verdict])
    return worst  # 退出码: 0=安全 1=注意 2=危险


def cmd_open(url: str, force: bool) -> int:
    code = cmd_check([url])
    if code == 2:
        print("\n已拦截：该网站在恶意 / 钓鱼黑名单中，不会打开。")
        return 2
    if code == 1 and not force:
        ans = input("\n存在可疑特征，仍要打开吗？ [y/N]: ").strip().lower()
        if ans != "y":
            print("已取消。")
            return 1
    webbrowser.open(url if "://" in url else "https://" + url)
    return 0


def cmd_hosts() -> int:
    db, stale = load_blocklist()
    if stale:
        print("# 警告: 黑名单未下载或已过期", file=sys.stderr)
    print("# safe_url_guard 生成的拦截列表 (URLhaus / OpenPhish)")
    for h in sorted(db):
        try:
            ipaddress.ip_address(h)
            continue  # hosts 文件无法拦截 IP 地址
        except ValueError:
            print(f"0.0.0.0 {h}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="访问前检查 URL，避免病毒 / 诈骗网站")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("update", help="下载 / 更新黑名单")
    c = sub.add_parser("check", help="检查 URL")
    c.add_argument("urls", nargs="+")
    o = sub.add_parser("open", help="检查通过后用浏览器打开")
    o.add_argument("url")
    o.add_argument("-f", "--force", action="store_true", help="对“注意”级别不再询问")
    sub.add_parser("hosts", help="输出 hosts 格式的拦截列表")
    a = p.parse_args(argv)

    if a.cmd == "update":
        return update_feeds()
    if a.cmd == "check":
        return cmd_check(a.urls)
    if a.cmd == "open":
        return cmd_open(a.url, a.force)
    return cmd_hosts()


if __name__ == "__main__":
    sys.exit(main())
