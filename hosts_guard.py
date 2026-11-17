#!/usr/bin/env python3
"""hosts_guard - block dangerous sites on the whole computer (every browser and every app).

How it works: the blocklists (URLhaus / OpenPhish / built-in list) are written into the
system hosts file so those domains point to 0.0.0.0 and cannot be reached.
The lists are updated automatically every day.

Requires administrator rights:
    Windows       : run from PowerShell opened with "Run as administrator"
    macOS / Linux : put sudo in front of the command

Usage:
    python3 hosts_guard.py install     # update lists, write hosts, register daily updates
    python3 hosts_guard.py update      # update once (this is what the daily job runs)
    python3 hosts_guard.py uninstall   # remove the blocklist from hosts and stop daily updates
    python3 hosts_guard.py status      # show the current state
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The daily job runs as root / SYSTEM, so keep the cache next to this script, not in a user's home
os.environ.setdefault("SAFE_URL_GUARD_CACHE", str(HERE / ".cache"))

import safe_url_guard  # noqa: E402
from i18n import t  # noqa: E402

BEGIN = "# >>> safe-url-guard BEGIN (auto-generated, do not edit) >>>"
# marker written by older versions; still recognised so upgrades replace it cleanly
OLD_BEGINS = ("# >>> safe-url-guard BEGIN (\u81ea\u52a8\u751f\u6210\uff0c\u8bf7\u52ff\u624b\u52a8\u4fee\u6539) >>>",)
END = "# <<< safe-url-guard END <<<"
TASK_NAME = "safe-url-guard"
SYSTEM = platform.system()


def default_hosts_path() -> Path:
    if SYSTEM == "Windows":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


# ---------------------------------------------------------------- hosts file
def read_text(path: Path) -> str:
    raw = path.read_bytes() if path.exists() else b""
    for enc in ("utf-8", "cp932", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def strip_block(text: str) -> str:
    out, inside = [], False
    for line in text.splitlines():
        if line.strip() == BEGIN or line.strip() in OLD_BEGINS:
            inside = True
            continue
        if line.strip() == END:
            inside = False
            continue
        if not inside:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + ("\n" if out else "")


def build_block(domains: list[str]) -> str:
    lines = [BEGIN, t("hg_block_note", n=len(domains))]
    for d in domains:
        lines.append(f"0.0.0.0 {d}")
        if not d.startswith("www."):
            lines.append(f"0.0.0.0 www.{d}")
    lines.append(END)
    return "\n".join(lines) + "\n"


def collect_domains() -> list[str]:
    db, _ = safe_url_guard.load_blocklist()
    allow = safe_url_guard.read_domain_file(safe_url_guard.ALLOWLIST_FILE)
    out = []
    for h in sorted(db):
        if h in allow:
            continue
        try:
            ipaddress.ip_address(h)
            continue  # a hosts file cannot block IP addresses
        except ValueError:
            out.append(h)
    return out


def write_hosts(path: Path, domains: list[str]) -> None:
    backup = path.with_name(path.name + ".safe-url-guard.bak")
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)   # back up the original hosts file before the first change
    base = strip_block(read_text(path))
    newline = "\r\n" if SYSTEM == "Windows" else "\n"
    content = (base + ("\n" if base else "") + build_block(domains)).replace("\n", newline)
    tmp = path.with_name(path.name + ".safe-url-guard.tmp")
    tmp.write_bytes(content.encode("utf-8"))
    os.replace(tmp, path)


def remove_from_hosts(path: Path) -> None:
    if not path.exists():
        return
    newline = "\r\n" if SYSTEM == "Windows" else "\n"
    content = strip_block(read_text(path)).replace("\n", newline)
    path.write_bytes(content.encode("utf-8"))


def flush_dns() -> None:
    cmds = {
        "Windows": [["ipconfig", "/flushdns"]],
        "Darwin": [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]],
        "Linux": [["resolvectl", "flush-caches"]],
    }.get(SYSTEM, [])
    for c in cmds:
        try:
            subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass


# ---------------------------------------------------------------- daily automatic updates
def _cmd() -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()), "update"]


def register_schedule() -> str:
    cmd = _cmd()
    if SYSTEM == "Windows":
        tr = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        for suffix, sched in (("", ["/SC", "DAILY", "/ST", "12:00"]), ("-startup", ["/SC", "ONSTART"])):
            subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME + suffix, "/TR", tr, *sched,
                            "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"], check=True,
                           stdout=subprocess.DEVNULL)
        return t("hg_sched_win")
    if SYSTEM == "Darwin":
        plist = Path("/Library/LaunchDaemons/local.safe-url-guard.plist")
        args = "".join(f"<string>{c}</string>" for c in cmd)
        plist.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>'
            "<key>Label</key><string>local.safe-url-guard</string>"
            f"<key>ProgramArguments</key><array>{args}</array>"
            "<key>RunAtLoad</key><true/><key>StartInterval</key><integer>86400</integer>"
            "</dict></plist>\n", encoding="utf-8")
        subprocess.run(["launchctl", "unload", str(plist)], stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["launchctl", "load", "-w", str(plist)], check=True)
        return t("hg_sched_mac")
    cron = Path("/etc/cron.d/safe-url-guard")
    line = " ".join(cmd)
    cron.write_text(f"@reboot root {line}\n17 12 * * * root {line}\n", encoding="utf-8")
    return t("hg_sched_cron")


def unregister_schedule() -> None:
    if SYSTEM == "Windows":
        for suffix in ("", "-startup"):
            subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME + suffix, "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    elif SYSTEM == "Darwin":
        plist = Path("/Library/LaunchDaemons/local.safe-url-guard.plist")
        subprocess.run(["launchctl", "unload", str(plist)], stderr=subprocess.DEVNULL, check=False)
        plist.unlink(missing_ok=True)
    else:
        Path("/etc/cron.d/safe-url-guard").unlink(missing_ok=True)


# ---------------------------------------------------------------- commands
def do_update(hosts: Path) -> int:
    rc = safe_url_guard.update_feeds()
    domains = collect_domains()
    if rc != 0 and not domains:
        print(t("hg_download_failed"), file=sys.stderr)
        return 1
    write_hosts(hosts, domains)
    flush_dns()
    print(t("hg_updated", n=len(domains), path=hosts))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=t("hg_desc"))
    p.add_argument("cmd", choices=["install", "update", "uninstall", "status"])
    p.add_argument("--hosts", type=Path, default=None, help=argparse.SUPPRESS)  # for tests
    p.add_argument("--no-schedule", action="store_true", help=t("hg_no_sched"))
    a = p.parse_args(argv)
    hosts = a.hosts or default_hosts_path()

    try:
        if a.cmd == "status":
            text = read_text(hosts)
            installed = BEGIN in text or any(b in text for b in OLD_BEGINS)
            n = sum(1 for l in text.splitlines() if l.startswith("0.0.0.0 ")) if installed else 0
            print(t("hg_status", path=hosts, state=t("hg_installed" if installed else "hg_not_installed"), n=n))
            return 0
        if a.cmd == "uninstall":
            remove_from_hosts(hosts)
            if not a.no_schedule:
                unregister_schedule()
            flush_dns()
            print(t("hg_uninstalled"))
            return 0
        rc = do_update(hosts)
        if rc == 0 and a.cmd == "install" and not a.no_schedule:
            print(t("hg_scheduled", how=register_schedule()))
        if rc == 0 and a.cmd == "install":
            print(t("hg_done"))
        return rc
    except PermissionError:
        hint = t("hg_hint_win") if SYSTEM == "Windows" else t("hg_hint_unix")
        print(t("hg_perm", path=hosts, hint=hint), file=sys.stderr)
        return 77


if __name__ == "__main__":
    sys.exit(main())
