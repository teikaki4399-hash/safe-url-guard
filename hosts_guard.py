#!/usr/bin/env python3
"""hosts_guard - 在整台电脑上拦截危险网站（所有浏览器、所有 App 都有效）。

原理：把黑名单（URLhaus / OpenPhish / 内置黑名单）写进系统的 hosts 文件，
让这些域名指向 0.0.0.0，访问时直接连不上。每天自动更新。

需要管理员权限：
    Windows : 以“管理员身份”打开 PowerShell 或命令提示符后运行
    macOS / Linux : 在命令前加 sudo

用法:
    python3 hosts_guard.py install     # 安装：更新黑名单、写入 hosts、注册每日自动更新
    python3 hosts_guard.py update      # 手动更新一次（自动更新也是运行这个）
    python3 hosts_guard.py uninstall   # 卸载：从 hosts 中删除拦截列表并取消自动更新
    python3 hosts_guard.py status      # 查看当前状态
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
# 自动更新以管理员 / SYSTEM 身份运行，所以缓存放在脚本旁边，而不是用户目录
os.environ.setdefault("SAFE_URL_GUARD_CACHE", str(HERE / ".cache"))

import safe_url_guard  # noqa: E402

BEGIN = "# >>> safe-url-guard BEGIN (自动生成，请勿手动修改) >>>"
END = "# <<< safe-url-guard END <<<"
TASK_NAME = "safe-url-guard"
SYSTEM = platform.system()


def default_hosts_path() -> Path:
    if SYSTEM == "Windows":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


# ---------------------------------------------------------------- hosts 文件
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
        if line.strip() == BEGIN:
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
    lines = [BEGIN, f"# 共 {len(domains)} 个域名。卸载: python3 hosts_guard.py uninstall"]
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
            continue  # hosts 文件无法拦截 IP 地址
        except ValueError:
            out.append(h)
    return out


def write_hosts(path: Path, domains: list[str]) -> None:
    backup = path.with_name(path.name + ".safe-url-guard.bak")
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)   # 第一次修改前备份原始 hosts
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


# ---------------------------------------------------------------- 每日自动更新
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
        return "Windows 任务计划程序（开机时 + 每天 12:00）"
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
        return "macOS launchd（开机时 + 每 24 小时）"
    cron = Path("/etc/cron.d/safe-url-guard")
    line = " ".join(cmd)
    cron.write_text(f"@reboot root {line}\n17 12 * * * root {line}\n", encoding="utf-8")
    return "cron（开机时 + 每天 12:17）"


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


# ---------------------------------------------------------------- 命令
def do_update(hosts: Path) -> int:
    rc = safe_url_guard.update_feeds()
    domains = collect_domains()
    if rc != 0 and not domains:
        print("黑名单下载失败，hosts 保持不变。请检查网络后重试。", file=sys.stderr)
        return 1
    write_hosts(hosts, domains)
    flush_dns()
    print(f"已更新：正在拦截 {len(domains)} 个域名（{hosts}）")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="在整台电脑上拦截危险网站（修改 hosts 文件）")
    p.add_argument("cmd", choices=["install", "update", "uninstall", "status"])
    p.add_argument("--hosts", type=Path, default=None, help=argparse.SUPPRESS)  # 测试用
    p.add_argument("--no-schedule", action="store_true", help="不注册每日自动更新")
    a = p.parse_args(argv)
    hosts = a.hosts or default_hosts_path()

    try:
        if a.cmd == "status":
            text = read_text(hosts)
            n = sum(1 for l in text.splitlines() if l.startswith("0.0.0.0 ")) if BEGIN in text else 0
            print(f"hosts: {hosts}\n状态: {'已安装' if BEGIN in text else '未安装'}（拦截条目 {n} 条）")
            return 0
        if a.cmd == "uninstall":
            remove_from_hosts(hosts)
            if not a.no_schedule:
                unregister_schedule()
            flush_dns()
            print("已卸载：拦截列表已从 hosts 中删除，自动更新已取消。")
            return 0
        rc = do_update(hosts)
        if rc == 0 and a.cmd == "install" and not a.no_schedule:
            print("已注册自动更新：" + register_schedule())
        if rc == 0 and a.cmd == "install":
            print("安装完成。整台电脑的浏览器和 App 都会拦截黑名单上的网站。")
        return rc
    except PermissionError:
        hint = "请用“以管理员身份运行”打开 PowerShell 后再执行" if SYSTEM == "Windows" else "请在命令前加 sudo"
        print(f"没有权限修改 {hosts}。{hint}。", file=sys.stderr)
        return 77


if __name__ == "__main__":
    sys.exit(main())
