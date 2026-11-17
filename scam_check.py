#!/usr/bin/env python3
"""scam_check - 检查短信、LINE、邮件、私信等消息是否含有常见的诈骗话术。

只使用 Python 标准库。规则文件为 docs/scam_rules.json（和网页版共用）。

用法:
    python3 scam_check.py "要检查的消息"
    python3 scam_check.py -f message.txt
    pbpaste | python3 scam_check.py          # 从标准输入读取
    python3 scam_check.py --online "..."     # 同时在线查询消息中网址的注册时间

退出码: 0=未发现 1=低 2=中 3=高
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import safe_url_guard

RULES_PATH = Path(__file__).resolve().parent / "docs" / "scam_rules.json"
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'，。、）)」】]+", re.IGNORECASE)
LEVEL_NAMES = {0: "未发现明显特征", 1: "低", 2: "中", 3: "高"}


def load_rules(path: Path = RULES_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    for r in data["rules"]:
        r["_re"] = re.compile(r["pattern"], re.IGNORECASE)
    return data


def analyze(text: str, rules: dict) -> dict:
    """返回 {score, level, hits:[{id,category,reason,matches}], combos:[...], urls:[...]}"""
    hits = []
    for r in rules["rules"]:
        found = sorted({m.group(0) for m in r["_re"].finditer(text)})
        if found:
            hits.append({"id": r["id"], "category": r["category"], "weight": r["weight"],
                         "reason": r["reason"], "matches": found})
    cats = {h["category"] for h in hits}
    combos = [c for c in rules["combos"] if all(x in cats for x in c["categories"])]
    score = sum(h["weight"] for h in hits) + sum(c["bonus"] for c in combos)
    t = rules["thresholds"]
    level = 3 if score >= t["high"] else 2 if score >= t["medium"] else 1 if score > 0 else 0
    urls = [u.rstrip(".,!?;:") for u in URL_RE.findall(text)]
    return {"score": score, "level": level, "hits": hits, "combos": combos, "urls": urls}


def print_report(res: dict, rules: dict, online: bool) -> None:
    names = rules["categories"]
    print(f"诈骗风险: 【{LEVEL_NAMES[res['level']]}】 (分数 {res['score']})\n")
    if res["hits"]:
        print("发现的特征:")
        for h in res["hits"]:
            print(f"  ● [{names[h['category']]}] {h['reason']}")
            print(f"      命中: {'、'.join(h['matches'][:5])}")
    if res["combos"]:
        print("\n危险组合:")
        for c in res["combos"]:
            print(f"  ▲ {c['reason']}")

    if res["urls"]:
        print("\n消息中的网址:")
        db, _stale = safe_url_guard.load_blocklist()
        allow = safe_url_guard.read_domain_file(safe_url_guard.ALLOWLIST_FILE)
        for u in res["urls"]:
            verdict, reasons = safe_url_guard.check_url(u, db, allow)
            print(f"  [{safe_url_guard.LABEL[verdict]}] {u}")
            for r in reasons:
                print(f"      - {r}")
            if online:
                import domain_age
                info = domain_age.check(safe_url_guard.host_of(u))
                print(f"      - {domain_age.describe(info)}")

    if res["level"] >= 2:
        print("\n建议:")
        for a in rules["advice"]:
            print(f"  - {a}")
    print("\n※ 本工具只根据常见话术判断，结果不代表一定是或一定不是诈骗。")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="检查消息中是否含有常见的诈骗话术")
    p.add_argument("text", nargs="*", help="要检查的消息（省略则从标准输入读取）")
    p.add_argument("-f", "--file", help="从文件读取消息")
    p.add_argument("--online", action="store_true", help="在线查询消息中网址的注册时间 (RDAP)")
    p.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    a = p.parse_args(argv)

    if a.file:
        text = Path(a.file).read_text(encoding="utf-8")
    elif a.text:
        text = " ".join(a.text)
    else:
        text = sys.stdin.read()

    rules = load_rules()
    res = analyze(text, rules)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print_report(res, rules, a.online)
    return res["level"]


if __name__ == "__main__":
    sys.exit(main())
