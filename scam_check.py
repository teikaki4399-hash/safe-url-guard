#!/usr/bin/env python3
"""scam_check - check SMS, LINE, e-mail, DMs etc. for common scam phrases.

Python standard library only. Rules live in docs/scam_rules.json (shared with the web version).

Usage:
    python3 scam_check.py "message to check"
    python3 scam_check.py -f message.txt
    pbpaste | python3 scam_check.py          # read from stdin
    python3 scam_check.py --online "..."     # also look up registration dates of URLs in the message

Exit code: 0=nothing found 1=low 2=medium 3=high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import safe_url_guard
from i18n import pick, t

RULES_PATH = Path(__file__).resolve().parent / "docs" / "scam_rules.json"
# stop at whitespace, quotes and CJK punctuation (，。、）」】)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\uff0c\u3002\u3001\uff09)\u300d\u3011]+", re.IGNORECASE)


def load_rules(path: Path = RULES_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    for r in data["rules"]:
        r["_re"] = re.compile(r["pattern"], re.IGNORECASE)
    return data


def analyze(text: str, rules: dict) -> dict:
    """Return {score, level, hits:[{id,category,reason,matches}], combos:[...], urls:[...]}."""
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
    print(t("risk", level=t(f"lvl_{res['level']}"), score=res["score"]))
    if res["hits"]:
        print(t("signs"))
        for h in res["hits"]:
            print(f"  ● [{pick(names[h['category']])}] {pick(h['reason'])}")
            print("      " + t("matched", m=" / ".join(h["matches"][:5])))
    if res["combos"]:
        print(t("combos"))
        for c in res["combos"]:
            print(f"  ▲ {pick(c['reason'])}")

    if res["urls"]:
        print(t("urls_in_msg"))
        db, _stale = safe_url_guard.load_blocklist()
        allow = safe_url_guard.read_domain_file(safe_url_guard.ALLOWLIST_FILE)
        for u in res["urls"]:
            verdict, reasons = safe_url_guard.check_url(u, db, allow)
            print(f"  [{safe_url_guard.label(verdict)}] {u}")
            for r in reasons:
                print(f"      - {r}")
            if online:
                import domain_age
                info = domain_age.check(safe_url_guard.host_of(u))
                print(f"      - {domain_age.describe(info)}")

    if res["level"] >= 2:
        print(t("advice"))
        for a in pick(rules["advice"]):
            print(f"  - {a}")
    print(t("disclaimer"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=t("sc_desc"))
    p.add_argument("text", nargs="*", help=t("sc_text"))
    p.add_argument("-f", "--file", help=t("sc_file"))
    p.add_argument("--online", action="store_true", help=t("sc_online"))
    p.add_argument("--json", action="store_true", help=t("sc_json"))
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
