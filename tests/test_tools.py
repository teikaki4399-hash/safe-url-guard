import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import domain_age  # noqa: E402
import scam_check  # noqa: E402

SAMPLES = json.loads((ROOT / "tests" / "samples.json").read_text(encoding="utf-8"))["samples"]


class TestScamCheck(unittest.TestCase):
    rules = scam_check.load_rules()

    def test_samples(self):
        for s in SAMPLES:
            with self.subTest(text=s["text"]):
                level = scam_check.analyze(s["text"], self.rules)["level"]
                self.assertGreaterEqual(level, s["min"])
                self.assertLessEqual(level, s["max"])

    def test_url_extraction(self):
        r = scam_check.analyze("点这里 https://evil.example/a。然后 www.shop.test", self.rules)
        self.assertEqual(r["urls"], ["https://evil.example/a", "www.shop.test"])

    def test_rule_categories_defined(self):
        for r in self.rules["rules"]:
            self.assertIn(r["category"], self.rules["categories"])
        for c in self.rules["combos"]:
            for cat in c["categories"]:
                self.assertIn(cat, self.rules["categories"])


class TestDomainAge(unittest.TestCase):
    bootstrap = {"services": [[["com", "net"], ["https://rdap.example/com/"]],
                              [["uk"], ["http://x/", "https://rdap.uk.example/"]]]}
    now = datetime(2026, 11, 17, tzinfo=timezone.utc)

    def fake_fetch(self, registered):
        def fetch(url):
            if url.endswith("/domain/example.com"):
                return {"events": [{"eventAction": "registration", "eventDate": registered}]}
            raise HTTPError(url, 404, "not found", None, None)
        return fetch

    def test_rdap_base(self):
        self.assertEqual(domain_age.rdap_base("a.example.co.uk", self.bootstrap), "https://rdap.uk.example/")
        self.assertIsNone(domain_age.rdap_base("example.jp", self.bootstrap))

    def test_new_domain_is_danger(self):
        info = domain_age.check("shop.example.com", self.bootstrap, self.fake_fetch("2026-11-10T00:00:00Z"), self.now)
        self.assertEqual((info["domain"], info["days"], info["verdict"]), ("example.com", 7, "DANGER"))

    def test_medium_and_old(self):
        f = domain_age.check("example.com", self.bootstrap, self.fake_fetch("2026-08-01T00:00:00Z"), self.now)
        self.assertEqual(f["verdict"], "WARN")
        f = domain_age.check("example.com", self.bootstrap, self.fake_fetch("1995-08-14T04:00:00Z"), self.now)
        self.assertEqual(f["verdict"], "OK")

    def test_unknown_tld(self):
        self.assertEqual(domain_age.check("example.jp", self.bootstrap, self.fake_fetch(""), self.now)["verdict"], "UNKNOWN")


class TestQrCheck(unittest.TestCase):
    def test_decode(self):
        try:
            import cv2  # noqa: F401
            import qrcode
        except ImportError:
            self.skipTest("needs opencv-python-headless and qrcode")
        import tempfile

        import qr_check
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "q.png"
            qrcode.make("https://evil.example/login").save(p)
            self.assertEqual(qr_check.decode(str(p)), ["https://evil.example/login"])


if __name__ == "__main__":
    unittest.main()


class TestHostsGuard(unittest.TestCase):
    def test_install_update_uninstall_roundtrip(self):
        import tempfile
        from unittest import mock

        import hosts_guard
        import safe_url_guard
        with tempfile.TemporaryDirectory() as d:
            hosts = Path(d) / "hosts"
            original = "127.0.0.1 localhost\n::1 localhost\n"
            hosts.write_text(original, encoding="utf-8")
            with mock.patch.object(safe_url_guard, "update_feeds", return_value=1), \
                 mock.patch.object(safe_url_guard, "CACHE_DIR", Path(d) / "cache"), \
                 mock.patch.object(hosts_guard, "flush_dns"):
                self.assertEqual(hosts_guard.main(["install", "--hosts", str(hosts), "--no-schedule"]), 0)
                text = hosts.read_text(encoding="utf-8")
                self.assertIn("0.0.0.0 y7vv.top", text)
                self.assertIn("0.0.0.0 www.y7vv.top", text)
                self.assertTrue(text.startswith(original))
                # 再次更新不会重复写入
                hosts_guard.main(["update", "--hosts", str(hosts)])
                self.assertEqual(hosts.read_text(encoding="utf-8").count(hosts_guard.BEGIN), 1)
                self.assertTrue((Path(d) / "hosts.safe-url-guard.bak").exists())
                hosts_guard.main(["uninstall", "--hosts", str(hosts), "--no-schedule"])
                self.assertEqual(hosts.read_text(encoding="utf-8"), original)

    def test_builtin_lists_in_sync(self):
        a = (ROOT / "extension" / "builtin_blocklist.txt").read_text(encoding="utf-8")
        b = (ROOT / "docs" / "builtin_blocklist.txt").read_text(encoding="utf-8")
        self.assertEqual(a, b, "extension/ 和 docs/ 的内置黑名单必须一致")

    def test_builtin_blocks_scam_site(self):
        import safe_url_guard
        db, _ = safe_url_guard.load_blocklist()
        self.assertEqual(safe_url_guard.check_url("https://y7vv.top/#/login", db, set())[0], "DANGER")


class TestHostsGuardUpgrade(unittest.TestCase):
    def test_old_chinese_marker_is_replaced(self):
        import tempfile
        from unittest import mock

        import hosts_guard
        import safe_url_guard
        old = ("127.0.0.1 localhost\n\n" + hosts_guard.OLD_BEGINS[0] + "\n0.0.0.0 old.example\n"
               + hosts_guard.END + "\n")
        with tempfile.TemporaryDirectory() as d:
            hosts = Path(d) / "hosts"
            hosts.write_text(old, encoding="utf-8")
            with mock.patch.object(safe_url_guard, "update_feeds", return_value=1), \
                 mock.patch.object(safe_url_guard, "CACHE_DIR", Path(d) / "cache"), \
                 mock.patch.object(hosts_guard, "flush_dns"):
                hosts_guard.main(["update", "--hosts", str(hosts)])
            text = hosts.read_text(encoding="utf-8")
            self.assertNotIn("old.example", text)
            self.assertNotIn(hosts_guard.OLD_BEGINS[0], text)
            self.assertEqual(text.count(hosts_guard.BEGIN), 1)


class TestI18n(unittest.TestCase):
    def test_all_messages_have_both_languages(self):
        import i18n
        for k, v in i18n.MESSAGES.items():
            self.assertEqual(set(v), {"en", "zh"}, k)

    def test_rules_have_both_languages(self):
        rules = scam_check.load_rules()
        for r in rules["rules"]:
            self.assertEqual(set(r["reason"]), {"en", "zh"}, r["id"])
        for c in rules["combos"]:
            self.assertEqual(set(c["reason"]), {"en", "zh"})
        for v in rules["categories"].values():
            self.assertEqual(set(v), {"en", "zh"})
        self.assertEqual(set(rules["advice"]), {"en", "zh"})

    def test_cli_output_in_both_languages(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        import i18n
        msg = "亲爱的，这个平台稳赚不赔，先充值试试"
        for lang, word in (("en", "Scam risk"), ("zh", "诈骗风险")):
            with mock.patch.object(i18n, "LANG", lang):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    scam_check.main([msg])
                self.assertIn(word, buf.getvalue())
