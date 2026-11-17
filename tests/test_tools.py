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
            self.skipTest("需要 opencv-python-headless 和 qrcode")
        import tempfile

        import qr_check
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "q.png"
            qrcode.make("https://evil.example/login").save(p)
            self.assertEqual(qr_check.decode(str(p)), ["https://evil.example/login"])


if __name__ == "__main__":
    unittest.main()
