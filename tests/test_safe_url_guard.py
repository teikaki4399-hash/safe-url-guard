import unittest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import safe_url_guard as g  # noqa: E402


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.db = {"evil.example": "urlhaus", "phish.test": "openphish"}

    def test_parse_hosts_feed(self):
        text = "# comment\n127.0.0.1\tlocalhost\n127.0.0.1\tBad.Example\n"
        self.assertEqual(g.parse_feed(text, "hosts"), {"bad.example"})

    def test_parse_url_feed(self):
        text = "https://www.phish.test/login\nhttp://1.2.3.4/x\n"
        self.assertEqual(g.parse_feed(text, "urls"), {"phish.test", "1.2.3.4"})

    def test_blocklisted_and_subdomain(self):
        self.assertEqual(g.check_url("https://evil.example/a", self.db, set())[0], "DANGER")
        self.assertEqual(g.check_url("https://x.y.phish.test", self.db, set())[0], "DANGER")

    def test_allowlist_wins(self):
        self.assertEqual(g.check_url("https://evil.example", self.db, {"evil.example"})[0], "OK")

    def test_heuristics(self):
        self.assertEqual(g.check_url("http://192.168.0.1/login", self.db, set())[0], "WARN")
        self.assertEqual(g.check_url("https://xn--pple-43d.com", self.db, set())[0], "WARN")
        self.assertEqual(g.check_url("https://google.com@bad.io", self.db, set())[0], "WARN")

    def test_clean(self):
        self.assertEqual(g.check_url("https://www.python.org/", self.db, set())[0], "OK")


if __name__ == "__main__":
    unittest.main()
