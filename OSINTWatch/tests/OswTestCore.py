import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import OswConfig as C  # noqa: E402
import OswMatch as M  # noqa: E402
from OswCore import Paths, clean_text, redact, register_secret, safe_http_url  # noqa: E402
from OswStore import Store  # noqa: E402


class Item:  # minimal stand-in for OswFetch.Item
    def __init__(self, sid, uid, title="t", text="x", url="https://e.com/1", kind="web", pub=0, author=""):
        self.source_id, self.uid, self.title, self.text, self.url = sid, uid, title, text, url
        self.kind, self.published, self.author = kind, pub, author


class MatcherTests(unittest.TestCase):
    def hits(self, entries, text):
        return [r.label for r in M.Matcher.from_entries(entries).match(text)]

    def test_word_boundary(self):
        self.assertEqual(self.hits(["hypersonic"], "A Hypersonic missile"), ["hypersonic"])
        self.assertEqual(self.hits(["hypersonic"], "hypersonics are fast"), [])

    def test_phrase_spans_whitespace(self):
        self.assertTrue(self.hits(['"south china sea"'], "South   China\nSea patrol"))

    def test_wildcard(self):
        self.assertTrue(self.hits(["missil*"], "new missiles tested"))
        self.assertFalse(self.hits(["missil*"], "mis"))

    def test_case_sensitive(self):
        self.assertTrue(self.hits(["cs:PLA"], "the PLA moved"))
        self.assertFalse(self.hits(["cs:PLA"], "the pla moved"))
        self.assertFalse(self.hits(["cs:PLA"], "PLAN B"))

    def test_and_and_exclusion_and_urgent(self):
        self.assertTrue(self.hits(["pla navy + hambantota"], "PLA Navy ship at Hambantota"))
        self.assertFalse(self.hits(["pla navy + hambantota"], "PLA Navy ship at Karachi"))
        self.assertEqual(self.hits(["missile", "-drill"], "missile drill"), [])
        self.assertEqual(self.hits(["missile", "-drill"], "missile launch"), ["missile"])
        self.assertTrue(M.parse_entry("!hypersonic").urgent)

    def test_unicode_and_casefold(self):
        self.assertTrue(self.hits(["\u067e\u0627\u06a9\u0633\u062a\u0627\u0646"], "\u067e\u0627\u06a9\u0633\u062a\u0627\u0646 \u0646\u06d2 \u06a9\u06c1\u0627"))
        self.assertTrue(self.hits(["\u53f0\u6e7e"], "\u53f0\u6e7e\u6d77\u5cfd\u6f14\u4e60"))
        self.assertTrue(self.hits(["strasse"], "Stra\u00dfe closed"))

    def test_no_regex_injection(self):
        self.assertEqual(self.hits(["(a+)+$ x"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"), [])
        self.assertTrue(self.hits(["c++ dev"], "hiring c++ dev today") is not None)

    def test_invalid(self):
        for bad in ("", "a", "*", "!-x", "-a + b"):
            with self.assertRaises(M.RuleError):
                M.parse_entry(bad)


class ConfigTests(unittest.TestCase):
    def test_handles(self):
        self.assertEqual(C.norm_twitter("@NASA"), "nasa")
        self.assertEqual(C.norm_twitter("https://x.com/NASA/status/123"), "nasa")
        for bad in ("home", "a b", "waytoolonghandle_12345", ""):
            with self.assertRaises(ValueError):
                C.norm_twitter(bad)
        self.assertEqual(C.norm_telegram("https://t.me/s/Durov"), "durov")
        self.assertEqual(C.norm_telegram("@bbcnews"), "bbcnews")
        for bad in ("t.me/+AbCdEf", "t.me/joinchat/xyz", "ab"):
            with self.assertRaises(ValueError):
                C.norm_telegram(bad)

    def test_website_ssrf_guard(self):
        self.assertEqual(C.norm_website("example.com/feed?utm_source=x&a=1"), "https://example.com/feed?a=1")
        for bad in ("http://127.0.0.1/x", "localhost", "http://10.0.0.5/", "http://169.254.169.254/latest", "http://[::1]/",
                    "http://2130706433/", "https://user:pw@example.com/", "ftp://example.com"):
            with self.assertRaises(ValueError, msg=bad):
                C.norm_website(bad)
        self.assertTrue(C.norm_website("http://192.168.1.10/rss", allow_private=True).startswith("http://192.168.1.10"))

    def test_watchlist_limits_dedupe_and_errors(self):
        raw = {"twitter": [f"user{i}" for i in range(51)] + ["USER1"], "telegram": ["t.me/durov", "@Durov"],
               "websites": ["example.com"], "keywords": ["missile", "a"]}
        clean, errs = C.normalize_watchlist(raw)
        self.assertEqual(len(clean["twitter"]), 51)
        self.assertEqual(clean["telegram"], ["durov"])
        msgs = [(e["list"], e["error"]) for e in errs]
        self.assertTrue(any(l == "twitter" and "limit 50" in m for l, m in msgs))
        self.assertTrue(any(l == "keywords" for l, m in msgs))

    def test_settings_validation(self):
        base = C.DEFAULT_SETTINGS
        m, e = C.validate_settings({"privacy": {"proxy": "127.0.0.1:9150"}}, base)
        self.assertEqual((m["privacy"]["proxy"], e), ("socks5h://127.0.0.1:9150", []))
        _, e = C.validate_settings({"privacy": {"proxy": "socks5://u:p@1.2.3.4:1080"}}, base)
        self.assertTrue(e and "credentials" in e[0])
        for patch in ({"nope": {"a": 1}}, {"polling": {"telegram": 5}}, {"polling": {"telegram": "90"}},
                      {"server": {"host": "0.0.0.0"}}, {"alerts": {"mode": "loud"}}, {"notify": {"ntfy_server": "ftp://x"}}):
            _, e = C.validate_settings(patch, base)
            self.assertTrue(e, patch)

    def test_vault(self):
        with tempfile.TemporaryDirectory() as d:
            v = C.Vault(Paths(Path(d)))
            secret = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            v.set("TG_BOT_TOKEN", secret)
            self.assertEqual(v.get("TG_BOT_TOKEN"), secret)
            self.assertEqual(v.status()["TG_BOT_TOKEN"], {"set": True, "source": "file", "hint": C.SECRET_SPECS["TG_BOT_TOKEN"][1]})
            self.assertNotIn(secret, redact(f"POST https://api.telegram.org/bot{secret}/sendMessage failed"))
            with self.assertRaises(ValueError):
                v.set("TG_BOT_TOKEN", "not-a-token")
            with self.assertRaises(ValueError):
                v.set("UNKNOWN", "x")
            if os.name != "nt":
                mode = stat.S_IMODE(os.stat(Path(d) / "OswSecrets.env").st_mode)
                self.assertEqual(mode, 0o600)
            os.environ["OSW_TG_BOT_TOKEN"] = "987654321:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            try:
                self.assertEqual(v.source("TG_BOT_TOKEN"), "env")
            finally:
                del os.environ["OSW_TG_BOT_TOKEN"]
            v.delete("TG_BOT_TOKEN")
            self.assertIsNone(v.get("TG_BOT_TOKEN"))

    def test_config_roundtrip_and_recovery_from_corrupt_file(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = C.Config(Paths(Path(d)))
            self.assertEqual(cfg.save_watchlist({"twitter": ["nasa"], "telegram": [], "websites": [], "keywords": ["missile"]}), [])
            self.assertTrue(cfg.save_watchlist({"twitter": ["nasa", "bad handle"]}))  # rejected, nothing written
            self.assertEqual(cfg.watchlist["twitter"], ["nasa"])
            cfg.save_watchlist({"twitter": ["nasa", "esa"], "keywords": ["missile"]})  # creates .bak of previous good file
            (Path(d) / "OswWatchlist.json").write_text("{ corrupt", encoding="utf-8")
            cfg2 = C.Config(Paths(Path(d)))
            self.assertEqual(cfg2.watchlist["twitter"], ["nasa"])  # restored from .bak


class SanitizerTests(unittest.TestCase):
    def test_clean_and_url(self):
        self.assertEqual(clean_text("a\u202eb\x00c\u200b  d"), "abc d")
        self.assertEqual(safe_http_url("https://e.com/a b?utm_x=1&k=v#f"), "https://e.com/a%20b?k=v#f")
        for bad in ("javascript:alert(1)", "file:///etc/passwd", "https://u:p@e.com", "//e.com", "https://e.com/\nx"):
            self.assertIsNone(safe_http_url(bad), bad)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def test_dedupe_alert_filter_forget(self):
        self.s.upsert_state("tg:a", "telegram", "@a", "a")
        new = self.s.insert_items([Item("tg:a", "1", text="hello 100% _real_"), Item("tg:a", "2")])
        self.assertEqual(len(new), 2)
        self.assertEqual(len(self.s.insert_items([Item("tg:a", "1"), Item("tg:a", "3")])), 1)
        aid = self.s.add_alert(new[0][0], ["hello"], True)
        self.assertTrue(aid)
        self.assertEqual(self.s.add_alert(new[0][0], ["hello"], True), 0)  # one alert per item
        self.assertEqual(len(self.s.list_items(q="100%")), 1)  # LIKE wildcards escaped
        self.assertEqual(len(self.s.list_items(q="%")), 1)
        self.assertEqual(self.s.list_alerts()[0]["matched"], ["hello"])
        self.assertTrue(self.s.list_alerts()[0]["urgent"])
        self.assertEqual(self.s.integrity(), ["ok"])
        self.s.backup(Path(self.tmp.name) / "b.db")
        self.assertEqual(Store(Path(self.tmp.name) / "b.db").counts()["items"], 3)
        self.s.forget_sources(["tg:a"])
        self.assertEqual(self.s.counts(), {"items": 0, "alerts": 0, "alerts_24h": 0})

    def test_sql_injection_is_inert(self):
        self.s.upsert_state("x", "web", "l", "t")
        self.s.insert_items([Item("x", "1")])
        self.assertEqual(self.s.list_items(q="'; DROP TABLE items;--"), [])
        self.assertEqual(self.s.counts()["items"], 1)
        self.s.update_state("x", **{"fails; DROP TABLE items": 1, "fails": 2})
        self.assertEqual(self.s.get_state("x")["fails"], 2)


if __name__ == "__main__":
    unittest.main()
