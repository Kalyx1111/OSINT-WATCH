import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import OswFetch as F  # noqa: E402
import OswServer as S  # noqa: E402
from OswCore import Paths  # noqa: E402
from OswTestKit import Mock, fixture  # noqa: E402


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = Mock()
        self._old = (F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE)
        F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE = self.mock.url(), self.mock.url("/x"), self.mock.url("/tio")
        self.app = S.create_app(Paths(Path(self.tmp.name)))
        self.a: S.App = self.app.state.a
        self.a.cfg.save_settings({"privacy": {"mode": "open", "allow_private": True}})
        self.cm = TestClient(self.app, base_url="http://127.0.0.1")
        self.c = self.cm.__enter__()  # runs lifespan startup: engine + dispatcher threads start
        self.token = self.a.token

    def tearDown(self):
        self.cm.__exit__(None, None, None)
        F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE = self._old
        self.mock.close()
        self.tmp.cleanup()

    def put(self, path, body):
        return self.c.put(path, json=body, headers={"X-Osw-Token": self.token})

    def post(self, path, body=None):
        return self.c.post(path, json=body or {}, headers={"X-Osw-Token": self.token})

    # -------------------------------------------------------------- security
    def test_page_serves_real_token_not_placeholder(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("__OSW_TOKEN__", r.text)
        m = re.search(r'name="osw-token" content="([^"]+)"', r.text)
        self.assertTrue(m and len(m.group(1)) > 20)
        self.assertEqual(m.group(1), self.token)

    def test_mutating_request_without_token_is_rejected(self):
        r = self.c.put("/api/watchlist", json={"twitter": ["nasa"]})
        self.assertEqual(r.status_code, 403)
        r2 = self.c.put("/api/watchlist", json={"twitter": ["nasa"]}, headers={"X-Osw-Token": "wrong"})
        self.assertEqual(r2.status_code, 403)
        self.assertEqual(self.put("/api/watchlist", {"twitter": ["nasa"]}).status_code, 200)

    def test_get_requests_do_not_need_token(self):
        self.assertEqual(self.c.get("/api/status").status_code, 200)

    def test_forged_host_header_is_rejected(self):
        r = self.c.get("/api/status", headers={"Host": "evil.example.com"})
        self.assertEqual(r.status_code, 421)

    def test_security_headers_present(self):
        r = self.c.get("/api/status")
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_secrets_never_leak_value(self):
        secret = "AAAA" + "x" * 30
        r = self.put("/api/secrets/X_BEARER_TOKEN", {"value": secret})
        self.assertEqual(r.status_code, 200)
        for resp in (self.c.get("/api/secrets"), self.c.get("/api/status"), self.c.get("/api/export")):
            self.assertNotIn(secret, resp.text)
        st = self.c.get("/api/secrets").json()
        self.assertEqual(st["X_BEARER_TOKEN"], {"set": True, "source": "file", "hint": st["X_BEARER_TOKEN"]["hint"]})
        r2 = self.put("/api/secrets/X_BEARER_TOKEN", {"value": "bad short"})
        self.assertEqual(r2.status_code, 422)
        r3 = self.c.delete("/api/secrets/X_BEARER_TOKEN", headers={"X-Osw-Token": self.token})
        self.assertFalse(self.c.get("/api/secrets").json()["X_BEARER_TOKEN"]["set"])

    # -------------------------------------------------------------- watchlist & settings
    def test_watchlist_validation_errors_are_structured_and_nothing_partial_is_saved(self):
        r = self.put("/api/watchlist", {"twitter": ["nasa", "not a handle"], "telegram": [], "websites": [], "keywords": []})
        self.assertEqual(r.status_code, 422)
        self.assertTrue(any(e["list"] == "twitter" for e in r.json()["errors"]))
        self.assertEqual(self.c.get("/api/watchlist").json()["twitter"], [])  # rejected as a whole, nothing partial saved
        r2 = self.put("/api/watchlist", {"twitter": ["nasa"], "telegram": [], "websites": ["example.com"], "keywords": ["hypersonic"]})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(self.c.get("/api/watchlist").json()["twitter"], ["nasa"])

    def test_settings_validation_and_lockout_guard(self):
        r = self.put("/api/settings", {"polling": {"telegram": 5}})
        self.assertEqual(r.status_code, 422)
        r2 = self.put("/api/settings", {"server": {"host": "0.0.0.0"}})
        self.assertEqual(r2.status_code, 422)  # would need TLS - refused rather than risking lockout
        self.assertIn("tls", r2.json()["errors"][0].lower())

    def test_sources_view_reflects_watchlist_and_poll_now_is_accepted(self):
        r0 = self.put("/api/watchlist", {"twitter": [], "telegram": ["chan"], "websites": [], "keywords": ["test"]})
        self.assertEqual(r0.status_code, 200, r0.text)
        srcs = self.c.get("/api/sources").json()
        self.assertEqual([s["id"] for s in srcs], ["tg:chan"])
        r = self.post("/api/sources/poll", {"id": "tg:chan"})
        self.assertEqual(r.json()["queued"], 1)
        self.assertEqual(self.post("/api/sources/reset-backoff").status_code, 200)

    # -------------------------------------------------------------- diagnostics / maintenance
    def test_hardware_tor_and_maintenance_endpoints(self):
        h = self.c.get("/api/hardware").json()
        self.assertIn("cpu_cores", h)
        self.assertIsInstance(self.c.get("/api/tor").json()["found"], list)
        r = self.post("/api/maintenance/optimize")
        self.assertEqual(r.json()["integrity"], ["ok"])
        r2 = self.post("/api/maintenance/backup")
        self.assertTrue((self.a.paths.backups / r2.json()["file"]).exists())

    def test_notify_test_endpoint_does_not_crash_when_unconfigured(self):
        r = self.post("/api/notify/test/ntfy")
        self.assertIn("ok", r.json())

    def test_open_link_endpoint_reports_not_configured_by_default(self):
        r = self.post("/api/open", {"url": "https://example.com/"})
        self.assertEqual(r.json(), {"ok": False, "configured": False})
        self.assertEqual(self.post("/api/open", {"url": "javascript:alert(1)"}).status_code, 400)

    # -------------------------------------------------------------- end-to-end: HTTP -> engine -> alert
    def test_end_to_end_poll_produces_an_alert_visible_over_http(self):
        self.mock.route("/s/chan", fixture("telegram_channel.html"))
        r0 = self.put("/api/watchlist", {"twitter": [], "telegram": ["chan"], "websites": [], "keywords": ["hypersonic"]})
        self.assertEqual(r0.status_code, 200, r0.text)
        self.assertEqual(self.post("/api/sources/poll", {"id": "tg:chan"}).json()["queued"], 1)
        self._wait_for(lambda: self.a.store.get_state("tg:chan") and self.a.store.get_state("tg:chan")["baseline"] == 1)
        # add a brand-new post containing the keyword, then poll again
        extra = fixture("telegram_channel.html").replace(
            '<section class="tgme_channel_history js-message_history">',
            '<section class="tgme_channel_history js-message_history">'
            '<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="chan/999">'
            '<div class="tgme_widget_message_bubble"><div class="tgme_widget_message_text">Hypersonic missile test confirmed by officials'
            '<div class="tgme_widget_message_footer"><span class="tgme_widget_message_meta">'
            f'<a class="tgme_widget_message_date" href="https://t.me/chan/999"><time datetime="{datetime.now(timezone.utc).isoformat()}"></time></a>'
            '</span></div></div></div></div></div>')
        self.mock.route("/s/chan", extra)
        self.assertEqual(self.post("/api/sources/poll", {"id": "tg:chan"}).json()["queued"], 1)
        self._wait_for(lambda: len(self.c.get("/api/alerts").json()) >= 1)
        alerts = self.c.get("/api/alerts").json()
        self.assertEqual(alerts[0]["matched"], ["hypersonic"])
        self.assertEqual(alerts[0]["url"], "https://t.me/chan/999")
        items = self.c.get("/api/items").json()
        self.assertGreaterEqual(len(items), 4)  # 3 baseline + 1 new

    def _wait_for(self, cond, timeout=8.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if cond():
                    return
            except Exception:
                pass
            time.sleep(0.1)
        self.fail("condition not met in time")


if __name__ == "__main__":
    unittest.main()
