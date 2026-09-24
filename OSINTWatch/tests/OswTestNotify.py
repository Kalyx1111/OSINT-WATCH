import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from OswCore import redact  # noqa: E402
from OswFetch import Item  # noqa: E402
from OswNet import Net  # noqa: E402
from OswNotify import Alert, Bus, Dispatcher, alert_body, alert_title  # noqa: E402
from OswStore import Store  # noqa: E402
from OswTestKit import Mock, make_cfg  # noqa: E402


def alert(i=1, urgent=False, kind="telegram", source="@chan", matched=None):
    return Alert(i, kind, source, f"Title {i}", f"Body text {i} about missiles", f"https://t.me/chan/{i}",
                int(time.time()), matched or ["missile"], urgent, int(time.time()))


class DispatcherHarness:
    def __init__(self, tmp: Path, **settings):
        self.cfg = make_cfg(tmp, **settings)
        self.store = Store(tmp / "t.db")
        self.net = Net(self.cfg, sleep=lambda s: None)
        self.bus = Bus()
        self.d = Dispatcher(self.cfg, self.net, self.store, self.bus)
        self.d.start()

    def close(self):
        self.d.stop()
        self.store.close()

    def wait_idle(self, timeout=3.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.d._q.empty():
                time.sleep(0.6)  # let the 0.4s coalescing window and delivery finish
                return
            time.sleep(0.05)


class TextTests(unittest.TestCase):
    def test_title_and_body(self):
        a = alert(1, urgent=True, kind="web", source="news.example.com")
        self.assertEqual(alert_title(a), "URGENT: Web news.example.com")
        self.assertIn("Matched: missile", alert_body(a))
        d = Alert(0, "digest", "OSINT Watch", "3 new matches", "line1\nline2", "", 0, [], False, 0)
        self.assertEqual(alert_title(d), "3 new matches")


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_disabled_channels_still_publish_to_bus_only(self):
        h = DispatcherHarness(Path(self.tmp.name))
        try:
            q = h.bus.subscribe()
            h.d.submit(alert(1))
            ev = q.get(timeout=2)
            self.assertEqual((ev["type"], ev["id"]), ("alert", 1))
            h.wait_idle()
            self.assertEqual(h.store.list_alerts(), [])  # dispatcher never writes rows itself - none exist yet
        finally:
            h.close()

    def test_burst_over_limit_sends_singles_for_urgent_then_one_digest(self):
        h = DispatcherHarness(Path(self.tmp.name), notify={"desktop": True}, alerts={"burst_limit": 2})
        try:
            ids = []
            for sid in ("a", "b", "c"):
                h.store.upsert_state(sid, "telegram", sid, sid)
                iid = h.store.insert_items([Item(sid, "telegram", "1", f"https://t.me/{sid}/1", "t", "t")])[0][0]
                ids.append(h.store.add_alert(iid, ["missile"], urgent=(sid == "a")))
            with mock.patch("OswNotify.send_desktop", return_value="ok") as sender:
                h.d.submit(alert(ids[0], urgent=True))
                h.d.submit(alert(ids[1], urgent=False))
                h.d.submit(alert(ids[2], urgent=False))
                h.wait_idle()
                kinds = [c.args[0].kind for c in sender.call_args_list]
            self.assertEqual(kinds.count("digest"), 1)
            self.assertEqual(kinds.count("telegram"), 1)  # only the urgent one went as a single
            rows = {r["id"]: r for r in h.store.list_alerts()}
            import json
            self.assertEqual(json.loads(rows[ids[0]]["delivered"])["desktop"], "ok")
            self.assertIn("digest", json.loads(rows[ids[2]]["delivered"]))
        finally:
            h.close()

    def test_quiet_hours_holds_non_urgent_but_not_urgent(self):
        h = DispatcherHarness(Path(self.tmp.name), notify={"desktop": True},
                              alerts={"quiet_enabled": True, "quiet_start": "00:00", "quiet_end": "23:59"})
        try:
            h.store.upsert_state("a", "telegram", "a", "a")
            iid = h.store.insert_items([Item("a", "telegram", "1", "https://t.me/a/1", "t", "t")])[0][0]
            aid = h.store.add_alert(iid, ["missile"], False)
            with mock.patch("OswNotify.send_desktop", return_value="ok") as sender:
                h.d.submit(alert(aid, urgent=False))
                h.wait_idle()
                self.assertEqual(sender.call_count, 0)
            with mock.patch("OswNotify.send_desktop", return_value="ok") as sender:
                h.d.submit(alert(9999, urgent=True))
                h.wait_idle()
                self.assertEqual(sender.call_count, 1)
        finally:
            h.close()

    def test_quiet_hours_window_math(self):
        h = DispatcherHarness(Path(self.tmp.name), alerts={"quiet_enabled": True, "quiet_start": "23:00", "quiet_end": "06:00"})
        try:
            self.assertTrue(h.d.in_quiet_hours(datetime(2026, 1, 1, 23, 30)))
            self.assertTrue(h.d.in_quiet_hours(datetime(2026, 1, 1, 2, 0)))
            self.assertFalse(h.d.in_quiet_hours(datetime(2026, 1, 1, 12, 0)))
        finally:
            h.close()

    def test_channel_test_reports_failure_without_crashing(self):
        h = DispatcherHarness(Path(self.tmp.name))
        try:
            r = h.d.test("ntfy")  # NTFY_TOPIC not set
            self.assertFalse(r["ok"])
            self.assertIn("NTFY_TOPIC", r["detail"])
            self.assertEqual(h.d.test("nonsense")["ok"], False)
        finally:
            h.close()

    def test_notify_error_never_leaks_secret_into_state_or_logs(self):
        h = DispatcherHarness(Path(self.tmp.name))
        m = Mock()
        try:
            h.cfg.vault.set("TG_BOT_TOKEN", "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            h.cfg.vault.set("TG_CHAT_ID", "12345")
            import OswNotify
            old = OswNotify.TG_API
            OswNotify.TG_API = m.url()
            m.route("/bot123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage",
                   '{"ok": false, "description": "Forbidden: bot was blocked"}', status=403)
            r = h.d.test("tgbot")
            self.assertFalse(r["ok"])
            self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r["detail"])
            self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", h.d.state["tgbot"]["last_err"])
            self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", redact(str(m.hits)))
        finally:
            OswNotify.TG_API = old
            m.close()
            h.close()


if __name__ == "__main__":
    unittest.main()
