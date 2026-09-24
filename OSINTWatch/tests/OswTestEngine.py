import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from OswEngine import Engine, sources_from_watchlist  # noqa: E402
from OswFetch import Item, PollResult  # noqa: E402
from OswNet import Net, NetError  # noqa: E402
from OswNotify import Alert  # noqa: E402
from OswStore import Store  # noqa: E402
from OswTestKit import make_cfg  # noqa: E402


class FakeFetchers:
    """Scripted responses per source id: a list of PollResult/NetError to return, one per call."""

    def __init__(self):
        self.plan: dict[str, list] = {}
        self.calls: list[str] = []

    def queue(self, sid: str, *results):
        self.plan.setdefault(sid, []).extend(results)

    def poll(self, src, state):
        self.calls.append(src.id)
        q = self.plan.get(src.id)
        if not q:
            return PollResult([])
        r = q.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def item(sid, uid, text="hello", title=None, pub=None):
    return Item(sid, "telegram", uid, f"https://t.me/x/{uid}", title or text, text, "@x", pub if pub is not None else int(time.time()))


class FakeDispatcher:
    """Engine only calls .submit(alert) - capture synchronously, no background thread needed here."""

    def __init__(self):
        self.delivered: list[Alert] = []

    def submit(self, alert: Alert) -> None:
        self.delivered.append(alert)


class Harness:
    def __init__(self, tmp: Path, **settings):
        self.cfg = make_cfg(tmp, **settings)
        self.store = Store(tmp / "t.db")
        self.net = Net(self.cfg, sleep=lambda s: None)
        self.dispatcher = FakeDispatcher()
        self.fetchers = FakeFetchers()
        self.engine = Engine(self.cfg, self.net, self.store, self.dispatcher, fetchers=self.fetchers)

    @property
    def delivered(self):
        return self.dispatcher.delivered

    def close(self):
        self.store.close()

    def set_watchlist(self, **wl):
        base = {"twitter": [], "telegram": [], "websites": [], "keywords": []}
        base.update(wl)
        errs = self.cfg.save_watchlist(base)
        assert not errs, errs
        self.engine.reload()

    def entry(self, sid):
        return self.engine._sched[sid]

    def poll(self, sid):
        self.engine._poll_one(self.entry(sid))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.h = Harness(Path(self.tmp.name))

    def tearDown(self):
        self.h.close()
        self.tmp.cleanup()

    def test_first_poll_is_a_silent_baseline(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["hello"])
        self.h.fetchers.queue("tg:chan", PollResult([item("tg:chan", "1"), item("tg:chan", "2")]))
        self.h.poll("tg:chan")
        self.assertEqual(self.h.delivered, [])  # existing history never alerts
        self.assertEqual(self.h.store.count_items("tg:chan"), 2)
        st = self.h.store.get_state("tg:chan")
        self.assertEqual((st["baseline"], st["fails"]), (1, 0))

    def test_new_item_after_baseline_triggers_keyword_alert_with_link(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["hypersonic"])
        self.h.fetchers.queue("tg:chan", PollResult([item("tg:chan", "1", text="quiet post")]),
                              PollResult([item("tg:chan", "2", text="A Hypersonic test today")]))
        self.h.poll("tg:chan")
        self.h.poll("tg:chan")
        self.assertEqual(len(self.h.delivered), 1)
        a = self.h.delivered[0]
        self.assertEqual((a.matched, a.urgent, a.url), (["hypersonic"], False, "https://t.me/x/2"))
        self.assertEqual(len(self.h.store.list_alerts()), 1)

    def test_urgent_keyword_and_exclusion(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["!hypersonic", "missile", "-drill"])
        self.h.fetchers.queue("tg:chan", PollResult([]))
        self.h.poll("tg:chan")
        self.h.fetchers.queue("tg:chan", PollResult([item("tg:chan", "1", text="hypersonic glide test"),
                                                     item("tg:chan", "2", text="missile drill announced"),
                                                     item("tg:chan", "3", text="missile launch confirmed")]))
        self.h.poll("tg:chan")
        by_uid = {a.url.rsplit("/", 1)[1]: a for a in self.h.delivered}
        self.assertEqual(set(by_uid), {"1", "3"})  # "2" excluded by -drill
        self.assertTrue(by_uid["1"].urgent)
        self.assertFalse(by_uid["3"].urgent)

    def test_duplicate_items_across_polls_do_not_realert(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["missile"])
        self.h.fetchers.queue("tg:chan", PollResult([]))
        self.h.poll("tg:chan")
        same = item("tg:chan", "1", text="missile test")
        self.h.fetchers.queue("tg:chan", PollResult([same]), PollResult([same]))
        self.h.poll("tg:chan")
        self.h.poll("tg:chan")
        self.assertEqual(len(self.h.delivered), 1)

    def test_old_post_surfacing_late_is_stored_but_not_alerted(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["missile"], )
        self.h.cfg.save_settings({"alerts": {"max_age_hours": 1}})
        self.h.fetchers.queue("tg:chan", PollResult([]))
        self.h.poll("tg:chan")
        old = item("tg:chan", "1", text="missile test", pub=int(time.time()) - 7200)
        self.h.fetchers.queue("tg:chan", PollResult([old]))
        self.h.poll("tg:chan")
        self.assertEqual(self.h.delivered, [])
        self.assertEqual(self.h.store.count_items("tg:chan"), 1)

    def test_alert_all_mode_still_honours_exclusions(self):
        self.h.set_watchlist(telegram=["chan"], keywords=["-spam"])
        self.h.cfg.save_settings({"alerts": {"mode": "all"}})
        self.h.fetchers.queue("tg:chan", PollResult([]))
        self.h.poll("tg:chan")
        self.h.fetchers.queue("tg:chan", PollResult([item("tg:chan", "1", text="normal post"), item("tg:chan", "2", text="spam post")]))
        self.h.poll("tg:chan")
        self.assertEqual([a.url for a in self.h.delivered], ["https://t.me/x/1"])

    def test_backoff_grows_and_privacy_error_rechecks_fast(self):
        self.h.set_watchlist(telegram=["chan"])
        self.h.fetchers.queue("tg:chan", NetError("blocked", kind="blocked"), NetError("blocked", kind="blocked"))
        self.h.poll("tg:chan")
        st1 = self.h.store.get_state("tg:chan")
        self.h.poll("tg:chan")
        st2 = self.h.store.get_state("tg:chan")
        self.assertEqual((st1["fails"], st2["fails"]), (1, 2))
        self.assertGreater(st2["next_due"], st1["next_due"])
        self.h.fetchers.queue("tg:chan", NetError("paused", kind="privacy"))
        self.h.poll("tg:chan")
        st3 = self.h.store.get_state("tg:chan")
        self.assertLess(st3["next_due"] - int(time.time()), 30)  # cheap re-check, not exponential backoff

    def test_reload_adds_and_forgets_sources_and_their_data(self):
        self.h.set_watchlist(telegram=["chana", "chanb"], keywords=["xx"])
        self.h.fetchers.queue("tg:chana", PollResult([item("tg:chana", "1")]))
        self.h.fetchers.queue("tg:chanb", PollResult([item("tg:chanb", "1")]))
        self.h.poll("tg:chana")
        self.h.poll("tg:chanb")
        self.assertEqual(self.h.store.counts()["items"], 2)
        self.h.set_watchlist(telegram=["chana"], keywords=["xx"])  # "chanb" removed
        self.assertNotIn("tg:chanb", self.h.engine._sched)
        self.assertEqual(self.h.store.counts()["items"], 1)
        self.assertIsNone(self.h.store.get_state("tg:chanb"))

    def test_sources_from_watchlist_ids_are_stable(self):
        s = sources_from_watchlist({"twitter": ["nasa"], "telegram": ["durov"], "websites": ["https://e.com/"], "keywords": []})
        self.assertEqual(set(s), {"tw:nasa", "tg:durov", "web:https://e.com/"})


if __name__ == "__main__":
    unittest.main()
