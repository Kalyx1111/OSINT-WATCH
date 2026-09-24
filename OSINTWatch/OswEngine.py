"""OSINT Watch - polling engine.

* one scheduler thread + small worker pool; per-source next-due times persisted in SQLite
* first successful poll of a source is a silent BASELINE (existing posts are stored, never alerted)
* new item -> keyword match -> alert row -> dispatcher (desktop / phone / dashboard)
* failures back off exponentially (Retry-After honoured); privacy/config problems re-check every 20 s
By Aryan / @EPureNest
"""
from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

from OswConfig import Config
from OswCore import clip, log, new_cid, now
from OswFetch import Fetchers, Source
from OswMatch import Matcher
from OswNet import Net, NetError
from OswNotify import Alert, Dispatcher
from OswStore import Store


@dataclass
class _Entry:
    src: Source
    next_due: float
    running: bool = False


def sources_from_watchlist(wl: dict) -> dict[str, Source]:
    out: dict[str, Source] = {}
    for h in wl["twitter"]:
        out[f"tw:{h}"] = Source(f"tw:{h}", "twitter", h, "@" + h)
    for c in wl["telegram"]:
        out[f"tg:{c}"] = Source(f"tg:{c}", "telegram", c, "@" + c)
    for u in wl["websites"]:
        out[f"web:{u}"] = Source(f"web:{u}", "web", u, urlsplit(u).hostname or u)
    return out


class Engine:
    def __init__(self, cfg: Config, net: Net, store: Store, dispatcher: Dispatcher, default_workers: int = 4,
                 fetchers: Fetchers | None = None):
        self.cfg, self.net, self.store, self.dispatcher = cfg, net, store, dispatcher
        self.fetchers = fetchers or Fetchers(net, cfg)
        self.default_workers = default_workers
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._sched: dict[str, _Entry] = {}
        self.matcher = Matcher([])
        self._pool: ThreadPoolExecutor | None = None
        self._thread: threading.Thread | None = None
        self._last_log: dict[str, str] = {}
        self.started_at = 0

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        workers = self.cfg.settings["polling"]["workers"] or self.default_workers
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="osw-poll")
        self.reload()
        self.started_at = now()
        self._thread = threading.Thread(target=self._loop, name="osw-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def interval(self, kind: str) -> float:
        p = self.cfg.settings["polling"]
        return float(p[kind if kind in ("telegram", "twitter") else "web"])

    def _jitter(self, seconds: float) -> float:
        j = self.cfg.settings["polling"]["jitter"]
        return seconds * (1 + random.uniform(-j, j))  # nosec B311 - scheduling jitter, not security

    def reload(self) -> None:
        """Re-read watchlist: add new sources, drop removed ones (and their stored data), rebuild the matcher."""
        wl = self.cfg.watchlist
        new = sources_from_watchlist(wl)
        with self._lock:
            for sid in [s for s in self._sched if s not in new]:
                del self._sched[sid]
            for sid, src in new.items():
                self.store.upsert_state(sid, src.kind, src.label, src.target)
                if sid not in self._sched:
                    st = self.store.get_state(sid) or {}
                    first = random.uniform(0, min(self.interval(src.kind), 45))  # nosec B311
                    self._sched[sid] = _Entry(src, max(time.time() + first, float(st.get("next_due") or 0)))
            self.matcher = Matcher.from_entries(wl["keywords"])
        stale = [s["source_id"] for s in self.store.all_states() if s["source_id"] not in new]
        if stale:
            self.store.forget_sources(stale)
        self._wake.set()

    def poll_now(self, source_id: str | None = None) -> int:
        n = 0
        with self._lock:
            for sid, e in self._sched.items():
                if (source_id is None or sid == source_id) and not e.running:
                    e.next_due, n = 0.0, n + 1
        self._wake.set()
        return n

    # ------------------------------------------------------------ scheduler
    def _loop(self) -> None:
        while not self._stop.is_set():
            t = time.time()
            due: list[_Entry] = []
            nxt = t + 5
            with self._lock:
                for e in self._sched.values():
                    if e.running:
                        continue
                    if e.next_due <= t:
                        due.append(e)
                    else:
                        nxt = min(nxt, e.next_due)
                due.sort(key=lambda e: e.next_due)
                for e in due:
                    e.running = True
            for e in due:
                try:
                    self._pool.submit(self._run, e)  # type: ignore[union-attr]
                except RuntimeError:  # pool shut down
                    return
            self._wake.wait(timeout=max(0.2, min(5.0, nxt - time.time())))
            self._wake.clear()

    def _run(self, e: _Entry) -> None:
        try:
            self._poll_one(e)
        except Exception:
            cid = new_cid()
            log.exception("poll crashed [%s] %s", cid, e.src.id)
            self._fail(e, f"internal error (ref {cid})", "internal", None)
        finally:
            with self._lock:
                e.running = False
            self._wake.set()

    # ------------------------------------------------------------ one poll
    def _poll_one(self, e: _Entry) -> None:
        src = e.src
        st = self.store.get_state(src.id) or {}
        try:
            res = self.fetchers.poll(src, st)
        except NetError as ex:
            self._fail(e, str(ex), ex.kind, ex.retry_after)
            return
        with self._lock:
            if src.id not in self._sched:  # removed while in flight
                return
        new_rows = self.store.insert_items(res.items) if res.items else []
        t = now()
        upd: dict = {"last_ok": t, "last_try": t, "fails": 0, "last_err": "", "last_err_kind": "",
                     "item_count": self.store.count_items(src.id)}
        for k in ("etag", "last_modified", "feed_url", "label", "provider"):
            if k in res.fields:
                upd[k] = res.fields[k]
        if res.meta:
            upd["meta"] = {**(st.get("meta") or {}), **res.meta}
        delay = self._jitter(self.interval(src.kind))
        upd["next_due"] = int(t + delay)
        first_poll = not st.get("baseline")
        if first_poll:
            upd["baseline"] = 1
        self.store.update_state(src.id, **upd)
        with self._lock:
            e.next_due = time.time() + delay
        self._last_log.pop(src.id, None)
        if not first_poll and new_rows:
            self._evaluate(src, upd.get("label") or st.get("label") or src.label, new_rows)

    def _evaluate(self, src: Source, label: str, rows: list) -> None:
        s = self.cfg.settings["alerts"]
        cutoff = now() - s["max_age_hours"] * 3600
        with self._lock:
            matcher = self.matcher
        for item_id, it in sorted(rows, key=lambda r: r[1].published or 0):
            if it.published and it.published < cutoff:
                continue  # old post surfacing late (feed re-order): stored, not alerted
            text = f"{it.title}\n{it.text}"
            if s["mode"] == "all":
                if matcher.excluded(text):
                    continue
                labels, urgent = ["(all posts)"], False
            else:
                hits = matcher.match(text)
                if not hits:
                    continue
                labels, urgent = [r.label for r in hits], any(r.urgent for r in hits)
            aid = self.store.add_alert(item_id, labels, urgent)
            if aid:
                self.dispatcher.submit(Alert(aid, src.kind, label, clip(it.title, 300), it.text, it.url,
                                             it.published or now(), labels, urgent, now()))

    def _fail(self, e: _Entry, msg: str, kind: str, retry_after: int | None) -> None:
        st = self.store.get_state(e.src.id) or {}
        fails = int(st.get("fails") or 0) + 1
        mx = self.cfg.settings["polling"]["max_backoff"]
        if kind in ("privacy", "config"):
            delay = 20.0  # waiting for the user to fix Settings: cheap re-check
        elif kind == "auth":
            delay = float(mx)
        else:
            delay = min(float(mx), self.interval(e.src.kind) * (2 ** min(fails, 6)))
        if retry_after:
            delay = min(float(mx), max(delay, float(retry_after)))
        delay = self._jitter(delay)
        t = now()
        self.store.update_state(e.src.id, fails=fails, last_try=t, last_err=clip(msg, 300), last_err_kind=kind, next_due=int(t + delay))
        with self._lock:
            e.next_due = time.time() + delay
        if self._last_log.get(e.src.id) != msg:  # log a given failure once, not every retry
            self._last_log[e.src.id] = msg
            log.warning("poll failed %s: %s", e.src.id, msg)

    # ------------------------------------------------------------ status for UI
    @staticmethod
    def health(st: dict, running: bool) -> str:
        if st.get("fails", 0) > 0 and st.get("last_err_kind") in ("privacy", "config", "auth"):
            return "paused"
        if st.get("fails", 0) >= 3:
            return "failing"
        if st.get("fails", 0) > 0:
            return "retrying"
        if not st.get("last_ok"):
            return "polling" if running else "waiting"
        return "ok"

    def sources_view(self) -> list[dict]:
        with self._lock:
            entries = {sid: (e.src, e.running) for sid, e in self._sched.items()}
        out = []
        for st in self.store.all_states():
            if st["source_id"] not in entries:
                continue
            src, running = entries[st["source_id"]]
            out.append({"id": src.id, "kind": src.kind, "target": src.target, "label": st["label"] or src.label,
                        "state": self.health(st, running), "running": running, "last_ok": st["last_ok"], "last_try": st["last_try"],
                        "error": st["last_err"], "error_kind": st["last_err_kind"], "fails": st["fails"],
                        "next_due": st["next_due"], "items": st["item_count"], "provider": st["provider"]})
        return out
