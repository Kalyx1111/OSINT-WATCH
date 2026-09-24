"""OSINT Watch - SQLite storage. Parameterized SQL only; one connection guarded by a lock.

By Aryan / @EPureNest
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from OswCore import log, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id TEXT NOT NULL, kind TEXT NOT NULL, uid TEXT NOT NULL,
  url TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '',
  author TEXT NOT NULL DEFAULT '', published INTEGER NOT NULL, fetched INTEGER NOT NULL,
  UNIQUE(source_id, uid));
CREATE INDEX IF NOT EXISTS ix_items_pub ON items(published DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_items_src ON items(source_id, id DESC);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL UNIQUE REFERENCES items(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, matched TEXT NOT NULL DEFAULT '[]', urgent INTEGER NOT NULL DEFAULT 0,
  delivered TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS source_state(
  source_id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
  etag TEXT NOT NULL DEFAULT '', last_modified TEXT NOT NULL DEFAULT '', feed_url TEXT NOT NULL DEFAULT '',
  meta TEXT NOT NULL DEFAULT '{}', baseline INTEGER NOT NULL DEFAULT 0,
  last_ok INTEGER NOT NULL DEFAULT 0, last_try INTEGER NOT NULL DEFAULT 0,
  last_err TEXT NOT NULL DEFAULT '', last_err_kind TEXT NOT NULL DEFAULT '', fails INTEGER NOT NULL DEFAULT 0,
  next_due INTEGER NOT NULL DEFAULT 0, item_count INTEGER NOT NULL DEFAULT 0, provider TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""

_STATE_COLS = {"label", "target", "etag", "last_modified", "feed_url", "meta", "baseline", "last_ok", "last_try",
               "last_err", "last_err_kind", "fails", "next_due", "item_count", "provider"}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._db = self._open()

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        db.executescript(SCHEMA)
        return db

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except sqlite3.Error:
                pass

    def reopen(self) -> None:
        with self._lock:
            self.close()
            self._db = self._open()

    # ---------------------------------------------------------- source state
    def upsert_state(self, sid: str, kind: str, label: str, target: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO source_state(source_id, kind, label, target) VALUES(?,?,?,?)",
                             (sid, kind, label, target))
            self._db.execute("UPDATE source_state SET target=? WHERE source_id=?", (target, sid))

    def get_state(self, sid: str) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM source_state WHERE source_id=?", (sid,)).fetchone()
        return self._state(r) if r else None

    @staticmethod
    def _state(r: sqlite3.Row) -> dict:
        d = dict(r)
        try:
            d["meta"] = json.loads(d.get("meta") or "{}")
        except ValueError:
            d["meta"] = {}
        return d

    def update_state(self, sid: str, **fields) -> None:
        cols = {k: v for k, v in fields.items() if k in _STATE_COLS}
        if not cols:
            return
        if isinstance(cols.get("meta"), dict):
            cols["meta"] = json.dumps(cols["meta"], separators=(",", ":"))
        sets = ", ".join(f"{k}=?" for k in cols)  # column names come from the allow-list above
        with self._lock:
            self._db.execute(f"UPDATE source_state SET {sets} WHERE source_id=?", (*cols.values(), sid))  # nosec B608

    def all_states(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM source_state ORDER BY kind, label").fetchall()
        return [self._state(r) for r in rows]

    def forget_sources(self, sids: list[str]) -> None:
        with self._lock:
            for sid in sids:
                self._db.execute("DELETE FROM items WHERE source_id=?", (sid,))
                self._db.execute("DELETE FROM source_state WHERE source_id=?", (sid,))

    def reset_backoff(self) -> int:
        with self._lock:
            cur = self._db.execute("UPDATE source_state SET fails=0, next_due=0 WHERE fails>0")
            return cur.rowcount

    # ---------------------------------------------------------- items
    def insert_items(self, items: list) -> list[tuple[int, object]]:
        """Insert new items; returns [(id, item)] only for rows that were actually new."""
        new: list[tuple[int, object]] = []
        ts = now()
        with self._lock:
            self._db.execute("BEGIN")
            try:
                for it in items:
                    cur = self._db.execute(
                        "INSERT OR IGNORE INTO items(source_id, kind, uid, url, title, text, author, published, fetched) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (it.source_id, it.kind, it.uid, it.url, it.title, it.text, it.author, it.published or ts, ts))
                    if cur.rowcount == 1:
                        new.append((cur.lastrowid, it))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return new

    def count_items(self, sid: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM items WHERE source_id=?", (sid,)).fetchone()[0]

    def get_item(self, item_id: int) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        return dict(r) if r else None

    def _rows(self, sql: str, args: list) -> list[dict]:
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["matched"] = json.loads(d["matched"]) if d.get("matched") else []
            d["urgent"] = bool(d.get("urgent"))
            out.append(d)
        return out

    def list_items(self, *, kind=None, source_id=None, q=None, before_id=None, limit=50) -> list[dict]:
        where, args = [], []
        if kind:
            where.append("i.kind=?"); args.append(kind)
        if source_id:
            where.append("i.source_id=?"); args.append(source_id)
        if q:
            where.append("(i.title LIKE ? ESCAPE '\\' OR i.text LIKE ? ESCAPE '\\' OR i.author LIKE ? ESCAPE '\\')")
            args += [_like(q)] * 3
        if before_id:
            where.append("i.id<?"); args.append(before_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = ("SELECT i.*, s.label AS source, a.id AS alert_id, a.matched AS matched, a.urgent AS urgent "  # nosec B608
               "FROM items i LEFT JOIN alerts a ON a.item_id=i.id LEFT JOIN source_state s ON s.source_id=i.source_id "
               f"{clause} ORDER BY i.id DESC LIMIT ?")
        return self._rows(sql, args + [limit])

    def list_alerts(self, *, before_id=None, limit=50) -> list[dict]:
        args: list = []
        clause = ""
        if before_id:
            clause = "WHERE a.id<?"; args.append(before_id)
        sql = ("SELECT i.*, s.label AS source, a.id AS alert_id, a.matched AS matched, a.urgent AS urgent, "  # nosec B608
               "a.created AS alert_created, a.delivered AS delivered "
               "FROM alerts a JOIN items i ON i.id=a.item_id LEFT JOIN source_state s ON s.source_id=i.source_id "
               f"{clause} ORDER BY a.id DESC LIMIT ?")
        return self._rows(sql, args + [limit])

    # ---------------------------------------------------------- alerts
    def add_alert(self, item_id: int, matched: list[str], urgent: bool) -> int:
        with self._lock:
            cur = self._db.execute("INSERT OR IGNORE INTO alerts(item_id, created, matched, urgent) VALUES(?,?,?,?)",
                                   (item_id, now(), json.dumps(matched, ensure_ascii=False), 1 if urgent else 0))
            if cur.rowcount == 0:
                return 0
            return cur.lastrowid

    def set_delivery(self, alert_id: int, delivered: dict) -> None:
        with self._lock:
            self._db.execute("UPDATE alerts SET delivered=? WHERE id=?", (json.dumps(delivered), alert_id))

    def counts(self) -> dict:
        with self._lock:
            c = self._db.cursor()
            items = c.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            a24 = c.execute("SELECT COUNT(*) FROM alerts WHERE created>?", (now() - 86400,)).fetchone()[0]
        return {"items": items, "alerts": alerts, "alerts_24h": a24}

    # ---------------------------------------------------------- housekeeping
    def prune(self, retention_days: int) -> int:
        cutoff = now() - retention_days * 86400
        with self._lock:
            n = self._db.execute("DELETE FROM items WHERE fetched<? AND id NOT IN (SELECT item_id FROM alerts)", (cutoff,)).rowcount
            n += self._db.execute("DELETE FROM items WHERE fetched<?", (now() - max(retention_days, 90) * 86400,)).rowcount
        return n

    def backup(self, dest: Path) -> None:
        with self._lock:
            dst = sqlite3.connect(str(dest))
            try:
                self._db.backup(dst)
            finally:
                dst.close()

    def integrity(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._db.execute("PRAGMA integrity_check").fetchall()]

    def optimize(self) -> None:
        with self._lock:
            self._db.execute("REINDEX")
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.execute("VACUUM")

    def meta_get(self, k: str, default: str = "") -> str:
        with self._lock:
            r = self._db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def meta_set(self, k: str, v: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO meta(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
