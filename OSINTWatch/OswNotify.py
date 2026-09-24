"""OSINT Watch - alert delivery.

Channels: desktop toast (Windows/macOS/Linux) | ntfy push (phone) | Telegram bot (phone) | Termux (Android) | dashboard (SSE).
All post text is untrusted: it reaches native APIs only through environment variables / escaped XML / JSON, never a shell string.
By Aryan / @EPureNest
"""
from __future__ import annotations

import base64
import json
import os
import queue
import shlex
import shutil
import subprocess  # nosec B404 - fixed argv only, no shell
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from OswConfig import Config
from OswCore import IS_TERMUX, IS_WINDOWS, clip, log, now, safe_http_url
from OswNet import Net, NetError, decode_body
from OswStore import Store

TG_API = "https://api.telegram.org"
KIND_NAME = {"twitter": "X", "telegram": "Telegram", "web": "Web", "digest": "OSINT Watch", "test": "OSINT Watch"}


class NotifyError(Exception):
    pass


@dataclass
class Alert:
    alert_id: int
    kind: str
    source: str
    title: str
    text: str
    url: str
    published: int = 0
    matched: list = field(default_factory=list)
    urgent: bool = False
    created: int = 0


def alert_title(a: Alert) -> str:
    if a.kind in ("digest", "test"):
        return a.title
    return f"{'URGENT: ' if a.urgent else ''}{KIND_NAME.get(a.kind, a.kind)} {a.source}".strip()


def alert_body(a: Alert, limit: int = 300) -> str:
    if a.kind in ("digest", "test"):
        return clip(a.text, limit)
    kw = ", ".join(m for m in a.matched[:5] if m != "(all posts)")
    return (f"Matched: {kw}\n" if kw else "") + clip(a.text or a.title, limit)


def alert_event(a: Alert) -> dict:
    return {"type": "alert", "id": a.alert_id, "kind": a.kind, "source": a.source, "title": a.title, "text": clip(a.text, 600),
            "url": a.url, "published": a.published, "created": a.created, "matched": a.matched, "urgent": a.urgent}


class Bus:
    """In-process pub/sub used by the dashboard's live stream."""

    def __init__(self):
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass


# ------------------------------------------------------------------ desktop
_PS_TOAST = r"""
$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$t = [System.Security.SecurityElement]::Escape($env:OSW_T)
$b = [System.Security.SecurityElement]::Escape($env:OSW_B)
$u = [System.Security.SecurityElement]::Escape($env:OSW_U)
$launch = ''
if ($u) { $launch = ' activationType="protocol" launch="' + $u + '"' }
$xml = '<toast' + $launch + '><visual><binding template="ToastGeneric"><text>' + $t + '</text><text>' + $b + '</text></binding></visual></toast>'
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
"""


def _run(argv: list[str], env_extra: dict | None = None, timeout: int = 20) -> None:
    env = dict(os.environ)
    env.update(env_extra or {})
    kw = {"creationflags": 0x08000000} if IS_WINDOWS else {}
    try:
        r = subprocess.run(argv, env=env, capture_output=True, timeout=timeout, check=False, **kw)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as e:
        raise NotifyError(f"could not run {os.path.basename(argv[0])} ({type(e).__name__})") from None
    if r.returncode != 0:
        raise NotifyError(f"{os.path.basename(argv[0])} failed: " + clip(r.stderr.decode("utf-8", "replace").strip(), 200))


def send_desktop(a: Alert) -> str:
    title, body, url = clip(alert_title(a), 90), clip(alert_body(a, 250), 250), (safe_http_url(a.url) or "")
    env = {"OSW_T": title, "OSW_B": body, "OSW_U": url}
    if IS_WINDOWS:
        ps = shutil.which("powershell.exe") or shutil.which("powershell")
        if not ps:
            raise NotifyError("powershell.exe not found")
        enc = base64.b64encode(_PS_TOAST.encode("utf-16-le")).decode("ascii")
        _run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc], env)
    elif sys.platform == "darwin":
        _run(["osascript", "-e", 'display notification (system attribute "OSW_B") with title (system attribute "OSW_T")'], env)
    else:
        exe = shutil.which("notify-send")
        if not exe:
            raise NotifyError("notify-send not found (install libnotify-bin) - the dashboard still shows alerts")
        _run([exe, "-a", "OSINT Watch", "-u", "critical" if a.urgent else "normal", "--", title, body + ("\n" + url if url else "")])
    return "ok"


def send_termux(a: Alert) -> str:
    exe = shutil.which("termux-notification")
    if not exe:
        raise NotifyError("termux-notification not found (install the Termux:API app and: pkg install termux-api)")
    argv = [exe, "--title", clip(alert_title(a), 90), "--content", clip(alert_body(a, 300), 300), "--priority", "high",
            "--group", "osint-watch", "--id", str(a.alert_id or 1)]
    url = safe_http_url(a.url)
    if url:
        argv += ["--action", "termux-open-url " + shlex.quote(url)]
    _run(argv)
    return "ok"


# ------------------------------------------------------------------ phone push
def send_ntfy(net: Net, cfg: Config, a: Alert) -> str:
    topic = cfg.vault.get("NTFY_TOPIC")
    if not topic:
        raise NotifyError("NTFY_TOPIC is not set")
    url = safe_http_url(a.url)
    payload = {"topic": topic, "title": clip(alert_title(a), 120), "message": clip(alert_body(a, 900), 900),
               "priority": 5 if a.urgent else 4, "tags": ["rotating_light" if a.urgent else "mag"]}
    if url:
        payload["click"] = url
        payload["actions"] = [{"action": "view", "label": "Open source", "url": url, "clear": True}]
    token = cfg.vault.get("NTFY_TOKEN")
    try:
        net.post_json(cfg.settings["notify"]["ntfy_server"] + "/", payload, headers={"Authorization": f"Bearer {token}"} if token else {},
                      purpose="notify", timeout=25, max_bytes=100_000)
    except NetError as e:
        raise NotifyError(f"ntfy: {e}") from None
    return "ok"


def send_tgbot(net: Net, cfg: Config, a: Alert) -> str:
    token, chat = cfg.vault.get("TG_BOT_TOKEN"), cfg.vault.get("TG_CHAT_ID")
    if not token or not chat:
        raise NotifyError("TG_BOT_TOKEN and TG_CHAT_ID must both be set")
    text = f"{alert_title(a)}\n{alert_body(a, 3000)}" + (f"\n{a.url}" if a.url else "")
    body = {"chat_id": int(chat) if chat.lstrip("-").isdigit() else chat, "text": clip(text, 4000),
            "link_preview_options": {"is_disabled": True}}
    try:
        res = net.post_json(f"{TG_API}/bot{token}/sendMessage", body, purpose="notify", timeout=25, max_bytes=100_000)
        d = json.loads(decode_body(res))
    except NetError as e:
        raise NotifyError(f"Telegram bot: {e}") from None
    except ValueError:
        raise NotifyError("Telegram bot: unreadable reply") from None
    if not d.get("ok"):
        raise NotifyError("Telegram bot: " + clip(str(d.get("description") or "rejected"), 120))
    return "ok"


# ------------------------------------------------------------------ dispatcher
class Dispatcher:
    def __init__(self, cfg: Config, net: Net, store: Store, bus: Bus):
        self.cfg, self.net, self.store, self.bus = cfg, net, store, bus
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="osw-notify", daemon=True)
        self.state = {c: {"last_ok": 0, "last_err": ""} for c in ("desktop", "ntfy", "tgbot", "termux")}

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning("notify dispatcher did not stop within %ss (a delivery may still be in flight)", timeout)

    def submit(self, a: Alert) -> None:
        self._q.put(a)

    # ---- channel plumbing
    def _senders(self) -> dict:
        return {"desktop": lambda a: send_desktop(a), "ntfy": lambda a: send_ntfy(self.net, self.cfg, a),
                "tgbot": lambda a: send_tgbot(self.net, self.cfg, a), "termux": lambda a: send_termux(a)}

    def _enabled(self) -> list[str]:
        n = self.cfg.settings["notify"]
        return [c for c in ("desktop", "ntfy", "tgbot", "termux") if n.get(c)]

    def _send(self, channel: str, a: Alert) -> str:
        for attempt in (1, 2):
            try:
                self._senders()[channel](a)
                self.state[channel].update(last_ok=now(), last_err="")
                return "ok"
            except NotifyError as e:
                msg = str(e)
                transient = "timed out" in msg or "network error" in msg or "cannot" in msg
                if attempt == 1 and transient and not self._stop.is_set():
                    time.sleep(2)
                    continue
                self.state[channel]["last_err"] = clip(msg, 200)
                log.warning("notify %s failed: %s", channel, msg)
                return "error: " + clip(msg, 160)
            except Exception as e:  # never let a notifier kill the dispatcher
                self.state[channel]["last_err"] = f"internal error ({type(e).__name__})"
                log.exception("notify %s crashed", channel)
                return "error: internal"
        return "error"

    def test(self, channel: str) -> dict:
        if channel not in self.state:
            return {"ok": False, "detail": "unknown channel"}
        a = Alert(0, "test", "Test", "OSINT Watch test alert", "If you can read this, this channel works. "
                  "Real alerts show the matched keywords, the post text and a link to the source.", "https://example.com/",
                  now(), ["test"], False, now())
        res = self._send(channel, a)
        return {"ok": res == "ok", "detail": "delivered" if res == "ok" else res[7:]}

    def status(self) -> dict:
        cfgd = self.cfg.settings["notify"]
        v = self.cfg.vault
        conf = {"desktop": True, "ntfy": bool(v.get("NTFY_TOPIC")), "tgbot": bool(v.get("TG_BOT_TOKEN") and v.get("TG_CHAT_ID")),
                "termux": IS_TERMUX or bool(shutil.which("termux-notification"))}
        return {c: {"enabled": bool(cfgd.get(c)), "configured": conf[c], **self.state[c]} for c in self.state}

    def in_quiet_hours(self, at: datetime | None = None) -> bool:
        s = self.cfg.settings["alerts"]
        if not s["quiet_enabled"]:
            return False
        hhmm = (at or datetime.now()).strftime("%H:%M")
        start, end = s["quiet_start"], s["quiet_end"]
        return (start <= hhmm < end) if start <= end else (hhmm >= start or hhmm < end)

    # ---- worker
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                first = self._q.get(timeout=1)
            except queue.Empty:
                continue
            batch = [first]
            end = time.monotonic() + 0.4
            while time.monotonic() < end and len(batch) < 200:  # coalesce bursts
                try:
                    batch.append(self._q.get(timeout=0.1))
                except queue.Empty:
                    break
            try:
                self.deliver(batch)
            except Exception:
                log.exception("dispatcher crashed on a batch")

    def deliver(self, batch: list[Alert]) -> None:
        for a in batch:
            self.bus.publish(alert_event(a))  # dashboard + browser notifications always get it
        channels = self._enabled()
        if not channels:
            return
        quiet = self.in_quiet_hours()
        ext = [a for a in batch if a.urgent or not quiet]
        for a in batch:
            if a not in ext:
                self.store.set_delivery(a.alert_id, {"external": "held: quiet hours"})
        limit = self.cfg.settings["alerts"]["burst_limit"]
        if len(ext) <= limit:
            singles, digest = ext, []
        else:
            singles = [a for a in ext if a.urgent][:limit]
            digest = [a for a in ext if a not in singles]
        for a in singles:
            self.store.set_delivery(a.alert_id, {c: self._send(c, a) for c in channels})
        if digest:
            lines = [f"{KIND_NAME.get(d.kind, d.kind)} {d.source}: {clip(d.title or d.text, 80)}" for d in digest[:6]]
            more = f"\n+{len(digest) - 6} more" if len(digest) > 6 else ""
            summary = Alert(0, "digest", "OSINT Watch", f"{len(digest)} new matches", "\n".join(lines) + more,
                            digest[0].url, now(), [], False, now())
            res = {c: self._send(c, summary) for c in channels}
            for d in digest:
                self.store.set_delivery(d.alert_id, {"digest": res})
