"""OSINT Watch - the only place that touches the network.

Privacy rules enforced here:
  * strict mode: no proxy configured -> NO request is made (fail closed)
  * a dead proxy never falls back to a direct connection
  * proxied requests send the host NAME to the proxy (remote DNS) - nothing is resolved locally
  * no cookies kept, no Referer, generic User-Agent, ambient proxy/env settings ignored (trust_env=False)
  * redirects are followed manually and every hop is re-validated (SSRF guard, no https->http downgrade)
  * hard caps on response size and wall-clock time; per-host pacing
By Aryan / @EPureNest
"""
from __future__ import annotations

import email.utils
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from OswConfig import Config, normalize_proxy
from OswCore import host_is_blocked, ip_is_public, log, parse_ip

_REDIRECTS = (301, 302, 303, 307, 308)
_ACCEPT = {
    "fetch": "text/html,application/xhtml+xml,application/xml;q=0.9,application/rss+xml;q=0.9,text/xml;q=0.8,*/*;q=0.5",
    "api": "application/json",
    "notify": "application/json",
    "robots": "text/plain,*/*;q=0.5",
}


class NetError(Exception):
    """kind: privacy | proxy | network | timeout | tls | http | blocked | robots | config | parse"""

    def __init__(self, msg: str, *, kind: str = "network", status: int | None = None,
                 retry_after: int | None = None, body: bytes = b""):
        super().__init__(msg)
        self.kind, self.status, self.retry_after, self.body = kind, status, retry_after, body


@dataclass
class Response:
    status: int
    url: str
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    not_modified: bool = False


def _retry_after(v: str | None) -> int | None:
    if not v:
        return None
    v = v.strip()
    if v.isdigit():
        return min(int(v), 86400)
    try:
        return max(0, min(int(email.utils.parsedate_to_datetime(v).timestamp() - time.time()), 86400))
    except (TypeError, ValueError, OverflowError):
        return None


def decode_body(res: Response) -> str:
    m = re.search(r"charset=([\w.-]+)", res.headers.get("content-type", ""), re.I)
    enc = m.group(1) if m else None
    if not enc:
        head = res.body[:2048]
        m2 = re.search(rb"""<meta[^>]+charset=["']?([\w.-]+)""", head, re.I) or re.search(rb"""^\s*<\?xml[^>]+encoding=["']([\w.-]+)""", head, re.I)
        enc = m2.group(1).decode("ascii", "ignore") if m2 else "utf-8"
    try:
        return res.body.decode(enc, errors="replace")
    except LookupError:
        return res.body.decode("utf-8", errors="replace")


def detect_local_tor(timeout: float = 0.6) -> list[dict]:
    """Find a local SOCKS5 listener that looks like Tor (Tor Browser 9150 / tor daemon 9050)."""
    found = []
    for port, name in ((9150, "Tor Browser"), (9050, "Tor service")):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) == b"\x05\x00":
                    found.append({"port": port, "name": name, "proxy": f"socks5h://127.0.0.1:{port}"})
        except OSError:
            continue
    return found


class Net:
    def __init__(self, cfg: Config, sleep=time.sleep):
        self.cfg = cfg
        self._sleep = sleep
        self._gap_lock = threading.Lock()
        self._next_ok: dict[str, float] = {}
        self._robots: dict[str, tuple[float, RobotFileParser | None]] = {}
        self._iso_salt = secrets.token_hex(8)
        self.min_gap = 1.5

    # ------------------------------------------------------------ privacy state
    def proxy_url(self, host: str | None = None) -> str | None:
        secret = self.cfg.vault.get("PROXY_URL")
        try:
            p = normalize_proxy(secret, allow_creds=True) if secret else self.cfg.settings["privacy"]["proxy"]
        except ValueError:
            log.warning("PROXY_URL secret is malformed - ignored")
            p = self.cfg.settings["privacy"]["proxy"]
        if not p:
            return None
        if self.cfg.settings["privacy"]["isolate_streams"] and p.startswith("socks5h://") and "@" not in p and host:
            token = hashlib.sha256((host + self._iso_salt).encode()).hexdigest()[:16]
            p = p.replace("socks5h://", f"socks5h://osw:{token}@", 1)
        return p

    def privacy_state(self) -> dict:
        priv = self.cfg.settings["privacy"]
        p = self.proxy_url(None)
        shown = None
        if p:
            sp = urlsplit(p)
            shown = f"{sp.scheme}://{sp.hostname}:{sp.port}"
        return {"mode": priv["mode"], "proxy_set": bool(p), "proxy": shown, "paused": priv["mode"] == "strict" and not p,
                "proxy_from": "secret" if self.cfg.vault.get("PROXY_URL") else ("settings" if p else None),
                "isolate_streams": priv["isolate_streams"]}

    def _proxy_for(self, host: str, purpose: str) -> str | None:
        priv = self.cfg.settings["privacy"]
        if purpose == "notify":
            if host_is_blocked(host) or not priv["route_notifiers"]:
                return None  # LAN notifier (e.g. self-hosted ntfy) or user opted out: direct
        p = self.proxy_url(host)
        if p is None and priv["mode"] == "strict":
            raise NetError("Fetching is paused: no proxy configured (privacy mode is strict). "
                           "Add a proxy or switch to open mode in Settings.", kind="privacy")
        return p

    # ------------------------------------------------------------ guards
    def _check_url(self, url: str, allow_private: bool):
        if len(url) > 2048:
            raise NetError("URL too long", kind="blocked")
        try:
            p = urlsplit(url)
            host = p.hostname
            p.port  # noqa: B018 - validates the port
        except ValueError:
            raise NetError("invalid URL", kind="blocked") from None
        if p.scheme not in ("http", "https") or not host or p.username or p.password:
            raise NetError("only plain http(s) URLs without credentials are allowed", kind="blocked")
        if not allow_private and host_is_blocked(host):
            raise NetError("blocked: local/private address", kind="blocked")
        return p

    @staticmethod
    def _resolve_check(host: str) -> None:
        """Direct (unproxied) connections only: every resolved address must be public."""
        if parse_ip(host) is not None:
            return
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise NetError("DNS lookup failed", kind="network") from None
        for info in infos:
            if not ip_is_public(ipaddress.ip_address(info[4][0].split("%")[0])):
                raise NetError("blocked: host resolves to a private address", kind="blocked")

    def _pace(self, host: str) -> None:
        with self._gap_lock:
            now = time.monotonic()
            t = max(now, self._next_ok.get(host, 0.0))
            self._next_ok[host] = t + self.min_gap
            wait = t - now
        if wait > 0:
            self._sleep(wait)

    # ------------------------------------------------------------ requests
    def request(self, method: str, url: str, *, headers: dict | None = None, json_body=None, purpose: str = "fetch",
                max_bytes: int = 3_000_000, timeout: float = 25.0, etag: str = "", last_modified: str = "",
                max_redirects: int = 5) -> Response:
        priv = self.cfg.settings["privacy"]
        allow_private = bool(priv["allow_private"]) or purpose == "notify"
        payload = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        cur = url
        for hop in range(max_redirects + 1):
            parts = self._check_url(cur, allow_private)
            host = parts.hostname
            proxy = self._proxy_for(host, purpose)
            if proxy is None and not allow_private:
                self._resolve_check(host)  # never runs when proxied: no local DNS leak
            self._pace(host)
            hdrs = {"User-Agent": priv["user_agent"], "Accept": _ACCEPT.get(purpose, "*/*"),
                    "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate"}
            if hop == 0:
                if etag:
                    hdrs["If-None-Match"] = etag
                if last_modified:
                    hdrs["If-Modified-Since"] = last_modified
            if payload is not None:
                hdrs["Content-Type"] = "application/json"
            hdrs.update(headers or {})
            nxt, status, rh, data = None, 0, {}, b""
            try:
                with httpx.Client(proxy=proxy, trust_env=False, follow_redirects=False, verify=True, http2=False,
                                  timeout=httpx.Timeout(timeout, connect=20.0)) as client:
                    with client.stream(method, cur, headers=hdrs, content=payload) as r:
                        status = r.status_code
                        rh = {k.lower(): v for k, v in r.headers.items()}
                        if status in _REDIRECTS:
                            nxt = rh.get("location")
                        elif status < 400 and status != 304:
                            ctype = rh.get("content-type", "").lower()
                            if ctype.startswith(("image/", "video/", "audio/", "application/zip", "application/octet-stream")):
                                raise NetError("not a text response", kind="blocked")
                            data = self._read(r, max_bytes)
                        elif status >= 400:
                            data = self._read(r, 4096, strict=False)
            except NetError:
                raise
            except ImportError:
                raise NetError("SOCKS support is missing (pip install httpx[socks])", kind="config") from None
            except httpx.HTTPError as e:
                raise self._map_error(e, proxy is not None) from None
            if nxt:
                if method != "GET":
                    raise NetError("unexpected redirect on a non-GET request", kind="http", status=status)
                nurl = urljoin(cur, nxt)
                if urlsplit(cur).scheme == "https" and urlsplit(nurl).scheme != "https":
                    raise NetError("blocked: redirect downgrades https to http", kind="blocked")
                cur = nurl
                continue
            if status == 304:
                return Response(304, cur, rh, b"", True)
            if status >= 400:
                raise NetError(f"HTTP {status}", kind="http", status=status, retry_after=_retry_after(rh.get("retry-after")), body=data)
            return Response(status, cur, rh, data)
        raise NetError("too many redirects", kind="http")

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post_json(self, url: str, body, **kw) -> Response:
        return self.request("POST", url, json_body=body, **kw)

    @staticmethod
    def _read(r: httpx.Response, max_bytes: int, strict: bool = True) -> bytes:
        cl = r.headers.get("content-length", "")
        if strict and cl.isdigit() and int(cl) > max_bytes:
            raise NetError("response too large", kind="blocked")
        buf, deadline = bytearray(), time.monotonic() + 60
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > max_bytes:
                if strict:
                    raise NetError("response too large", kind="blocked")
                return bytes(buf[:max_bytes])
            if time.monotonic() > deadline:
                raise NetError("response too slow", kind="timeout")
        return bytes(buf)

    @staticmethod
    def _map_error(e: Exception, proxied: bool) -> NetError:
        via = " (via proxy)" if proxied else ""
        if isinstance(e, httpx.TimeoutException):
            return NetError(f"timed out{via}", kind="timeout")
        if isinstance(e, httpx.ProxyError):
            return NetError("proxy error: handshake refused or target unreachable through the proxy", kind="proxy")
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            return NetError("TLS certificate check failed", kind="tls")
        if isinstance(e, httpx.ConnectError):
            return NetError("cannot reach the proxy or the target" if proxied else "cannot connect", kind="proxy" if proxied else "network")
        if isinstance(e, (httpx.UnsupportedProtocol, httpx.InvalidURL)):
            return NetError("invalid or unsupported URL", kind="blocked")
        return NetError(f"network error ({type(e).__name__}){via}", kind="network")

    # ------------------------------------------------------------ robots.txt
    def robots_allowed(self, url: str) -> bool:
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        now = time.time()
        cached = self._robots.get(origin)
        if not cached or cached[0] < now:
            rp: RobotFileParser | None = None
            try:
                res = self.get(origin + "/robots.txt", purpose="robots", max_bytes=500_000, timeout=15)
                rp = RobotFileParser()
                rp.parse(decode_body(res).splitlines())
            except NetError as e:
                if e.kind in ("privacy", "proxy"):
                    raise
                rp = None  # robots.txt missing/unreachable -> allowed (RFC 9309 treats 4xx as "no rules")
            cached = (now + 12 * 3600, rp)
            self._robots[origin] = cached
        rp = cached[1]
        return True if rp is None else rp.can_fetch("*", url)

    # ------------------------------------------------------------ diagnostics
    def egress_check(self) -> dict:
        """What the outside world sees when we go through the configured proxy."""
        res = self.get("https://check.torproject.org/api/ip", purpose="api", max_bytes=10_000, timeout=30)
        d = json.loads(decode_body(res))
        return {"ip": d.get("IP"), "is_tor": bool(d.get("IsTor"))}
