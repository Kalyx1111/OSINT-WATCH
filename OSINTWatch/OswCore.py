"""OSINT Watch - shared constants, paths, secret-redacting logging, sanitizers.

By Aryan / @EPureNest
"""
from __future__ import annotations

import ipaddress
import json
import logging
import logging.handlers
import os
import re
import secrets
import socket
import subprocess  # nosec B404 - only used for fixed icacls call
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

APP_NAME = "OSINT Watch"
APP_VERSION = "1.0.0"
BRAND = "By Aryan / @EPureNest"

CODE_DIR = Path(__file__).resolve().parent  # where the program's own files live - never relocated
ROOT = Path(os.environ.get("OSW_HOME") or CODE_DIR).resolve()  # where DATA lives - OSW_HOME overrides this only
LOG_DIR = ROOT / "data" / "logs"
WEB_FILE = CODE_DIR / "OswFrontend.html"

# Hard caps requested by the user: 50 X accounts, 20 Telegram channels, 30 websites, 50 keywords.
LIMITS = {"twitter": 50, "telegram": 20, "web": 30, "keywords": 50}
IS_WINDOWS = os.name == "nt"
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")


class Paths:
    """All runtime files live under one data folder (single-folder portability)."""

    def __init__(self, data_dir: Path):
        self.data = Path(data_dir)
        self.state = self.data / "state"
        self.backups = self.data / "backups"
        self.db = self.data / "Osw.db"
        self.watchlist = self.data / "OswWatchlist.json"
        self.settings = self.data / "OswSettings.json"
        self.secrets = self.data / "OswSecrets.env"
        self.token = self.state / "OswToken.txt"
        self.heartbeat = self.state / "OswHeartbeat.json"

    def ensure(self) -> None:
        for d in (self.data, self.state, self.backups):
            d.mkdir(parents=True, exist_ok=True)
        secure_path(self.data, is_dir=True)


DEFAULT_PATHS = Paths(ROOT / "data")

# ---------------------------------------------------------------- redaction
_REDACT = [
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "[tg-token]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [redacted]"),
    (re.compile(r"\btk_[A-Za-z0-9]{20,}\b"), "[ntfy-token]"),
    (re.compile(r"(?i)((?:x-api-key|authorization|api[_-]?key|token|secret|password)['\"]?\s*[:=]\s*['\"]?)[^\s'\",;]{6,}"),
     r"\1[redacted]"),
    (re.compile(r"(?i)\b(socks5h?|https?)://[^/\s:@]+:[^/\s@]+@"), r"\1://[redacted]@"),
]
_SECRET_VALUES: set[str] = set()


def register_secret(value: str | None) -> None:
    """Remember a secret so it can never appear in a log line."""
    if value and len(value) >= 6:
        _SECRET_VALUES.add(value)


def redact(text: str) -> str:
    for v in _SECRET_VALUES:
        text = text.replace(v, "[redacted]")
    for rx, rep in _REDACT:
        text = rx.sub(rep, text)
    return text


class RedactFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # redacts message AND traceback
        return redact(super().format(record))


log = logging.getLogger("osw")


def setup_logging(log_dir: Path = LOG_DIR, debug: bool = False) -> None:
    log.setLevel(logging.DEBUG if debug else logging.INFO)
    if log.handlers:
        return
    fmt = RedactFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(log_dir / "Osw.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(RedactFormatter("%(asctime)s %(message)s", "%H:%M:%S"))
    sh.setLevel(logging.INFO)
    log.addHandler(fh)
    log.addHandler(sh)
    log.propagate = False


# ---------------------------------------------------------------- helpers
def now() -> int:
    return int(time.time())


def new_cid() -> str:
    """Short correlation id shown to the client instead of internal error detail."""
    return secrets.token_hex(4)


def clip(s: str | None, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1].rstrip() + "\u2026"


# Bidi overrides/isolates, BOM, zero-width space, word joiner: spoofing/hiding tricks. ZWNJ/ZWJ are kept (needed by Urdu/Hindi).
_CTRL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b\u202a-\u202e\u2060\u2066-\u2069\ufeff]")


def clean_text(s: str | None, limit: int = 4000) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFC", s)
    s = _CTRL.sub("", s).replace("\xa0", " ")
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r" ?\n ?", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s[:limit]


_TRACK = re.compile(r"^(utm_.*|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|igshid|yclid|_hsenc|_hsmi|ref_src|ref_url|vero_id|spm)$", re.I)


def safe_http_url(u: str | None, max_len: int = 2048) -> str | None:
    """Return a normalised http(s) URL without credentials/tracking params, else None."""
    if not u or len(u) > max_len:
        return None
    u = u.strip().replace(" ", "%20")
    if re.search(r"[\x00-\x20\x7f]", u):
        return None
    try:
        p = urlsplit(u)
        host = p.hostname
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not host or p.username or p.password:
        return None
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not _TRACK.match(k)])
    return urlunsplit((p.scheme.lower(), p.netloc, p.path, query, p.fragment))


def secure_path(p: Path, is_dir: bool = False) -> None:
    """Owner-only permissions. POSIX chmod; Windows icacls (fixed argv, no shell)."""
    try:
        if IS_WINDOWS:
            user = os.environ.get("USERNAME")
            if not user:
                return
            dom = os.environ.get("USERDOMAIN")
            who = f"{dom}\\{user}" if dom else user
            grant = f"{who}:(OI)(CI)F" if is_dir else f"{who}:(F)"
            subprocess.run(  # nosec B603 B607 - fixed argv
                ["icacls", str(p), "/inheritance:r", "/grant:r", grant],
                capture_output=True, timeout=15, check=False, creationflags=0x08000000,
            )
        else:
            os.chmod(p, 0o700 if is_dir else 0o600)
    except Exception as e:  # never fatal
        log.debug("secure_path failed for %s: %s", p, type(e).__name__)


def atomic_write(path: Path, data: str, *, secure: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if secure:
            secure_path(Path(tmp))
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        log.warning("could not read %s (%s)", path.name, type(e).__name__)
        return default


def mark_heartbeat(paths: "Paths", status: str, **extra) -> None:
    """Record run status for the next startup's crash notice. Used from OswApp (marking
    "running" at startup) and from OswServer's App.stop() - a normal shutdown always ends
    via the raw signal after uvicorn's own cleanup, never through OswApp's outer
    try/finally, so "stopped" must be written from inside the shutdown path that actually
    runs (the FastAPI lifespan), not the one that looks like it should but doesn't."""
    try:
        atomic_write(paths.heartbeat, json.dumps({"status": status, **extra}))
    except OSError as e:
        log.debug("could not write heartbeat (%s)", type(e).__name__)


# ---------------------------------------------------------------- host safety (shared by config + network layer)
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp", ".localdomain")


def parse_ip(host: str):
    """IP object for literal/numeric hosts (also odd forms such as 2130706433 or 0x7f.1), else None."""
    h = (host or "").strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-Fx.]+", h):
        try:
            return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(h)))
        except (OSError, ValueError):
            return None
    return None


def ip_is_public(ip) -> bool:
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def host_is_blocked(host: str) -> bool:
    """True for localhost-style names and non-public IP literals (SSRF guard)."""
    h = (host or "").lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(_LOCAL_SUFFIXES):
        return True
    ip = parse_ip(h)
    return (not ip_is_public(ip)) if ip is not None else False
