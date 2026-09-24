"""OSINT Watch - settings, watchlist and secrets with strict server-side validation.

Secrets (API keys, tokens, proxy credentials) are never stored in settings/watchlist files:
they come from environment variables (OSW_<NAME>) or data/OswSecrets.env (owner-only permissions).
By Aryan / @EPureNest
"""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import shlex
import shutil
import threading
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from OswCore import (LIMITS, Paths, atomic_write, host_is_blocked, log, register_secret, safe_http_url)
from OswMatch import validate_entries

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"

DEFAULT_SETTINGS: dict = {
    "privacy": {
        "mode": "strict",            # strict = never fetch without a proxy (fail closed)
        "proxy": "",                 # host:port, socks5h://host:port, http://host:port  (no credentials here)
        "isolate_streams": False,    # separate Tor circuit per destination host (SOCKS auth isolation)
        "route_notifiers": True,     # send ntfy / Telegram-bot traffic through the proxy too
        "respect_robots": True,
        "allow_private": False,      # allow LAN/localhost websites (off = SSRF guard on)
        "user_agent": DEFAULT_UA,
    },
    "polling": {"telegram": 90, "twitter": 180, "web": 300, "jitter": 0.2, "max_backoff": 1800, "workers": 0},
    "alerts": {"mode": "keywords", "max_age_hours": 24, "burst_limit": 5,
               "quiet_enabled": False, "quiet_start": "23:00", "quiet_end": "06:00"},
    "notify": {"desktop": True, "ntfy": False, "ntfy_server": "https://ntfy.sh", "tgbot": False, "termux": False},
    "twitter": {"providers": ["x_api", "twitterapi_io"]},
    "server": {"host": "127.0.0.1", "port": 8765, "tls_cert": "", "tls_key": "", "open_browser": True},
    "storage": {"retention_days": 30},
    "links": {"opener": ""},
}

SECRET_SPECS = {
    "X_BEARER_TOKEN": (r"^[\x21-\x7e]{20,600}$", "X API v2 bearer token"),
    "TWITTERAPI_KEY": (r"^[\x21-\x7e]{8,200}$", "twitterapi.io API key"),
    "NTFY_TOPIC": (r"^[A-Za-z0-9_-]{6,64}$", "ntfy topic (acts as a password: make it long and random)"),
    "NTFY_TOKEN": (r"^[\x21-\x7e]{8,200}$", "ntfy access token (only for protected servers)"),
    "TG_BOT_TOKEN": (r"^\d{5,12}:[A-Za-z0-9_-]{20,60}$", "Telegram bot token from @BotFather"),
    "TG_CHAT_ID": (r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$", "Telegram chat id that receives alerts"),
    "PROXY_URL": (r"^(socks5h?|https?)://\S{3,300}$", "full proxy URL incl. credentials (overrides Settings)"),
}


# ------------------------------------------------------------------ validators
def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def normalize_proxy(v: str, allow_creds: bool = False) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    if "://" not in v:
        v = "socks5h://" + v
    p = urlsplit(v)
    scheme = p.scheme.lower()
    if scheme == "socks5":
        scheme = "socks5h"  # always resolve DNS at the proxy, never locally
    if scheme not in ("socks5h", "http", "https"):
        raise ValueError("proxy scheme must be socks5h://, http:// or https://")
    if (p.username or p.password) and not allow_creds:
        raise ValueError("credentials are not stored here - put the full URL in the PROXY_URL secret")
    try:
        host, port = p.hostname, p.port
    except ValueError:
        raise ValueError("invalid proxy address") from None
    if not host or not port:
        raise ValueError("proxy needs host and port, e.g. 127.0.0.1:9150")
    auth = ""
    if allow_creds and (p.username or p.password):
        auth = f"{p.username or ''}:{p.password or ''}@"
    h = f"[{host}]" if ":" in host else host
    return f"{scheme}://{auth}{h}:{port}"


def _v_bool(v, spec):
    if isinstance(v, bool):
        return v
    raise ValueError("must be true or false")


def _v_int(v, spec):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v:
        raise ValueError("must be a whole number")
    if not spec[1] <= v <= spec[2]:
        raise ValueError(f"must be between {spec[1]} and {spec[2]}")
    return int(v)


def _v_float(v, spec):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError("must be a number")
    if not spec[1] <= v <= spec[2]:
        raise ValueError(f"must be between {spec[1]} and {spec[2]}")
    return float(v)


def _v_enum(v, spec):
    if v not in spec[1]:
        raise ValueError("must be one of: " + ", ".join(spec[1]))
    return v


def _v_str(v, spec):
    if not isinstance(v, str) or not spec[1] <= len(v.strip()) <= spec[2] or re.search(r"[\x00-\x1f\x7f]", v):
        raise ValueError(f"must be {spec[1]}-{spec[2]} printable characters")
    return v.strip()


def _v_hhmm(v, spec):
    if not isinstance(v, str) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
        raise ValueError("must look like 23:00")
    return v


def _v_proxy(v, spec):
    if not isinstance(v, str):
        raise ValueError("must be text")
    return normalize_proxy(v)


def _v_httpurl(v, spec):
    if not isinstance(v, str):
        raise ValueError("must be a URL")
    u = safe_http_url(v)
    p = urlsplit(u) if u else None
    if not u or p.query or p.fragment:
        raise ValueError("must be a plain http(s) URL such as https://ntfy.sh")
    return urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), "", ""))


def _v_host(v, spec):
    if not isinstance(v, str) or not (v == "localhost" or _try_ip(v)):
        raise ValueError("must be localhost or an IP address")
    return v


def _try_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip("[]"))
        return True
    except ValueError:
        return False


def _v_file(v, spec):
    if not isinstance(v, str):
        raise ValueError("must be a path")
    v = v.strip()
    if v and not Path(v).is_file():
        raise ValueError("file not found")
    return v


def _v_list_enum(v, spec):
    if not isinstance(v, list) or not v or any(x not in spec[1] for x in v) or len(set(v)) != len(v):
        raise ValueError("must be a non-empty list of: " + ", ".join(spec[1]))
    return list(v)


def split_opener(template: str) -> list[str]:
    parts = shlex.split(template, posix=(os.name != "nt"))
    return [p[1:-1] if len(p) > 1 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]


def _v_opener(v, spec):
    if not isinstance(v, str) or len(v) > 500 or re.search(r"[\x00-\x1f\x7f]", v):
        raise ValueError("must be a command line under 500 characters")
    v = v.strip()
    if not v:
        return ""
    try:
        argv = split_opener(v)
    except ValueError:
        raise ValueError("could not parse the command") from None
    if not argv or not (Path(argv[0]).is_file() or shutil.which(argv[0])):
        raise ValueError("program not found")
    return v


_VALIDATORS = {"bool": _v_bool, "int": _v_int, "float": _v_float, "enum": _v_enum, "str": _v_str, "hhmm": _v_hhmm,
               "proxy": _v_proxy, "httpurl": _v_httpurl, "host": _v_host, "file": _v_file,
               "list_enum": _v_list_enum, "opener": _v_opener}

SCHEMA = {
    "privacy": {"mode": ("enum", ("strict", "open")), "proxy": ("proxy",), "isolate_streams": ("bool",),
                "route_notifiers": ("bool",), "respect_robots": ("bool",), "allow_private": ("bool",),
                "user_agent": ("str", 10, 300)},
    "polling": {"telegram": ("int", 45, 3600), "twitter": ("int", 60, 7200), "web": ("int", 120, 86400),
                "jitter": ("float", 0.0, 0.5), "max_backoff": ("int", 300, 21600), "workers": ("int", 0, 16)},
    "alerts": {"mode": ("enum", ("keywords", "all")), "max_age_hours": ("int", 1, 168), "burst_limit": ("int", 1, 20),
               "quiet_enabled": ("bool",), "quiet_start": ("hhmm",), "quiet_end": ("hhmm",)},
    "notify": {"desktop": ("bool",), "ntfy": ("bool",), "ntfy_server": ("httpurl",), "tgbot": ("bool",), "termux": ("bool",)},
    "twitter": {"providers": ("list_enum", ("x_api", "twitterapi_io"))},
    "server": {"host": ("host",), "port": ("int", 1024, 65535), "tls_cert": ("file",), "tls_key": ("file",),
               "open_browser": ("bool",)},
    "storage": {"retention_days": ("int", 1, 365)},
    "links": {"opener": ("opener",)},
}


def validate_settings(patch, base: dict) -> tuple[dict, list[str]]:
    """Merge a (partial) settings patch into base. Unknown keys are rejected; nothing is trusted."""
    merged, errors = copy.deepcopy(base), []
    if not isinstance(patch, dict):
        return merged, ["settings must be an object"]
    for sec, vals in patch.items():
        if sec not in SCHEMA or not isinstance(vals, dict):
            errors.append(f"unknown section: {str(sec)[:40]}")
            continue
        for key, val in vals.items():
            spec = SCHEMA[sec].get(key)
            if not spec:
                errors.append(f"unknown setting: {sec}.{str(key)[:40]}")
                continue
            try:
                merged[sec][key] = _VALIDATORS[spec[0]](val, spec)
            except ValueError as e:
                errors.append(f"{sec}.{key}: {e}")
    s = merged["server"]
    if not _is_loopback(s["host"]) and not (s["tls_cert"] and s["tls_key"]):
        errors.append("server.host: a non-local address needs tls_cert and tls_key (dashboard is never served in clear text on a network)")
    return merged, errors


# ------------------------------------------------------------------ watchlist
_TW = re.compile(r"^[A-Za-z0-9_]{1,15}$")
_TG = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_TW_RESERVED = {"home", "i", "search", "explore", "notifications", "messages", "settings", "intent", "share",
                "hashtag", "login", "signup", "tos", "privacy", "compose", "about"}


def norm_twitter(s: str) -> str:
    s = s.strip()
    m = re.match(r"^(?:https?://)?(?:www\.|mobile\.)?(?:x|twitter)\.com/([^/?#\s]+)", s, re.I)
    if m:
        s = m.group(1)
    s = s.lstrip("@")
    if not _TW.match(s) or s.lower() in _TW_RESERVED:
        raise ValueError("not a valid X handle (1-15 letters, digits or underscore)")
    return s.lower()


def norm_telegram(s: str) -> str:
    s = s.strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?(?:t|telegram)\.me/(?:s/)?([^/?#\s]+)", s, re.I)
    if m:
        s = m.group(1)
    s = s.lstrip("@")
    if s.startswith("+") or s.lower() in ("joinchat", "c", "s"):
        raise ValueError("private invite links are not supported - public channels only")
    if not _TG.match(s):
        raise ValueError("not a valid public channel name (4-32 letters, digits, underscore)")
    return s.lower()


def norm_website(s: str, allow_private: bool = False) -> str:
    s = s.strip()
    if not s:
        raise ValueError("empty")
    if "://" not in s:
        s = "https://" + s
    u = safe_http_url(s)
    if not u:
        raise ValueError("not a valid http(s) address")
    if len(u) > 300:
        raise ValueError("address too long (max 300 characters)")
    p = urlsplit(u)
    try:
        p.hostname.encode("idna")
    except (UnicodeError, AttributeError):
        raise ValueError("invalid host name") from None
    if not allow_private and host_is_blocked(p.hostname):
        raise ValueError("local/private addresses are blocked")
    return urlunsplit((p.scheme, p.netloc.lower(), p.path or "/", p.query, ""))


def _as_lines(v) -> list[str]:
    if isinstance(v, str):
        v = v.splitlines()
    if not isinstance(v, list):
        raise ValueError("must be a list")
    return [x for x in (str(i).strip() for i in v) if x and not x.startswith("#")]


def normalize_watchlist(raw, allow_private: bool = False) -> tuple[dict, list[dict]]:
    """Validate the four lists. Returns (clean, errors). All-or-nothing: caller saves only if errors == []."""
    clean = {"twitter": [], "telegram": [], "websites": [], "keywords": []}
    errors: list[dict] = []
    if not isinstance(raw, dict):
        return clean, [{"list": "all", "entry": "", "error": "watchlist must be an object"}]
    limits = {"twitter": LIMITS["twitter"], "telegram": LIMITS["telegram"], "websites": LIMITS["web"], "keywords": LIMITS["keywords"]}
    for name in clean:
        try:
            lines = _as_lines(raw.get(name, []))
        except ValueError as e:
            errors.append({"list": name, "entry": "", "error": str(e)})
            continue
        seen: set[str] = set()
        for entry in lines:
            try:
                if name == "twitter":
                    val = norm_twitter(entry)
                elif name == "telegram":
                    val = norm_telegram(entry)
                elif name == "websites":
                    val = norm_website(entry, allow_private)
                else:
                    val = entry.strip()
            except ValueError as e:
                errors.append({"list": name, "entry": entry[:80], "error": str(e)})
                continue
            key = val.casefold()
            if key in seen:
                continue
            seen.add(key)
            clean[name].append(val)
        if len(clean[name]) > limits[name]:
            errors.append({"list": name, "entry": "", "error": f"too many entries: {len(clean[name])} (limit {limits[name]})"})
    _, kerrs = validate_entries(clean["keywords"])
    errors += [{"list": "keywords", "entry": e[:80], "error": m} for e, m in kerrs]
    return clean, errors


# ------------------------------------------------------------------ secrets
class Vault:
    """Secrets from OSW_<NAME> environment variables first, then data/OswSecrets.env (owner-only)."""

    def __init__(self, paths: Paths):
        self.paths = paths
        self._lock = threading.RLock()
        self._file: dict[str, str] = {}
        self.load()

    def load(self) -> None:
        data: dict[str, str] = {}
        try:
            text = self.paths.secrets.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k in SECRET_SPECS and v:
                data[k] = v
        with self._lock:
            self._file = data
        for name in SECRET_SPECS:
            register_secret(self.get(name))

    def get(self, name: str) -> str | None:
        v = os.environ.get("OSW_" + name)
        if v and v.strip():
            return v.strip()
        with self._lock:
            return self._file.get(name)

    def source(self, name: str) -> str | None:
        if (os.environ.get("OSW_" + name) or "").strip():
            return "env"
        with self._lock:
            return "file" if name in self._file else None

    def status(self) -> dict:
        return {n: {"set": self.source(n) is not None, "source": self.source(n), "hint": spec[1]}
                for n, spec in SECRET_SPECS.items()}

    def _write(self) -> None:
        lines = ["# OSINT Watch secrets - owner-only file. Never share or commit it.",
                 "# Environment variables OSW_<NAME> take priority over this file."]
        lines += [f"{k}={v}" for k, v in sorted(self._file.items())]
        atomic_write(self.paths.secrets, "\n".join(lines) + "\n", secure=True)

    def set(self, name: str, value: str) -> None:
        if name not in SECRET_SPECS:
            raise ValueError("unknown secret name")
        if not isinstance(value, str):
            raise ValueError("value must be text")
        value = value.strip()
        if name == "PROXY_URL":
            value = normalize_proxy(value, allow_creds=True)
        if not re.fullmatch(SECRET_SPECS[name][0], value):
            raise ValueError(f"{name} has the wrong format")
        with self._lock:
            self._file[name] = value
            self._write()
        register_secret(value)

    def delete(self, name: str) -> None:
        if name not in SECRET_SPECS:
            raise ValueError("unknown secret name")
        with self._lock:
            if name in self._file:
                del self._file[name]
                self._write()


# ------------------------------------------------------------------ manager
class Config:
    def __init__(self, paths: Paths):
        self.paths = paths
        paths.ensure()
        self._lock = threading.RLock()
        self.vault = Vault(paths)
        self.load_notes: list[str] = []
        self.settings: dict = self._load_settings()
        self.watchlist: dict = self._load_watchlist()

    def _read(self, path: Path):
        import json
        for candidate in (path, path.with_name(path.name + ".bak")):
            try:
                return json.loads(candidate.read_text(encoding="utf-8")), candidate
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                self.load_notes.append(f"{candidate.name} unreadable")
        return None, None

    def _load_settings(self) -> dict:
        raw, _ = self._read(self.paths.settings)
        merged, errors = validate_settings(raw if isinstance(raw, dict) else {}, copy.deepcopy(DEFAULT_SETTINGS))
        if errors:
            log.warning("settings file had invalid values (defaults used for them): %s", "; ".join(errors))
            self.load_notes += errors
        return merged

    def _load_watchlist(self) -> dict:
        raw, _ = self._read(self.paths.watchlist)
        clean, errors = normalize_watchlist(raw if isinstance(raw, dict) else {}, self.settings["privacy"]["allow_private"])
        if errors:
            # keep every valid entry, drop only the broken ones
            log.warning("watchlist had %d invalid entries - they were skipped", len(errors))
            self.load_notes.append(f"{len(errors)} invalid watchlist entries skipped")
            clean, _ = normalize_watchlist(_strip_bad(raw, errors), self.settings["privacy"]["allow_private"])
        for name, cap in (("twitter", LIMITS["twitter"]), ("telegram", LIMITS["telegram"]),
                          ("websites", LIMITS["web"]), ("keywords", LIMITS["keywords"])):
            clean[name] = clean[name][:cap]  # a hand-edited file can never exceed the caps
        return clean

    def _write_json(self, path: Path, data: dict) -> None:
        import json
        if path.exists():
            try:
                shutil.copy2(path, path.with_name(path.name + ".bak"))
            except OSError:
                pass
        atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    def save_settings(self, patch) -> list[str]:
        with self._lock:
            merged, errors = validate_settings(patch, self.settings)
            if errors:
                return errors
            self._write_json(self.paths.settings, merged)
            self.settings = merged
            return []

    def save_watchlist(self, raw) -> list[dict]:
        with self._lock:
            clean, errors = normalize_watchlist(raw, self.settings["privacy"]["allow_private"])
            if errors:
                return errors
            self._write_json(self.paths.watchlist, clean)
            self.watchlist = clean
            return []


def _strip_bad(raw, errors: list[dict]):
    """Rebuild a raw watchlist without the entries that failed validation."""
    if not isinstance(raw, dict):
        return {}
    bad = {(e["list"], e["entry"]) for e in errors}
    out = {}
    for k, v in raw.items():
        try:
            out[k] = [x for x in _as_lines(v) if (k, x[:80]) not in bad]
        except ValueError:
            out[k] = []
    return out
