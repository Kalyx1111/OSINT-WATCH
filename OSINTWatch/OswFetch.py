"""OSINT Watch - fetchers.

Telegram : public web preview https://t.me/s/<channel> (no login, no API key, no account)
X        : official X API v2 (pay-per-use) and/or twitterapi.io. Anonymous scraping of X is not supported:
           X blocks it and is taking legal action against scrapers (Nitter shut down Aug 2026).
Websites : RSS/Atom (auto-discovered), else headline-link extraction from the HTML page.
Everything fetched is untrusted data: it is sanitised, never executed, never rendered as HTML.
By Aryan / @EPureNest
"""
from __future__ import annotations

import hashlib
import html
import html.entities
import json
import re
import xml.etree.ElementTree as ET  # nosec B405 - entity declarations are refused before parsing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlencode, urljoin, urlsplit

from bs4 import BeautifulSoup

from OswConfig import Config
from OswCore import clean_text, clip, safe_http_url
from OswNet import Net, NetError, decode_body

TG_BASE = "https://t.me"
X_API_BASE = "https://api.x.com"
TWITTERAPI_BASE = "https://api.twitterapi.io"


@dataclass
class Source:
    id: str
    kind: str          # twitter | telegram | web
    target: str
    label: str


@dataclass
class Item:
    source_id: str
    kind: str
    uid: str
    url: str
    title: str
    text: str
    author: str = ""
    published: int = 0


@dataclass
class PollResult:
    items: list = field(default_factory=list)
    not_modified: bool = False
    meta: dict = field(default_factory=dict)     # merged into source_state.meta
    fields: dict = field(default_factory=dict)   # etag, last_modified, feed_url, label, provider


# ------------------------------------------------------------------ helpers
def headline(text: str, n: int = 140) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return clip(line.strip(), n)
    return ""


def parse_time(s) -> int:
    """ISO-8601, RFC-822 or X 'Wed Jan 06 18:40:40 +0000 2021' -> epoch seconds (0 if unknown)."""
    if not s or not isinstance(s, str):
        return 0
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp())
    except ValueError:
        pass
    for fn in (lambda v: datetime.strptime(v, "%a %b %d %H:%M:%S %z %Y"), parsedate_to_datetime):
        try:
            d = fn(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return int(d.timestamp())
        except (ValueError, TypeError, OverflowError):
            continue
    return 0


def _plain(markup: str, limit: int = 3000) -> str:
    markup = markup or ""
    if "<" in markup:
        soup = BeautifulSoup(markup[:30000], "html.parser")
        for br in soup.find_all("br"):
            br.replace_with("\n")
        for blk in soup.find_all(["p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre"]):
            blk.append("\n")
        markup = soup.get_text()
    return clean_text(html.unescape(markup), limit)


# ------------------------------------------------------------------ Telegram
def parse_telegram(markup: str) -> tuple[list[Item], dict]:
    soup = BeautifulSoup(markup, "html.parser")
    info: dict = {}
    t = soup.select_one(".tgme_channel_info_header_title")
    if t:
        info["title"] = clean_text(t.get_text(" ", strip=True), 100)
    info["has_history"] = soup.select_one(".tgme_channel_history") is not None
    items: list[Item] = []
    for post in soup.select("div.tgme_widget_message[data-post]"):
        if "service_message" in (post.get("class") or []):
            continue  # "channel created", "pinned a message" ... not content
        m = re.fullmatch(r"([A-Za-z0-9_]{3,64})/(\d{1,12})", post.get("data-post", ""))
        if not m:
            continue
        chan, mid = m.group(1), m.group(2)
        te = post.select_one("time[datetime]")
        published = parse_time(te.get("datetime")) if te else 0
        body = post.select_one("div.tgme_widget_message_text")
        text = ""
        if body:
            for br in body.find_all("br"):
                br.replace_with("\n")
            text = clean_text(body.get_text())
        extra = []
        lp = post.select_one("a.tgme_widget_message_link_preview")
        if lp:
            for cls in ("link_preview_site_name", "link_preview_title", "link_preview_description"):
                e = lp.select_one("." + cls)
                if e:
                    extra.append(clean_text(e.get_text(" ", strip=True), 300))
        fwd = post.select_one(".tgme_widget_message_forwarded_from_name")
        if fwd:
            extra.insert(0, "Forwarded from " + clean_text(fwd.get_text(" ", strip=True), 100))
        if not text and not extra:
            label = ("[photo]" if post.select_one(".tgme_widget_message_photo_wrap") else
                     "[video]" if post.select_one("[class*=message_video]") else "[media post]")
            text = label
        full = "\n".join([x for x in [text] + extra if x])
        items.append(Item("", "telegram", mid, f"https://t.me/{chan}/{mid}", headline(text or (extra[0] if extra else "")),
                          full, "@" + chan, published))
    return items, info


def poll_telegram(net: Net, src: Source, state: dict) -> PollResult:
    res = net.get(f"{TG_BASE}/s/{quote(src.target)}", timeout=30)
    if not urlsplit(res.url).path.startswith("/s/"):
        raise NetError("no public web preview for this name (private channel, group, bot, or preview disabled)", kind="unavailable")
    items, info = parse_telegram(decode_body(res))
    if not items and not info["has_history"]:
        raise NetError("unexpected page: no message list found (channel restricted or Telegram changed its layout)", kind="unavailable")
    for it in items:
        it.source_id = src.id
    fields = {"label": "@" + src.target}
    if info.get("title"):
        fields["label"] = clip(f"{info['title']} (@{src.target})", 80)
    return PollResult(items, fields=fields)


# ------------------------------------------------------------------ X
def _x_explain(e: NetError, who: str) -> NetError:
    if e.status == 401:
        return NetError(f"{who}: token rejected (401)", kind="auth", status=401)
    if e.status == 402:
        return NetError(f"{who}: credits depleted or payment required (402)", kind="quota", status=402)
    if e.status == 403:
        return NetError(f"{who}: access forbidden (403) - check plan/credits and app permissions", kind="auth", status=403)
    if e.status == 429:
        return NetError(f"{who}: rate limit (429)", kind="quota", status=429, retry_after=e.retry_after)
    return e


def poll_x_api(net: Net, vault, src: Source, state: dict) -> tuple[list[Item], dict]:
    token = vault.get("X_BEARER_TOKEN")
    if not token:
        raise NetError("X_BEARER_TOKEN is not set", kind="config")
    auth = {"Authorization": f"Bearer {token}"}
    meta = dict(state.get("meta") or {})
    try:
        uid = meta.get("x_user_id")
        if not uid:
            r = net.get(f"{X_API_BASE}/2/users/by/username/{quote(src.target)}", headers=auth, purpose="api", max_bytes=200_000)
            data = (json.loads(decode_body(r)) or {}).get("data") or {}
            if not data.get("id"):
                raise NetError(f"@{src.target}: account not found, suspended or protected", kind="http", status=404)
            uid = meta["x_user_id"] = str(data["id"])
        since = meta.get("x_since_id")
        q = {"max_results": 100 if since else 5, "tweet.fields": "created_at,referenced_tweets,note_tweet"}
        if since:
            q["since_id"] = since
        r = net.get(f"{X_API_BASE}/2/users/{uid}/tweets?{urlencode(q)}", headers=auth, purpose="api", max_bytes=2_000_000)
    except NetError as e:
        raise _x_explain(e, "X API") from None
    d = json.loads(decode_body(r)) or {}
    items = []
    for tw in d.get("data") or []:
        tid = str(tw.get("id") or "")
        if not tid.isdigit():
            continue
        text = clean_text(((tw.get("note_tweet") or {}).get("text")) or tw.get("text") or "")
        items.append(Item(src.id, "twitter", tid, f"https://x.com/{src.target}/status/{tid}", headline(text), text,
                          "@" + src.target, parse_time(tw.get("created_at"))))
    newest = str((d.get("meta") or {}).get("newest_id") or "")
    if newest.isdigit():
        meta["x_since_id"] = newest
    return items, meta


def poll_twitterapi_io(net: Net, vault, src: Source, state: dict) -> tuple[list[Item], dict]:
    key = vault.get("TWITTERAPI_KEY")
    if not key:
        raise NetError("TWITTERAPI_KEY is not set", kind="config")
    try:
        r = net.get(f"{TWITTERAPI_BASE}/twitter/user/last_tweets?" + urlencode({"userName": src.target, "includeReplies": "false"}),
                    headers={"X-API-Key": key}, purpose="api", max_bytes=2_000_000)
    except NetError as e:
        raise _x_explain(e, "twitterapi.io") from None
    d = json.loads(decode_body(r)) or {}
    if d.get("status") == "error":
        raise NetError("twitterapi.io: " + clip(str(d.get("message") or "error"), 160), kind="http")
    tweets = d.get("tweets") or (d.get("data") or {}).get("tweets") or []
    items = []
    for tw in tweets:
        tid = str(tw.get("id") or "")
        if not tid.isdigit():
            continue
        text = clean_text(tw.get("text") or "")
        items.append(Item(src.id, "twitter", tid, f"https://x.com/{src.target}/status/{tid}", headline(text), text,
                          "@" + src.target, parse_time(tw.get("createdAt"))))
    return items, dict(state.get("meta") or {})


X_PROVIDERS = {"x_api": poll_x_api, "twitterapi_io": poll_twitterapi_io}


def poll_twitter(net: Net, vault, providers: list[str], src: Source, state: dict) -> PollResult:
    errors: list[NetError] = []
    for name in providers:
        try:
            items, meta = X_PROVIDERS[name](net, vault, src, state)
            return PollResult(items, meta=meta, fields={"provider": name, "label": "@" + src.target})
        except NetError as e:
            if e.kind == "privacy":
                raise
            errors.append(NetError(f"{name}: {e}", kind=e.kind, status=e.status, retry_after=e.retry_after))
    if not errors or all(e.kind == "config" for e in errors):
        raise NetError("No X provider is set up: add X_BEARER_TOKEN (official API) or TWITTERAPI_KEY in Settings", kind="config")
    real = [e for e in errors if e.kind != "config"]
    raise NetError("; ".join(str(e) for e in real), kind=real[-1].kind, status=real[-1].status, retry_after=real[-1].retry_after)


# ------------------------------------------------------------------ RSS / Atom
_XML_PREDEF = {"amp", "lt", "gt", "quot", "apos"}
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def _fix_entities(s: str) -> str:
    def repl(m):
        name = m.group(1)
        if name in _XML_PREDEF:
            return m.group(0)
        cp = html.entities.name2codepoint.get(name)
        return f"&#{cp};" if cp else f"&amp;{name};"
    s = re.sub(r"&([A-Za-z][A-Za-z0-9]*);", repl, s)
    return re.sub(r"&(?!(?:[A-Za-z][A-Za-z0-9]*|#\d+|#[xX][0-9A-Fa-f]+);)", "&amp;", s)


def _ln(tag) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _txt(el) -> str:
    return _plain("".join(el.itertext()), 4000)


def looks_like_feed(body: bytes, content_type: str = "") -> bool:
    head = body[:3000].lower()
    return b"<rss" in head or b"<feed" in head or b"<rdf:rdf" in head or (
        "xml" in content_type.lower() and b"<channel" in head)


def parse_feed(text: str, base_url: str) -> tuple[dict, list[dict]]:
    if re.search(r"<!ENTITY", text, re.I):
        raise NetError("feed refused: XML entity declarations are not allowed", kind="parse")
    text = re.sub(r"^\ufeff?\s*<\?xml[^>]*\?>", "", text)
    text = _fix_entities(_INVALID_XML.sub("", text))
    try:
        root = ET.fromstring(text)  # nosec B314 - entity declarations refused above, size capped by Net
    except ET.ParseError:
        raise NetError("feed is not valid XML", kind="parse") from None
    rk = _ln(root.tag)
    title = ""
    if rk == "rss":
        channel = next((c for c in root if _ln(c.tag) == "channel"), root)
        nodes = [n for n in channel if _ln(n.tag) == "item"]
        title = next((_txt(c) for c in channel if _ln(c.tag) == "title"), "")
    elif rk == "feed":
        nodes = [n for n in root if _ln(n.tag) == "entry"]
        title = next((_txt(c) for c in root if _ln(c.tag) == "title"), "")
    elif rk == "rdf":
        nodes = [n for n in root if _ln(n.tag) == "item"]
        title = next((_txt(c) for n in root if _ln(n.tag) == "channel" for c in n if _ln(c.tag) == "title"), "")
    else:
        raise NetError("not an RSS or Atom feed", kind="parse")
    entries = []
    for node in nodes[:100]:
        d: dict = {"dates": {}}
        for ch in node:
            ln = _ln(ch.tag)
            if ln == "link":
                href = ch.get("href")
                if href:
                    if ch.get("rel", "alternate") == "alternate" and "link" not in d:
                        d["link"] = href
                elif (ch.text or "").strip() and "link" not in d:
                    d["link"] = ch.text.strip()
            elif ln == "title":
                d.setdefault("title", _txt(ch))
            elif ln in ("guid", "id"):
                d.setdefault("guid", (ch.text or "").strip())
            elif ln in ("pubdate", "published", "date", "issued", "created", "updated", "modified"):
                d["dates"].setdefault(ln, (ch.text or "").strip())
            elif ln in ("description", "summary"):
                d.setdefault("summary", _txt(ch))
            elif ln in ("encoded", "content"):
                d.setdefault("content", _txt(ch))
            elif ln in ("author", "creator"):
                name = next((c.text for c in ch if _ln(c.tag) == "name" and c.text), None)
                d.setdefault("author", clean_text(name or "".join(ch.itertext()), 80))
        dt = 0
        for k in ("published", "pubdate", "date", "issued", "created", "updated", "modified"):
            if d["dates"].get(k):
                dt = parse_time(d["dates"][k])
                if dt:
                    break
        d["date"] = dt
        if d.get("link"):
            d["link"] = urljoin(base_url, d["link"])
        entries.append(d)
    return {"title": clean_text(title, 100)}, entries


def discover_feeds(markup: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(markup[:400_000], "html.parser")
    out: list[str] = []
    for link in soup.find_all("link", href=True):
        t = (link.get("type") or "").lower()
        rel = " ".join(link.get("rel") or []).lower()
        if "alternate" in rel and ("rss" in t or "atom" in t or t in ("application/xml", "text/xml")):
            u = safe_http_url(urljoin(base_url, link["href"]))
            if u and u not in out:
                out.append(u)
    return out


# ------------------------------------------------------------------ HTML fallback
_SKIP_PATH = re.compile(r"/(tag|tags|category|categories|author|authors|page|topic|topics|search|about|contact|privacy|terms|login|register|subscribe|feed)(/|$)", re.I)


def extract_links(markup: str, base_url: str, limit: int = 80) -> list[tuple[str, str]]:
    """Headline-like same-site links (>=4 words, >=25 chars, article-looking path)."""
    soup = BeautifulSoup(markup[:1_500_000], "html.parser")
    base_host = (urlsplit(base_url).hostname or "").lower()
    out, seen = [], set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        u = safe_http_url(urljoin(base_url, href))
        if not u:
            continue
        p = urlsplit(u)
        h = (p.hostname or "").lower()
        if not (h == base_host or h.endswith("." + base_host) or base_host.endswith("." + h)):
            continue
        segs = [s for s in p.path.split("/") if s]
        if not segs or _SKIP_PATH.search(p.path):
            continue
        text = clean_text(a.get_text(" ", strip=True), 300)
        if len(text) < 25 or len(text.split()) < 4:
            continue
        if not (len(segs) >= 2 or re.search(r"\d", p.path) or "-" in p.path):
            continue
        key = p._replace(fragment="").geturl()
        if key in seen:
            continue
        seen.add(key)
        out.append((key, text))
        if len(out) >= limit:
            break
    return out


def _feedish(url: str) -> bool:
    p = urlsplit(url)
    path = p.path.lower()
    return bool(re.search(r"\.(xml|rss|atom|rdf)$", path) or re.search(r"/(feed|rss|atom)(/|\.xml)?$", path)
                or (p.hostname or "").lower().startswith(("feed.", "feeds.", "rss.")))


def poll_web(net: Net, cfg: Config, src: Source, state: dict) -> PollResult:
    priv = cfg.settings["privacy"]
    feed_url = state.get("feed_url") or ""
    url = feed_url or src.target
    if priv["respect_robots"] and not feed_url and not _feedish(url) and not net.robots_allowed(url):
        raise NetError("blocked by the site's robots.txt (turn off 'respect robots.txt' in Settings to override)", kind="robots")
    res = net.get(url, etag=state.get("etag", ""), last_modified=state.get("last_modified", ""), timeout=30)
    if res.not_modified:
        return PollResult(not_modified=True)
    fields = {"etag": res.headers.get("etag", ""), "last_modified": res.headers.get("last-modified", "")}
    host = urlsplit(src.target).hostname or src.target
    meta_title, entries = "", None
    if looks_like_feed(res.body, res.headers.get("content-type", "")):
        info, entries = parse_feed(decode_body(res), res.url)
        meta_title = info.get("title", "")
        fields["provider"] = "feed"
        if not feed_url:
            fields["feed_url"] = res.url
    else:
        page = decode_body(res)
        if feed_url:  # a remembered feed now returns a page: forget it, rediscover next round
            fields.update(feed_url="", etag="", last_modified="")
        for fu in discover_feeds(page, res.url)[:3]:
            try:
                r2 = net.get(fu, timeout=30)
            except NetError as e:
                if e.kind in ("privacy", "proxy"):
                    raise
                continue
            if looks_like_feed(r2.body, r2.headers.get("content-type", "")):
                info, entries = parse_feed(decode_body(r2), r2.url)
                meta_title = info.get("title", "")
                fields.update(feed_url=r2.url, etag=r2.headers.get("etag", ""), last_modified=r2.headers.get("last-modified", ""), provider="feed")
                break
        if entries is None:
            if priv["respect_robots"] and not net.robots_allowed(res.url):
                raise NetError("blocked by the site's robots.txt (turn off 'respect robots.txt' in Settings to override)", kind="robots")
            entries = [{"link": u, "title": t, "summary": "", "guid": u, "date": 0, "author": ""} for u, t in extract_links(page, res.url)]
            fields["provider"] = "html"
    items = []
    for e in entries[:100]:
        link = safe_http_url(e.get("link") or "") or safe_http_url(e.get("guid") or "")
        if not link and not e.get("guid"):
            continue
        uid = hashlib.sha1((e.get("guid") or link).encode("utf-8", "ignore")).hexdigest()[:16]  # nosec B324 - id, not security
        title = clean_text(e.get("title") or "", 300) or link or host
        body = clean_text(e.get("summary") or e.get("content") or "", 3000)
        items.append(Item(src.id, "web", uid, link or src.target, title, body, clean_text(e.get("author") or host, 80), e.get("date", 0)))
    fields["label"] = clip(meta_title or host, 80)
    return PollResult(items, fields=fields)


class Fetchers:
    def __init__(self, net: Net, cfg: Config):
        self.net, self.cfg = net, cfg

    def poll(self, src: Source, state: dict) -> PollResult:
        if src.kind == "telegram":
            return poll_telegram(self.net, src, state)
        if src.kind == "twitter":
            return poll_twitter(self.net, self.cfg.vault, self.cfg.settings["twitter"]["providers"], src, state)
        if src.kind == "web":
            return poll_web(self.net, self.cfg, src, state)
        raise NetError("unknown source type", kind="config")
