import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import OswFetch as F  # noqa: E402
from OswNet import Net, NetError  # noqa: E402
from OswTestKit import Mock, Socks5, fixture, make_cfg  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ParserTests(unittest.TestCase):
    def test_telegram_preview(self):
        items, info = F.parse_telegram(fixture("telegram_channel.html"))
        self.assertEqual([i.uid for i in items], ["101", "102", "103"])  # service message skipped
        self.assertEqual(info["title"], "Defence Wire")
        a, b, c = items
        self.assertEqual(a.url, "https://t.me/defwire/101")
        self.assertEqual(a.text, "PLA Navy ship Yuan Wang 5 spotted near Hambantota.\nSecond line with report & more.")
        self.assertEqual(a.published, F.parse_time("2026-09-21T10:15:30+00:00"))
        self.assertEqual(a.title, "PLA Navy ship Yuan Wang 5 spotted near Hambantota.")
        self.assertEqual(b.title, "[photo]")
        self.assertIn("Forwarded from Naval Watch", c.text)
        self.assertIn("Hypersonic test reported", c.text)
        self.assertLess(a.published, b.published)
        self.assertEqual(a.author, "@defwire")

    def test_telegram_nopreview_page(self):
        items, info = F.parse_telegram(fixture("telegram_nopreview.html"))
        self.assertEqual((items, info["has_history"]), ([], False))

    def test_rss(self):
        info, e = F.parse_feed(fixture("feed_rss.xml"), "https://news.example.com/")
        self.assertEqual(info["title"], "Example Defence News")
        self.assertEqual(len(e), 2)
        self.assertEqual(e[0]["title"], "Navy commissions new frigate \u2014 sea trials done")
        self.assertEqual(e[0]["summary"], "The frigate was commissioned. Budget: R&D & procurement.")
        self.assertEqual(e[0]["author"], "A. Reporter")
        self.assertEqual(e[1]["link"], "https://news.example.com/2026/09/hypersonic-test")
        self.assertEqual(e[1]["content"], "Full text about hypersonic test.")
        self.assertGreater(e[1]["date"], e[0]["date"])

    def test_atom(self):
        info, e = F.parse_feed(fixture("feed_atom.xml"), "https://atom.example.org/")
        self.assertEqual(e[0]["link"], "https://atom.example.org/p/1")
        self.assertEqual(e[0]["summary"], "Ship arrived.")
        self.assertEqual(e[0]["date"], F.parse_time("2026-09-21T06:00:00Z"))  # published wins over updated

    def test_billion_laughs_refused(self):
        with self.assertRaises(NetError) as cm:
            F.parse_feed(fixture("evil_entity.xml"), "https://e.com/")
        self.assertEqual(cm.exception.kind, "parse")
        with self.assertRaises(NetError):
            F.parse_feed("<html><body>no</body></html>", "https://e.com/")

    def test_time_formats(self):
        z = F.parse_time("2026-09-21T10:15:30+00:00")
        self.assertEqual(F.parse_time("2026-09-21T10:15:30.000Z"), z)
        self.assertEqual(F.parse_time("Mon, 21 Sep 2026 10:15:30 GMT"), z)
        self.assertEqual(F.parse_time("Mon Sep 21 10:15:30 +0000 2026"), z)
        self.assertEqual(F.parse_time("garbage"), 0)

    def test_discovery_and_links(self):
        self.assertEqual(F.discover_feeds(fixture("page_with_feed_link.html"), "https://x.test/a/"), ["https://x.test/feed.xml"])
        links = F.extract_links(fixture("page_nofeed.html"), "https://www.pagehost.test/")
        self.assertEqual([u for u, _ in links], ["https://www.pagehost.test/news/2026/09/frigate-arrives-at-colombo-port",
                                                 "https://www.pagehost.test/news/hypersonic-test-announced-by-ministry"])


class NetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = Mock()
        self.mock.route("/feed", fixture("feed_rss.xml"), ctype="application/rss+xml")

    def tearDown(self):
        self.mock.close()
        self.tmp.cleanup()

    def net(self, **priv):
        return Net(make_cfg(Path(self.tmp.name), privacy=priv), sleep=lambda s: None)

    def test_strict_mode_without_proxy_makes_no_request(self):
        with self.assertRaises(NetError) as cm:
            self.net(mode="strict").get(self.mock.url("/feed"))
        self.assertEqual(cm.exception.kind, "privacy")
        self.assertEqual(self.mock.hits, [])

    def test_socks_sends_hostname_not_ip_and_nothing_else_leaks(self):
        socks = Socks5({("mock.test", 80): ("127.0.0.1", self.mock.port)})
        try:
            n = self.net(mode="strict", proxy=f"127.0.0.1:{socks.port}", allow_private=False)
            res = n.get("http://mock.test/feed")
        finally:
            socks.close()
        self.assertEqual(res.status, 200)
        atyp, host, port, _ = socks.requests[0]
        self.assertEqual((atyp, host, port), (3, "mock.test", 80))  # ATYP 3 = domain name: DNS done by the proxy
        h = self.mock.hits[0][2]
        self.assertEqual(h["Host"], "mock.test")
        self.assertNotIn("Cookie", h)
        self.assertNotIn("Referer", h)
        self.assertNotIn("python", h["User-Agent"].lower())

    def test_dead_proxy_never_falls_back_to_direct(self):
        with self.assertRaises(NetError) as cm:
            self.net(mode="strict", proxy=f"127.0.0.1:{free_port()}").get(self.mock.url("/feed"))
        self.assertEqual(cm.exception.kind, "proxy")
        self.assertEqual(self.mock.hits, [])

    def test_redirect_into_private_space_is_blocked(self):
        self.mock.routes["/r1"] = lambda *a: (302, {"Location": "http://127.0.0.1:9/admin"}, b"")
        self.mock.routes["/r2"] = lambda *a: (302, {"Location": "http://localhost/x"}, b"")
        self.mock.routes["/r3"] = lambda *a: (302, {"Location": "http://169.254.169.254/latest/meta-data"}, b"")
        socks = Socks5({("mock.test", 80): ("127.0.0.1", self.mock.port)})
        try:
            n = self.net(mode="strict", proxy=f"127.0.0.1:{socks.port}", allow_private=False)
            for p in ("/r1", "/r2", "/r3"):
                with self.assertRaises(NetError, msg=p) as cm:
                    n.get("http://mock.test" + p)
                self.assertEqual(cm.exception.kind, "blocked")
            with self.assertRaises(NetError):
                n.get("http://127.0.0.1/")  # direct literal also refused
        finally:
            socks.close()

    def test_isolation_uses_different_socks_credentials_per_host(self):
        socks = Socks5({("a.test", 80): ("127.0.0.1", self.mock.port), ("b.test", 80): ("127.0.0.1", self.mock.port)})
        try:
            n = self.net(mode="strict", proxy=f"127.0.0.1:{socks.port}", allow_private=False, isolate_streams=True)
            n.get("http://a.test/feed")
            n.get("http://b.test/feed")
        finally:
            socks.close()
        ca, cb = socks.requests[0][3], socks.requests[1][3]
        self.assertEqual(ca[0], "osw")
        self.assertNotEqual(ca[1], cb[1])

    def test_limits_and_http_errors(self):
        self.mock.route("/big", b"x" * 200_000, ctype="text/plain")
        self.mock.routes["/slow"] = lambda *a: (429, {"Retry-After": "120"}, b"")
        self.mock.routes["/etag"] = lambda m, p, h, b: (304, {}, b"") if h.get("If-None-Match") == '"v1"' else (200, {"ETag": '"v1"'}, b"ok")
        self.mock.route("/img", b"GIF89a", ctype="image/gif")
        n = self.net(mode="open")
        with self.assertRaises(NetError) as cm:
            n.get(self.mock.url("/big"), max_bytes=1000)
        self.assertEqual(cm.exception.kind, "blocked")
        with self.assertRaises(NetError) as cm:
            n.get(self.mock.url("/slow"))
        self.assertEqual((cm.exception.status, cm.exception.retry_after), (429, 120))
        self.assertEqual(n.get(self.mock.url("/etag")).headers["etag"], '"v1"')
        self.assertTrue(n.get(self.mock.url("/etag"), etag='"v1"').not_modified)
        with self.assertRaises(NetError):
            n.get(self.mock.url("/img"))
        with self.assertRaises(NetError):
            n.get(self.mock.url("/nothing-here"))  # 404


class FetcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = Mock()
        self.cfg = make_cfg(Path(self.tmp.name))
        self.net = Net(self.cfg, sleep=lambda s: None)
        self.f = F.Fetchers(self.net, self.cfg)
        self._old = (F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE)
        F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE = self.mock.url(), self.mock.url("/x"), self.mock.url("/tio")

    def tearDown(self):
        F.TG_BASE, F.X_API_BASE, F.TWITTERAPI_BASE = self._old
        self.mock.close()
        self.tmp.cleanup()

    def test_telegram_poll_and_no_preview(self):
        self.mock.route("/s/defwire", fixture("telegram_channel.html"))
        self.mock.routes["/s/privatechan"] = lambda *a: (302, {"Location": "/privatechan"}, b"")
        self.mock.route("/privatechan", fixture("telegram_nopreview.html"))
        r = self.f.poll(F.Source("tg:defwire", "telegram", "defwire", "@defwire"), {})
        self.assertEqual([i.uid for i in r.items], ["101", "102", "103"])
        self.assertEqual(r.items[0].source_id, "tg:defwire")
        self.assertEqual(r.fields["label"], "Defence Wire (@defwire)")
        with self.assertRaises(NetError) as cm:
            self.f.poll(F.Source("tg:privatechan", "telegram", "privatechan", "@privatechan"), {})
        self.assertEqual(cm.exception.kind, "unavailable")
        self.mock.route("/s/weird", "<html><body>layout changed</body></html>")
        with self.assertRaises(NetError) as cm:
            self.f.poll(F.Source("tg:weird", "telegram", "weird", "@weird"), {})
        self.assertIn("unexpected page", str(cm.exception))

    def test_website_feed_etag_discovery_and_html_fallback(self):
        hits = {"n": 0}

        def feed(m, p, h, b):
            hits["n"] += 1
            return (304, {}, b"") if h.get("If-None-Match") == '"v1"' else (200, {"ETag": '"v1"', "Content-Type": "application/rss+xml"}, fixture("feed_rss.xml").encode())

        self.mock.routes["/feed.xml"] = feed
        src = F.Source("web:feed", "web", self.mock.url("/feed.xml"), "feed")
        r1 = self.f.poll(src, {})
        self.assertEqual(len(r1.items), 2)
        self.assertEqual((r1.fields["etag"], r1.fields["provider"]), ('"v1"', "feed"))
        self.assertEqual(r1.items[0].url, "https://news.example.com/2026/09/frigate-commissioned")
        self.assertTrue(self.f.poll(src, {"etag": '"v1"', "feed_url": r1.fields["feed_url"]}).not_modified)
        # page that advertises a feed -> discovered and remembered
        self.mock.route("/page.html", fixture("page_with_feed_link.html").replace("/feed.xml", self.mock.url("/feed.xml")))
        r2 = self.f.poll(F.Source("web:p", "web", self.mock.url("/page.html"), "p"), {})
        self.assertEqual((r2.fields["feed_url"], len(r2.items)), (self.mock.url("/feed.xml"), 2))
        # no feed anywhere -> headline links; robots.txt can forbid it
        self.mock.route("/nofeed.html", fixture("page_nofeed.html"))
        self.mock.route("/robots.txt", "User-agent: *\nDisallow: /nofeed.html\n", ctype="text/plain")
        self.net._robots.clear()  # earlier polls cached "no robots.txt"
        with self.assertRaises(NetError) as cm:
            self.f.poll(F.Source("web:n", "web", self.mock.url("/nofeed.html"), "n"), {})
        self.assertEqual(cm.exception.kind, "robots")
        self.mock.route("/robots.txt", "User-agent: *\nDisallow: /private\n", ctype="text/plain")
        self.net._robots.clear()
        r3 = self.f.poll(F.Source("web:n", "web", self.mock.url("/nofeed.html"), "n"), {})
        self.assertEqual(r3.fields["provider"], "html")
        self.assertEqual(len(r3.items), 1)  # only same-host (127.0.0.1) headline link qualifies
        self.assertTrue(r3.items[0].url.endswith("/news/2026/09/frigate-arrives-at-colombo-port"))

    def x_routes(self):
        tweets = {"n": 0}
        self.mock.route("/x/2/users/by/username/nasa", json.dumps({"data": {"id": "42", "name": "NASA", "username": "nasa"}}), ctype="application/json")

        def tl(m, p, h, b):
            q = parse_qs(urlparse(p).query)
            tweets["n"] += 1
            if "since_id" in q:
                d = {"data": [{"id": "1003", "text": "New hypersonic post", "created_at": "2026-09-21T11:00:00.000Z"}], "meta": {"newest_id": "1003", "result_count": 1}}
            else:
                d = {"data": [{"id": "1002", "text": "b", "created_at": "2026-09-21T10:00:00.000Z"}, {"id": "1001", "text": "a", "created_at": "2026-09-21T09:00:00.000Z"}],
                     "meta": {"newest_id": "1002", "result_count": 2}}
            return 200, {"Content-Type": "application/json"}, json.dumps(d).encode()

        self.mock.routes["/x/2/users/42/tweets"] = tl

    def test_x_official_api_since_id_and_errors(self):
        self.x_routes()
        src = F.Source("tw:nasa", "twitter", "nasa", "@nasa")
        with self.assertRaises(NetError) as cm:
            self.f.poll(src, {})
        self.assertEqual(cm.exception.kind, "config")
        self.assertIn("X_BEARER_TOKEN", str(cm.exception))
        self.cfg.vault.set("X_BEARER_TOKEN", "AAAA" + "b" * 30)
        r1 = self.f.poll(src, {})
        self.assertEqual([i.uid for i in r1.items], ["1002", "1001"])
        self.assertEqual(r1.items[0].url, "https://x.com/nasa/status/1002")
        self.assertEqual(r1.meta, {"x_user_id": "42", "x_since_id": "1002"})
        r2 = self.f.poll(src, {"meta": r1.meta})
        self.assertEqual([i.uid for i in r2.items], ["1003"])
        auth = [h[2].get("Authorization") for h in self.mock.hits if "/tweets" in h[1]]
        self.assertTrue(all(a.startswith("Bearer AAAA") for a in auth))
        last_q = parse_qs(urlparse([h[1] for h in self.mock.hits if "/tweets" in h[1]][-1]).query)
        self.assertEqual((last_q["since_id"], last_q["max_results"]), (["1002"], ["100"]))
        self.mock.route("/x/2/users/42/tweets", "{}", status=402)
        with self.assertRaises(NetError) as cm:
            self.f.poll(src, {"meta": r1.meta})
        self.assertEqual(cm.exception.kind, "quota")
        self.mock.route("/x/2/users/42/tweets", "{}", status=401)
        with self.assertRaises(NetError) as cm:
            self.f.poll(src, {"meta": r1.meta})
        self.assertEqual(cm.exception.kind, "auth")

    def test_x_provider_fallback_to_twitterapi_io(self):
        self.x_routes()
        self.mock.route("/x/2/users/42/tweets", "{}", status=401)
        self.cfg.vault.set("X_BEARER_TOKEN", "AAAA" + "b" * 30)
        self.cfg.vault.set("TWITTERAPI_KEY", "key12345678")
        self.mock.route("/tio/twitter/user/last_tweets", json.dumps({"status": "success", "tweets": [
            {"id": "77", "text": "hello", "createdAt": "Mon Sep 21 10:15:30 +0000 2026", "author": {"userName": "nasa"}}]}), ctype="application/json")
        r = self.f.poll(F.Source("tw:nasa", "twitter", "nasa", "@nasa"), {})
        self.assertEqual((r.fields["provider"], r.items[0].uid), ("twitterapi_io", "77"))
        hit = [h for h in self.mock.hits if "last_tweets" in h[1]][0]
        self.assertEqual(hit[2].get("X-Api-Key") or hit[2].get("X-API-Key"), "key12345678")
        self.assertIn("userName=nasa", hit[1])


if __name__ == "__main__":
    unittest.main()
