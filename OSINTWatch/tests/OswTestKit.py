"""Test helpers: config factory, mock HTTP server, tiny SOCKS5 server (records what the client sent)."""
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import OswConfig as C  # noqa: E402
from OswCore import Paths  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def make_cfg(tmp: Path, **sections) -> C.Config:
    """Config in a temp folder. Defaults for tests: open mode + private hosts allowed (mock servers are on 127.0.0.1)."""
    cfg = C.Config(Paths(tmp))
    patch = {"privacy": {"mode": "open", "allow_private": True, "respect_robots": True}}
    for k, v in sections.items():
        patch.setdefault(k, {}).update(v)
    errs = cfg.save_settings(patch)
    assert not errs, errs
    return cfg


class Mock:
    def __init__(self):
        self.routes, self.hits = {}, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.hits.append((self.command, self.path, dict(self.headers), body))
                fn = outer.routes.get(self.path.split("?")[0])
                status, hdrs, data = fn(self.command, self.path, dict(self.headers), body) if fn else (404, {}, b"not found")
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _do

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path=""):
        return f"http://127.0.0.1:{self.port}{path}"

    def route(self, path, body=b"", status=200, ctype="text/html; charset=utf-8", headers=None):
        h = {"Content-Type": ctype, **(headers or {})}
        data = body.encode() if isinstance(body, str) else body
        self.routes[path] = lambda m, p, hd, b: (status, h, data)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Socks5:
    """Minimal SOCKS5 server. mapping: {(hostname, port): (ip, real_port)}. Records (atyp, host, port, creds)."""

    def __init__(self, mapping):
        self.mapping, self.requests = mapping, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    @staticmethod
    def _rx(c, n):
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise OSError("eof")
            buf += chunk
        return buf

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        creds = None
        try:
            _, nm = self._rx(c, 2)
            methods = self._rx(c, nm)
            if 2 in methods:
                c.sendall(b"\x05\x02")
                self._rx(c, 1)
                u = self._rx(c, self._rx(c, 1)[0]).decode()
                pw = self._rx(c, self._rx(c, 1)[0]).decode()
                creds = (u, pw)
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")
            _, cmd, _, atyp = self._rx(c, 4)
            if atyp == 1:
                host = socket.inet_ntoa(self._rx(c, 4))
            elif atyp == 3:
                host = self._rx(c, self._rx(c, 1)[0]).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._rx(c, 16))
            port = int.from_bytes(self._rx(c, 2), "big")
            self.requests.append((atyp, host, port, creds))
            target = self.mapping.get((host, port))
            if not target:
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            up = socket.create_connection(target)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            def pipe(a, b):
                try:
                    while (d := a.recv(65536)):
                        b.sendall(d)
                except OSError:
                    pass
                finally:
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    up.close()

            threading.Thread(target=pipe, args=(up, c), daemon=True).start()
            pipe(c, up)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.sock.close()
