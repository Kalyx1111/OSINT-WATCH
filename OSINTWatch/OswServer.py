"""OSINT Watch - local dashboard server (FastAPI).

Binds to 127.0.0.1 by default. Two lightweight defenses for a browser-hosted local API:
  * Host-header check on every request (blocks DNS-rebinding: a remote page tricking the
    browser into addressing this server as if it were the remote origin)
  * a per-run random token, embedded only in the page's own DOM, required on every
    state-changing request (blocks a malicious page elsewhere in the browser from
    driving this API - it cannot read the token via the Same-Origin Policy)
By Aryan / @EPureNest
"""
from __future__ import annotations

import contextlib
import json
import os
import queue
import secrets
import subprocess  # nosec B404 - fixed argv only, built from a validated opener template
import threading
import time
from pathlib import Path

import uvicorn
from fastapi import Body, FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

import OswHardware as hw
from OswConfig import Config, split_opener
from OswCore import APP_NAME, APP_VERSION, LIMITS, Paths, WEB_FILE, atomic_write, log, mark_heartbeat, new_cid, now, safe_http_url
from OswEngine import Engine
from OswNet import Net, NetError, detect_local_tor
from OswNotify import Bus, Dispatcher
from OswStore import Store

API_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}


class App:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.cfg = Config(paths)
        self.store = Store(paths.db)
        self.net = Net(self.cfg)
        self.bus = Bus()
        self.dispatcher = Dispatcher(self.cfg, self.net, self.store, self.bus)
        self.engine = Engine(self.cfg, self.net, self.store, self.dispatcher, default_workers=hw.suggested_workers(hw.total_ram_mb()))
        self.shutdown_event = threading.Event()
        self.token = secrets.token_urlsafe(24)
        paths.token.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(paths.token, self.token, secure=True)

    def start(self) -> None:
        self.dispatcher.start()
        self.engine.start()

    def stop(self) -> None:
        self.shutdown_event.set()
        self.engine.stop()
        self.dispatcher.stop()
        self.store.close()
        mark_heartbeat(self.paths, "stopped", ended=now())


def _err(errors, status: int = 422) -> JSONResponse:
    return JSONResponse({"ok": False, "errors": errors}, status_code=status)


def _neterr(e: NetError) -> JSONResponse:
    status = {"blocked": 400, "robots": 400, "config": 409, "auth": 401, "quota": 429,
             "privacy": 409, "unavailable": 404}.get(e.kind, 502)
    body = {"ok": False, "kind": e.kind, "error": str(e)}
    if e.retry_after:
        body["retry_after"] = e.retry_after
    return JSONResponse(body, status_code=status)


def _allowed_hosts(cfg: Config) -> set[str]:
    h = {"127.0.0.1", "localhost", "[::1]", "::1"}
    h.add(cfg.settings["server"]["host"])
    return h


def create_app(paths: Paths) -> FastAPI:
    a = App(paths)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        a.start()
        log.info("%s %s ready on %s:%s", APP_NAME, APP_VERSION, a.cfg.settings["server"]["host"], a.cfg.settings["server"]["port"])
        try:
            yield
        finally:
            a.stop()

    app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.a = a

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.url.hostname or "").lower()
        if host not in _allowed_hosts(a.cfg):
            return PlainTextResponse("host not allowed", status_code=421)
        if request.method in API_MUTATING and request.url.path.startswith("/api/"):
            if request.headers.get("x-osw-token") != a.token:
                return JSONResponse({"ok": False, "error": "missing or invalid session token - reload the page"}, status_code=403)
        resp = await call_next(request)
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.exception_handler(Exception)
    async def catch_all(request: Request, exc: Exception):
        cid = new_cid()
        log.exception("unhandled error [%s] on %s %s", cid, request.method, request.url.path)
        return JSONResponse({"ok": False, "error": f"internal error (ref {cid}) - see logs/Osw.log"}, status_code=500)

    # -------------------------------------------------------------- page
    @app.get("/", response_class=HTMLResponse)
    def index():
        html = WEB_FILE.read_text(encoding="utf-8")
        return html.replace("__OSW_TOKEN__", a.token)

    # -------------------------------------------------------------- status
    @app.get("/api/status")
    def status():
        return {"app": APP_NAME, "version": APP_VERSION, "started_at": a.engine.started_at, "now": now(),
                "counts": a.store.counts(), "privacy": a.net.privacy_state(), "notify": a.dispatcher.status(),
                "limits": LIMITS, "load_notes": a.cfg.load_notes}

    @app.get("/api/hardware")
    def hardware():
        return hw.report(a.paths.data)

    # -------------------------------------------------------------- watchlist
    @app.get("/api/watchlist")
    def get_watchlist():
        return a.cfg.watchlist

    @app.put("/api/watchlist")
    def put_watchlist(body: dict = Body(...)):
        errors = a.cfg.save_watchlist(body)
        if errors:
            return _err(errors)
        a.engine.reload()
        return {"ok": True, "watchlist": a.cfg.watchlist}

    # -------------------------------------------------------------- settings
    @app.get("/api/settings")
    def get_settings():
        return a.cfg.settings

    @app.put("/api/settings")
    def put_settings(body: dict = Body(...)):
        errors = a.cfg.save_settings(body)
        if errors:
            return _err(errors)
        a.net._robots.clear()
        return {"ok": True, "settings": a.cfg.settings}

    @app.get("/api/tor")
    def tor_probe():
        return {"found": detect_local_tor()}

    # -------------------------------------------------------------- secrets (values never returned)
    @app.get("/api/secrets")
    def secrets_status():
        return a.cfg.vault.status()

    @app.put("/api/secrets/{name}")
    def set_secret(name: str, body: dict = Body(...)):
        try:
            a.cfg.vault.set(name.upper(), str(body.get("value", "")))
        except ValueError as e:
            return _err([str(e)])
        return {"ok": True}

    @app.delete("/api/secrets/{name}")
    def delete_secret(name: str):
        try:
            a.cfg.vault.delete(name.upper())
        except ValueError as e:
            return _err([str(e)])
        return {"ok": True}

    # -------------------------------------------------------------- sources
    @app.get("/api/sources")
    def sources():
        return a.engine.sources_view()

    @app.post("/api/sources/poll")
    def poll_now(body: dict = Body(default={})):
        n = a.engine.poll_now(body.get("id"))
        return {"ok": True, "queued": n}

    @app.post("/api/sources/reset-backoff")
    def reset_backoff():
        return {"ok": True, "reset": a.store.reset_backoff()}

    # -------------------------------------------------------------- items & alerts
    @app.get("/api/items")
    def items(kind: str | None = None, source_id: str | None = None, q: str | None = Query(None, max_length=200),
              before_id: int | None = None, limit: int = Query(50, ge=1, le=200)):
        return a.store.list_items(kind=kind, source_id=source_id, q=q, before_id=before_id, limit=limit)

    @app.get("/api/alerts")
    def alerts(before_id: int | None = None, limit: int = Query(50, ge=1, le=200)):
        return a.store.list_alerts(before_id=before_id, limit=limit)

    @app.get("/api/alerts/stream")
    def alerts_stream(request: Request):
        q = a.bus.subscribe()

        async def gen():
            deadline = time.monotonic() + 6 * 3600
            last_ping = time.monotonic()
            try:
                yield "retry: 3000\n\n"
                while time.monotonic() < deadline:
                    if a.shutdown_event.is_set() or await request.is_disconnected():
                        break
                    try:
                        ev = await run_in_threadpool(q.get, True, 1.0)  # blocks up to 1s in a worker thread, not the event loop
                    except queue.Empty:
                        if time.monotonic() - last_ping >= 15:
                            yield ": ping\n\n"
                            last_ping = time.monotonic()
                        continue
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
            finally:
                a.bus.unsubscribe(q)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"})

    # -------------------------------------------------------------- notifications
    @app.post("/api/notify/test/{channel}")
    def notify_test(channel: str):
        return a.dispatcher.test(channel)

    # -------------------------------------------------------------- privacy diagnostics
    @app.get("/api/privacy/egress")
    def egress():
        try:
            return {"ok": True, **a.net.egress_check()}
        except NetError as e:
            return _neterr(e)
        except (ValueError, KeyError):
            return _err(["check.torproject.org returned an unexpected reply"], 502)

    # -------------------------------------------------------------- open link via configured opener
    @app.post("/api/open")
    def open_link(body: dict = Body(...)):
        u = safe_http_url(str(body.get("url", "")))
        if not u:
            return _err(["not a valid link"], 400)
        template = a.cfg.settings["links"]["opener"]
        if not template:
            return {"ok": False, "configured": False}
        try:
            argv = split_opener(template) + [u]
            subprocess.Popen(argv, close_fds=True, start_new_session=(os.name != "nt"))  # nosec B603
        except (OSError, ValueError) as e:
            return _err([f"could not launch opener: {e}"], 500)
        return {"ok": True, "configured": True}

    # -------------------------------------------------------------- maintenance
    @app.post("/api/maintenance/backup")
    def backup():
        a.paths.backups.mkdir(parents=True, exist_ok=True)
        dest = a.paths.backups / f"Osw-{now()}.db"
        a.store.backup(dest)
        return {"ok": True, "file": dest.name}

    @app.post("/api/maintenance/optimize")
    def optimize():
        a.store.optimize()
        n = a.store.prune(a.cfg.settings["storage"]["retention_days"])
        return {"ok": True, "pruned": n, "integrity": a.store.integrity()}

    @app.get("/api/export")
    def export():
        return {"exported_at": now(), "app": APP_NAME, "version": APP_VERSION, "settings": a.cfg.settings, "watchlist": a.cfg.watchlist}

    return app


def run(paths: Paths) -> None:
    app = create_app(paths)
    s: App = app.state.a
    server = s.cfg.settings["server"]
    kwargs = dict(host=server["host"], port=server["port"], log_config=None, access_log=False, timeout_graceful_shutdown=10)
    if server["tls_cert"] and server["tls_key"]:
        kwargs.update(ssl_certfile=server["tls_cert"], ssl_keyfile=server["tls_key"])
    uvicorn.run(app, **kwargs)
