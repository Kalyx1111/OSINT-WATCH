#!/usr/bin/env python3
"""OSINT Watch - entrypoint.

Run: python OswApp.py   (or OswRun.bat / OswRun.sh)
Data, logs and the database live under ./data next to this file (or $OSW_HOME if set) -
delete that folder to reset everything.
By Aryan / @EPureNest
"""
from __future__ import annotations

import os
import sys
import threading
import time
import webbrowser

from OswCore import APP_NAME, APP_VERSION, DEFAULT_PATHS, log, mark_heartbeat, now, read_json, setup_logging

BANNER = r"""
   ___  ____ ____ _  _ ___    _        __    _____ ____ _  _
  / _ \/ ___/ ___| \| |_ _|  | |      / /\  |_   _/ ___| || |
 | | | \___ \___ \ .` || |   | |     / /__\   | || |     || |
 | |_| |___) |__) |\  || |   | |___ / /____\  | || |___|__   _|
  \___/|____/____/|_|\_|___|  |_____/_/    \_\ |_| \____|  |_|
"""


def check_heartbeat(paths) -> None:
    hb = read_json(paths.heartbeat, None)
    if hb and hb.get("status") == "running":
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(hb.get("started", 0)))
        log.warning("Previous run (started %s) did not shut down cleanly. No action needed: the database uses "
                    "write-ahead logging and settings are saved atomically, so nothing should be lost. If the "
                    "dashboard looks off, use Diagnostics -> Optimize & prune.", stamp)
    mark_heartbeat(paths, "running", started=now(), pid=os.getpid())

def open_browser_soon(url: str) -> None:
    def go():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception as e:
            log.info("could not auto-open a browser (%s) - open %s manually", type(e).__name__, url)
    threading.Thread(target=go, daemon=True).start()


def main() -> int:
    paths = DEFAULT_PATHS
    paths.ensure()
    setup_logging(debug="--debug" in sys.argv)
    print(BANNER)
    print(f"{APP_NAME} {APP_VERSION} - by Aryan / @EPureNest")
    print(f"Data directory : {paths.data}")

    import OswHardware as hw
    h = hw.report(paths.data)
    print(f"Machine        : {h['os']}, {h['cpu_cores']} cores, "
         f"{(str(round(h['ram_mb']/1024,1))+' GB RAM') if h['ram_mb'] else 'RAM unknown'}, "
         f"{h['disk_free_gb']} GB free")
    if not h["internet"]:
        print("No internet connection detected - sources will not be reachable until one is available.")

    check_heartbeat(paths)

    from OswConfig import Config  # local import: keep failures below inside the try/except
    cfg = Config(paths)
    for note in cfg.load_notes:
        log.warning("startup note: %s", note)
    s = cfg.settings["server"]
    scheme = "https" if (s["tls_cert"] and s["tls_key"]) else "http"
    url = f"{scheme}://{'127.0.0.1' if s['host'] in ('0.0.0.0', '::') else s['host']}:{s['port']}/"  # nosec B104 - display string only; the real bind uses the validated server.host in OswServer.run()
    print(f"Dashboard      : {url}")
    print("Keep this window open. Press Ctrl+C to stop.\n")

    if s["open_browser"]:
        open_browser_soon(url)

    try:
        import OswServer
        OswServer.run(paths)
        return 0
    except KeyboardInterrupt:
        print("\nStopping...")
        return 0
    except OSError as e:
        if "address already in use" in str(e).lower() or getattr(e, "errno", None) in (98, 10048):
            print(f"\nPort {s['port']} is already in use. Close whatever is using it, or change "
                 f"server.port in data/OswSettings.json, then run this again.")
        else:
            log.exception("startup failed")
            print(f"\n{APP_NAME} could not start ({type(e).__name__}: {e}). See logs/Osw.log for details.")
        return 1
    except Exception as e:  # last-resort: never dump a bare traceback on the user
        log.exception("fatal error")
        print(f"\n{APP_NAME} hit an unexpected problem ({type(e).__name__}: {e}). See logs/Osw.log for details.")
        return 1
    finally:
        # A normal stop is marked from inside OswServer.App.stop() - see the note on
        # mark_heartbeat(). This only fires for a failure before that point (e.g. the
        # port was already in use), so the next startup doesn't wrongly call it a crash.
        mark_heartbeat(paths, "stopped", ended=now())


if __name__ == "__main__":
    sys.exit(main())
