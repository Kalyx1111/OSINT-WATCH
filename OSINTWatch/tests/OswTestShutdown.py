"""Regression test for a real bug found during a live dry run: an open SSE connection
could block graceful shutdown indefinitely (uvicorn's default timeout_graceful_shutdown
is None, and it waits for every connection before ever calling the app's own shutdown
code). This launches the actual server as a subprocess - a real socket, a real SIGTERM -
because the bug only reproduced there, not under FastAPI's TestClient.
"""
import shutil
import subprocess  # nosec B404 - fixed argv, used only to launch and signal our own server in a test
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def wait_for(url: str, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:  # nosec B310 - fixed http://127.0.0.1 URL
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.2)
    return False


@unittest.skipUnless(shutil.which(sys.executable), "needs a usable python executable")
class ShutdownTests(unittest.TestCase):
    def test_process_exits_after_sigterm_even_with_an_open_sse_connection(self):
        with tempfile.TemporaryDirectory() as d:
            code = (
                "import sys; sys.path.insert(0, %r)\n"
                "from pathlib import Path\n"
                "from OswCore import Paths\n"
                "import OswServer\n"
                "OswServer.run(Paths(Path(%r)))\n"
            ) % (str(ROOT), d)
            proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)  # nosec B603
            try:
                if not wait_for("http://127.0.0.1:8765/"):
                    proc.kill()
                    out, _ = proc.communicate(timeout=5)
                    self.fail("server never came up:\n" + out)

                # Open an SSE connection and read only the first line, then move on without
                # closing it ourselves cleanly first - the point is to leave a lingering
                # streaming response open on the server when we signal it.
                req = urllib.request.urlopen("http://127.0.0.1:8765/api/alerts/stream", timeout=5)  # nosec B310
                req.readline()

                proc.terminate()  # SIGTERM
                try:
                    out, _ = proc.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, _ = proc.communicate(timeout=5)
                    self.fail("server did not exit within 15s of SIGTERM with an open SSE connection:\n" + out)
                self.assertIsNotNone(proc.returncode)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

    def test_process_exits_promptly_with_no_open_connections(self):
        with tempfile.TemporaryDirectory() as d:
            code = (
                "import sys; sys.path.insert(0, %r)\n"
                "from pathlib import Path\n"
                "from OswCore import Paths\n"
                "import OswServer\n"
                "OswServer.run(Paths(Path(%r)))\n"
            ) % (str(ROOT), d)
            proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)  # nosec B603
            try:
                self.assertTrue(wait_for("http://127.0.0.1:8765/"))
                start = time.monotonic()
                proc.terminate()
                try:
                    out, _ = proc.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, _ = proc.communicate(timeout=5)
                    self.fail("server did not exit within 15s of SIGTERM:\n" + out)
                self.assertLess(time.monotonic() - start, 5.0, "shutdown with no open connections should be fast, not just under the hard cap")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
