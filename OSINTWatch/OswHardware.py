"""OSINT Watch - hardware/environment check. Stdlib only (no psutil): fewer offline-install failure points.

By Aryan / @EPureNest
"""
from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket
import subprocess  # nosec B404 - fixed argv only
import sys
from pathlib import Path

from OswCore import IS_TERMUX, IS_WINDOWS
from OswNet import detect_local_tor


def cpu_count() -> int:
    return os.cpu_count() or 2


def total_ram_mb() -> int | None:
    try:
        if IS_WINDOWS:
            class MEMSTAT(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                           ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                           ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                           ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                           ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MEMSTAT()
            m.dwLength = ctypes.sizeof(MEMSTAT)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore[attr-defined]
            return int(m.ullTotalPhys / (1024 * 1024))
        if sys.platform == "darwin":
            r = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, timeout=5, text=True, check=False)  # nosec B603 B607
            return int(int(r.stdout.strip()) / (1024 * 1024)) if r.returncode == 0 else None
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except Exception:
        return None
    return None


def disk_free_gb(path: Path) -> float:
    try:
        return round(shutil.disk_usage(path).free / (1024 ** 3), 1)
    except OSError:
        return 0.0


def suggested_workers(ram_mb: int | None) -> int:
    n = cpu_count()
    w = max(2, min(n, 8))
    if ram_mb and ram_mb < 3000:
        w = min(w, 2)
    return w


def has_internet(timeout: float = 2.5) -> bool:
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 443)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def report(data_dir: Path) -> dict:
    ram = total_ram_mb()
    return {
        "os": f"{platform.system()} {platform.release()}".strip(),
        "python": platform.python_version(),
        "termux": IS_TERMUX,
        "cpu_cores": cpu_count(),
        "ram_mb": ram,
        "disk_free_gb": disk_free_gb(data_dir),
        "internet": has_internet(),
        "tor_detected": detect_local_tor(),
        "suggested_workers": suggested_workers(ram),
        "notify_backend": ("Termux:API" if IS_TERMUX else "PowerShell toasts" if IS_WINDOWS
                           else "osascript" if sys.platform == "darwin" else "notify-send (libnotify)"),
    }
