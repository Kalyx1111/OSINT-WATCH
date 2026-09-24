#!/usr/bin/env bash
# OSINT Watch launcher - Linux, macOS, and Android (Termux).
set -uo pipefail
cd "$(dirname "$0")"

pause() { printf '\n'; read -r -p "Press Enter to exit..." _ || true; }

PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer was not found."
  if [ -n "${PREFIX:-}" ] && [[ "$PREFIX" == *com.termux* ]]; then
    echo "On Termux, install it with:  pkg install python"
  else
    echo "Install it from https://www.python.org/downloads/ or your package manager."
  fi
  pause; exit 1
fi

if [ ! -d venv ]; then
  echo "Creating a virtual environment in ./venv ..."
  "$PY" -m venv venv || { echo "Could not create the virtual environment."; pause; exit 1; }
fi
# shellcheck disable=SC1091
source venv/bin/activate

echo "Checking dependencies..."
python -m pip install --disable-pip-version-check -q --upgrade pip
if ! python -m pip install --disable-pip-version-check -q -r OswRequirements.txt; then
  if [ -d wheels ]; then
    echo "Online install failed - trying the offline wheels/ folder..."
    python -m pip install --disable-pip-version-check -q --no-index --find-links wheels -r OswRequirements.txt
  fi
fi
if ! python -c "import fastapi, uvicorn, httpx, bs4" >/dev/null 2>&1; then
  echo
  echo "Dependency install failed. Check your internet connection, or see wheels/README.txt"
  echo "to set up an offline install."
  pause; exit 1
fi

echo
python OswApp.py "$@"

echo "OSINT Watch has stopped."
pause
