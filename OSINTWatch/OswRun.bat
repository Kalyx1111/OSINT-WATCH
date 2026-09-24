@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title OSINT Watch

where py >nul 2>nul
if %ERRORLEVEL%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if %ERRORLEVEL%==0 (
    set "PY=python"
  ) else (
    echo Python 3.10 or newer was not found on this computer.
    echo Install it from https://www.python.org/downloads/ - tick "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
  )
)

if not exist venv (
  echo Creating a virtual environment in .\venv ...
  %PY% -m venv venv
  if errorlevel 1 (
    echo Could not create the virtual environment.
    pause
    exit /b 1
  )
)

call venv\Scripts\activate.bat

echo Checking dependencies...
python -m pip install --disable-pip-version-check -q --upgrade pip
python -m pip install --disable-pip-version-check -q -r OswRequirements.txt
if errorlevel 1 (
  if exist wheels (
    echo Online install failed - trying the offline wheels\ folder...
    python -m pip install --disable-pip-version-check -q --no-index --find-links wheels -r OswRequirements.txt
  )
)
python -c "import fastapi, uvicorn, httpx, bs4" 2>nul
if errorlevel 1 (
  echo.
  echo Dependency install failed. Check your internet connection, or see wheels\README.txt
  echo to set up an offline install.
  echo.
  pause
  exit /b 1
)

echo.
python OswApp.py %*

echo.
echo OSINT Watch has stopped.
pause
