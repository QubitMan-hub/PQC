@echo off
setlocal
pushd "%~dp0" || exit /b 1
if exist ".venv\Scripts\python.exe" goto install
py -3 -c "import sys; sys.exit(sys.version_info.__lt__((3, 11)))" >nul 2>nul
if not errorlevel 1 (
  py -3 -m venv .venv
  goto created
)
python -c "import sys; sys.exit(sys.version_info.__lt__((3, 11)))" >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 or newer is required. Install Python from https://www.python.org/downloads/windows/
  echo Enable Add Python to PATH, reopen Command Prompt, then run setup.cmd again.
  popd
  exit /b 1
)
python -m venv .venv
:created
if errorlevel 1 goto failed
:install
echo Installing PQC into this folder's private Python environment...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -c constraints.txt .
if errorlevel 1 goto failed
echo.
echo Installation complete. Run pqc.cmd for the guided menu.
echo Checking OpenSSL. If it is missing, install 64-bit OpenSSL 3.5 or newer.
call pqc.cmd doctor
set "setup_result=%errorlevel%"
popd
exit /b %setup_result%
:failed
echo Setup stopped. Fix the error above, then run setup.cmd again.
popd
exit /b 1

