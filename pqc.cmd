@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo PQC is not set up in this folder. Run setup.cmd first.
  exit /b 1
)
if not defined PQC_OPENSSL if exist "%ProgramFiles%\OpenSSL-Win64\bin\libssl-3-x64.dll" set "PQC_OPENSSL=%ProgramFiles%\OpenSSL-Win64\bin"
if "%~1"=="" (
  "%~dp0.venv\Scripts\python.exe" -m pqc start
) else (
  "%~dp0.venv\Scripts\python.exe" -m pqc %*
)
exit /b %errorlevel%

