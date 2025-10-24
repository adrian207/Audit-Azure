@echo off
REM Start both API and UI in separate windows

echo Starting Azure Audit Platform (API + UI)...
echo.

REM Start API in new window
start "Azure Audit API" cmd /k "%~dp0run_api.bat"

REM Wait 3 seconds for API to start
timeout /t 3 /nobreak

REM Start UI in new window
start "Azure Audit UI" cmd /k "%~dp0run_ui.bat"

echo.
echo Both services starting...
echo - API: http://localhost:8000
echo - UI:  http://localhost:3000
echo.
echo Press any key to close this window (services will keep running)
pause >nul
