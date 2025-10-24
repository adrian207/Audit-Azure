@echo off
REM Start Azure Audit Platform - React UI

echo Starting Azure Audit UI...
cd /d "%~dp0\ui"

if not exist "node_modules" (
    echo [ERROR] Node modules not found
    echo Please run install.bat first
    pause
    exit /b 1
)

echo Starting React development server...
echo UI will open at http://localhost:3000
echo.

call npm start
