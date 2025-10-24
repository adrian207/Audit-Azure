@echo off
REM Check for Azure Security Benchmark Updates

echo ============================================
echo Azure Security Benchmark Update Checker
echo ============================================
echo.

cd /d "%~dp0\api"

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found
    echo Please run install.bat first
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo Checking for benchmark updates...
echo.

python -m scripts.update_benchmarks

if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] Benchmark check complete
) else (
    echo.
    echo [ERROR] Benchmark check failed
)

deactivate
echo.
pause
