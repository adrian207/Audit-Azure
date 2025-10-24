@echo off
REM Azure Audit Platform - Windows Installation Script
REM Installs all prerequisites for both API and UI

echo ============================================
echo Azure Audit Platform - Installation Script
echo ============================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges
    echo Please run as Administrator
    pause
    exit /b 1
)

echo [1/7] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

echo [OK] Python found
python --version

echo.
echo [2/7] Checking Node.js installation...
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH
    echo Please install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

echo [OK] Node.js found
node --version

echo.
echo [3/7] Checking Azure CLI installation...
az --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Azure CLI not found
    echo Install from: https://aka.ms/installazurecli
    echo.
    echo Continue anyway? (Y/N)
    set /p continue=
    if /i not "%continue%"=="Y" exit /b 1
) else (
    echo [OK] Azure CLI found
    az --version | findstr "azure-cli"
)

echo.
echo [4/7] Installing Python dependencies...
cd /d "%~dp0\api"
if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found in api directory
    pause
    exit /b 1
)

echo Creating Python virtual environment...
python -m venv venv
if %errorLevel% neq 0 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing packages (this may take 5-10 minutes)...
pip install --upgrade pip
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)

echo [OK] Python dependencies installed
deactivate

echo.
echo [5/7] Installing UI dependencies...
cd /d "%~dp0\ui"
if not exist "package.json" (
    echo [ERROR] package.json not found in ui directory
    pause
    exit /b 1
)

echo Installing npm packages (this may take 3-5 minutes)...
call npm install
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install UI dependencies
    pause
    exit /b 1
)

echo [OK] UI dependencies installed

echo.
echo [6/7] Setting up environment configuration...
cd /d "%~dp0"
if not exist ".env" (
    echo Creating .env file from template...
    (
        echo # Azure Audit Platform Configuration
        echo # Created: %date% %time%
        echo.
        echo # Azure Authentication
        echo AZURE_TENANT_ID=your-tenant-id-here
        echo AZURE_CLIENT_ID=your-client-id-here
        echo AZURE_CLIENT_SECRET=your-client-secret-here
        echo AZURE_SUBSCRIPTION_ID=your-subscription-id-here
        echo.
        echo # Authentication Methods (set to true to enable)
        echo AZURE_USE_CLI=true
        echo AZURE_USE_MANAGED_IDENTITY=false
        echo.
        echo # Database Configuration
        echo DATABASE_URL=sqlite:///./audit.db
        echo.
        echo # API Configuration
        echo API_HOST=0.0.0.0
        echo API_PORT=8000
        echo.
        echo # Security
        echo SECRET_KEY=%RANDOM%%RANDOM%%RANDOM%%RANDOM%
        echo ENABLE_RATE_LIMITING=true
        echo RATE_LIMIT_REQUESTS=100
        echo RATE_LIMIT_WINDOW=60
        echo.
        echo # Performance
        echo ENABLE_CACHING=true
        echo CACHE_TTL=300
        echo MAX_CONCURRENT_EVALUATIONS=5
        echo.
        echo # Logging
        echo LOG_LEVEL=INFO
        echo ENABLE_AUDIT_LOG=true
    ) > .env
    echo [OK] .env file created - PLEASE UPDATE WITH YOUR AZURE CREDENTIALS
) else (
    echo [INFO] .env file already exists - skipping
)

echo.
echo [7/7] Running database migrations...
cd /d "%~dp0\api"
call venv\Scripts\activate.bat
python -c "from persistence.database import init_db; init_db()" 2>nul
if %errorLevel% neq 0 (
    echo [WARNING] Database initialization skipped (will auto-create on first run)
)
deactivate

echo.
echo ============================================
echo Installation Complete!
echo ============================================
echo.
echo IMPORTANT: Update the .env file with your Azure credentials:
echo   1. AZURE_TENANT_ID
echo   2. AZURE_CLIENT_ID (if using Service Principal)
echo   3. AZURE_CLIENT_SECRET (if using Service Principal)
echo   4. AZURE_SUBSCRIPTION_ID
echo.
echo Or simply login with Azure CLI:
echo   az login
echo.
echo To start the application:
echo   - API Backend:  run_api.bat
echo   - UI Frontend:  run_ui.bat
echo   - Both:         run_all.bat
echo.
echo For more information, see api\README.md
echo.
pause
