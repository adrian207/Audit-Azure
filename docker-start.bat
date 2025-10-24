@echo off
REM Azure Audit Platform - Docker Quick Start
REM This script builds and runs the platform in Docker containers

echo ============================================
echo Azure Audit Platform - Docker Deployment
echo ============================================
echo.

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo [OK] Docker is running
echo.

REM Check if .env.docker exists
if not exist .env.docker (
    echo [WARNING] .env.docker not found. Creating from example...
    copy .env.docker.example .env.docker
    echo.
    echo [ACTION REQUIRED] Please edit .env.docker with your Azure credentials
    echo   1. Set AZURE_SUBSCRIPTION_ID
    echo   2. Set AZURE_TENANT_ID
    echo   3. Set AZURE_CLIENT_ID
    echo   4. Set AZURE_CLIENT_SECRET
    echo   5. Generate secure keys for API_MASTER_KEY and SECRET_KEY
    echo.
    echo Run: openssl rand -hex 32
    echo.
    pause
    exit /b 0
)

echo [OK] Found .env.docker configuration
echo.

REM Load environment variables
for /f "delims=" %%x in (.env.docker) do (set "%%x")

echo Building Docker images...
echo This may take 5-10 minutes on first run.
echo.

docker-compose build

if %errorlevel% neq 0 (
    echo [ERROR] Docker build failed
    pause
    exit /b 1
)

echo.
echo [OK] Build completed successfully
echo.

echo Starting containers...
docker-compose up -d

if %errorlevel% neq 0 (
    echo [ERROR] Failed to start containers
    pause
    exit /b 1
)

echo.
echo ============================================
echo Deployment Complete!
echo ============================================
echo.
echo Services are now running:
echo   - API:      http://localhost:8000
echo   - API Docs: http://localhost:8000/docs
echo   - UI:       http://localhost:3000
echo   - Database: localhost:5432
echo.
echo To view logs:    docker-compose logs -f
echo To stop:         docker-compose down
echo To restart:      docker-compose restart
echo.
echo Waiting for services to be ready...
timeout /t 10 /nobreak >nul

echo.
echo Checking service health...
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] API is healthy
) else (
    echo [WARNING] API may still be starting up...
)

echo.
echo Opening UI in browser...
start http://localhost:3000

echo.
echo Press any key to view logs (Ctrl+C to exit logs)...
pause >nul

docker-compose logs -f
