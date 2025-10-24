#!/bin/bash
# Azure Audit Platform - Docker Quick Start
# This script builds and runs the platform in Docker containers

set -e

echo "============================================"
echo "Azure Audit Platform - Docker Deployment"
echo "============================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker is not running. Please start Docker first."
    exit 1
fi

echo "[OK] Docker is running"
echo ""

# Check if .env.docker exists
if [ ! -f .env.docker ]; then
    echo "[WARNING] .env.docker not found. Creating from example..."
    cp .env.docker.example .env.docker
    echo ""
    echo "[ACTION REQUIRED] Please edit .env.docker with your Azure credentials"
    echo "  1. Set AZURE_SUBSCRIPTION_ID"
    echo "  2. Set AZURE_TENANT_ID"
    echo "  3. Set AZURE_CLIENT_ID"
    echo "  4. Set AZURE_CLIENT_SECRET"
    echo "  5. Generate secure keys for API_MASTER_KEY and SECRET_KEY"
    echo ""
    echo "Run: openssl rand -hex 32"
    echo ""
    exit 0
fi

echo "[OK] Found .env.docker configuration"
echo ""

# Load environment variables
export $(cat .env.docker | grep -v '^#' | xargs)

echo "Building Docker images..."
echo "This may take 5-10 minutes on first run."
echo ""

docker-compose build

echo ""
echo "[OK] Build completed successfully"
echo ""

echo "Starting containers..."
docker-compose up -d

echo ""
echo "============================================"
echo "Deployment Complete!"
echo "============================================"
echo ""
echo "Services are now running:"
echo "  - API:      http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - UI:       http://localhost:3000"
echo "  - Database: localhost:5432"
echo ""
echo "To view logs:    docker-compose logs -f"
echo "To stop:         docker-compose down"
echo "To restart:      docker-compose restart"
echo ""
echo "Waiting for services to be ready..."
sleep 10

echo ""
echo "Checking service health..."
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "[OK] API is healthy"
else
    echo "[WARNING] API may still be starting up..."
fi

echo ""
echo "Opening UI in browser..."
if command -v xdg-open > /dev/null; then
    xdg-open http://localhost:3000
elif command -v open > /dev/null; then
    open http://localhost:3000
fi

echo ""
echo "Press Ctrl+C to exit logs..."
sleep 2

docker-compose logs -f
