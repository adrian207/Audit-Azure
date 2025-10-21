#!/bin/bash
# Azure Audit Platform - Linux/Mac Installation Script
# Installs all prerequisites for both API and UI

set -e  # Exit on error

echo "============================================"
echo "Azure Audit Platform - Installation Script"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "[1/7] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python 3 is not installed${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

echo -e "${GREEN}[OK] Python found${NC}"
python3 --version

echo ""
echo "[2/7] Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js is not installed${NC}"
    echo "Please install Node.js 18+ from https://nodejs.org"
    exit 1
fi

echo -e "${GREEN}[OK] Node.js found${NC}"
node --version

echo ""
echo "[3/7] Checking Azure CLI installation..."
if ! command -v az &> /dev/null; then
    echo -e "${YELLOW}[WARNING] Azure CLI not found${NC}"
    echo "Install from: https://aka.ms/installazurecli"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}[OK] Azure CLI found${NC}"
    az --version | grep "azure-cli"
fi

echo ""
echo "[4/7] Installing Python dependencies..."
cd "$SCRIPT_DIR/api"

if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}[ERROR] requirements.txt not found${NC}"
    exit 1
fi

echo "Creating Python virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing packages (this may take 5-10 minutes)..."
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}[OK] Python dependencies installed${NC}"
deactivate

echo ""
echo "[5/7] Installing UI dependencies..."
cd "$SCRIPT_DIR/ui"

if [ ! -f "package.json" ]; then
    echo -e "${RED}[ERROR] package.json not found${NC}"
    exit 1
fi

echo "Installing npm packages (this may take 3-5 minutes)..."
npm install

echo -e "${GREEN}[OK] UI dependencies installed${NC}"

echo ""
echo "[6/7] Setting up environment configuration..."
cd "$SCRIPT_DIR"

if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cat > .env << EOF
# Azure Audit Platform Configuration
# Created: $(date)

# Azure Authentication
AZURE_TENANT_ID=your-tenant-id-here
AZURE_CLIENT_ID=your-client-id-here
AZURE_CLIENT_SECRET=your-client-secret-here
AZURE_SUBSCRIPTION_ID=your-subscription-id-here

# Authentication Methods (set to true to enable)
AZURE_USE_CLI=true
AZURE_USE_MANAGED_IDENTITY=false

# Database Configuration
DATABASE_URL=sqlite:///./audit.db

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=$(openssl rand -hex 32)
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Performance
ENABLE_CACHING=true
CACHE_TTL=300
MAX_CONCURRENT_EVALUATIONS=5

# Logging
LOG_LEVEL=INFO
ENABLE_AUDIT_LOG=true
EOF
    echo -e "${GREEN}[OK] .env file created - PLEASE UPDATE WITH YOUR AZURE CREDENTIALS${NC}"
else
    echo -e "${YELLOW}[INFO] .env file already exists - skipping${NC}"
fi

echo ""
echo "[7/7] Running database migrations..."
cd "$SCRIPT_DIR/api"
source venv/bin/activate
python -c "from persistence.database import init_db; init_db()" 2>/dev/null || echo -e "${YELLOW}[WARNING] Database initialization skipped${NC}"
deactivate

echo ""
echo "============================================"
echo "Installation Complete!"
echo "============================================"
echo ""
echo -e "${YELLOW}IMPORTANT: Update the .env file with your Azure credentials:${NC}"
echo "  1. AZURE_TENANT_ID"
echo "  2. AZURE_CLIENT_ID (if using Service Principal)"
echo "  3. AZURE_CLIENT_SECRET (if using Service Principal)"
echo "  4. AZURE_SUBSCRIPTION_ID"
echo ""
echo "Or simply login with Azure CLI:"
echo "  az login"
echo ""
echo "To start the application:"
echo "  - API Backend:  ./run_api.sh"
echo "  - UI Frontend:  ./run_ui.sh"
echo "  - Both:         ./run_all.sh"
echo ""
echo "For more information, see api/README.md"
echo ""
