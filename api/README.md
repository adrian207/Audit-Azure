# Audit-Azure

**Author:** Adrian Johnson <adrian207@gmail.com>

Audit-Azure is a comprehensive, enterprise-grade platform for auditing Azure environments against Microsoft Azure Security Benchmark (ASB) and industry compliance frameworks. Built with security, performance, and usability in mind.

## ✨ What's New

**🎉 5 New Security Evaluators Added (40+ Automated Checks)**
- ✅ **Azure Policy Evaluator** - Governance & compliance (GS-1 through GS-6)
- ✅ **Data Protection Evaluator** - Encryption & data security (DP-1 through DP-7)  
- ✅ **Network Security Evaluator** - NSG rules, DDoS, WAF, Firewalls (NS-1 through NS-7)
- ✅ **Vulnerability Management Evaluator** - Defender for Cloud, patch mgmt (PV-1 through PV-7)
- ✅ **Logging & Monitoring Evaluator** - Log Analytics, diagnostics (LT-1 through LT-6)

See [NEW_EVALUATORS_SUMMARY.md](../docs/NEW_EVALUATORS_SUMMARY.md) for complete details.

## Features
- 🔐 **Security-First Design**: Rate limiting, API key auth, audit logging, credential encryption
- ⚡ **High Performance**: Async evaluations, caching, batch processing, connection pooling
- 🎯 **Azure Security Benchmark**: Full ASB v3.0 implementation with 74+ controls across 12 domains
- 🏛️ **Compliance Frameworks**: Pre-built mappings for CIS, NIST SP 800-53, PCI-DSS, ISO 27001
- 📊 **Secure Score**: Microsoft-aligned scoring algorithm with trend tracking
- 🔄 **Auto-Updates**: Automated checks for Microsoft baseline updates
- 🎨 **Modern React UI**: User-friendly dashboard with visualizations
- 🔧 **Auto-Remediation**: Generate PowerShell/CLI/Bicep/Terraform scripts
- � **Professional Documentation**: Complete API reference and deployment guides

## ⏱️ Execution Time Estimates

**Initial Setup:**
- Installation (Windows): ~10-15 minutes
- Installation (Linux/Mac): ~8-12 minutes
- Azure authentication setup: ~5 minutes

**Per-Subscription Audit Times:**
- Small environment (<50 resources): 2-5 minutes
- Medium environment (50-500 resources): 5-15 minutes
- Large environment (500-5000 resources): 15-45 minutes
- Enterprise (5000+ resources): 45-120 minutes

**Individual Evaluator Times:**
- Identity/Entra ID checks: 30-90 seconds
- Network Security (NSG analysis): 1-3 minutes per 100 NSGs
- Azure Policy compliance: 2-5 minutes
- Storage account security: 30-60 seconds per 100 accounts
- Data protection (encryption): 1-2 minutes per 100 resources
- Microsoft Defender assessment: 1-2 minutes
- Secure Score calculation: 5-10 seconds
- Report generation: 10-30 seconds

**Performance Factors:**
- API response times from Azure (biggest factor)
- Number of subscriptions being audited
- Resource count and distribution
- Network latency to Azure regions
- Concurrent evaluation limit (default: 5)

**Optimization Tips:**
- Enable caching (default TTL: 5 minutes) for repeated queries
- Use batch processing for large resource sets
- Run during off-peak hours for better Azure API performance
- Increase `MAX_CONCURRENT_EVALUATIONS` on powerful hardware

## Architecture

The project is organized into the following directories:

- **api/** - FastAPI REST API with security and performance enhancements
- **ui/** - Modern React web interface with dashboard
- **azure_sdk/** - Azure SDK integration layer (Resource Graph, Policy, Monitor, Defender, Entra ID)
- **evaluators/** - Security evaluators for ASB controls (Identity, Network, Data, etc.)
- **controls/** - Azure Security Benchmark control definitions (74+ controls)
- **persistence/** - SQLAlchemy models and database logic
- **scripts/** - Utility scripts including benchmark update checker
- **tests/** - Comprehensive pytest test suite
- **docs/** - Complete documentation and API reference

## 🚀 Quick Start (Recommended)

### Automated Installation

**Windows:**
```batch
# Run as Administrator
install.bat
```

**Linux/Mac:**
```bash
chmod +x install.sh
sudo ./install.sh
```

The installer will:
1. ✅ Verify Python 3.8+ and Node.js 18+ are installed
2. ✅ Check for Azure CLI (recommended but optional)
3. ✅ Create Python virtual environment
4. ✅ Install all Python dependencies (~5-10 minutes)
5. ✅ Install all npm packages (~3-5 minutes)
6. ✅ Create .env configuration file
7. ✅ Initialize database

### Manual Installation

If you prefer manual setup:

**Backend (API):**
```bash
cd api
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

**Frontend (UI):**
```bash
cd ui
npm install
```

### Azure Authentication Setup

Choose one of these methods:

**Option 1: Azure CLI (Easiest)**
```bash
az login
az account set --subscription "your-subscription-id"
```

**Option 2: Service Principal (Production)**
```bash
# Create service principal
az ad sp create-for-rbac --name "AuditAzure" --role Reader

# Update .env file with credentials:
# AZURE_TENANT_ID=<tenant-id>
# AZURE_CLIENT_ID=<app-id>
# AZURE_CLIENT_SECRET=<password>
# AZURE_SUBSCRIPTION_ID=<subscription-id>
```

**Option 3: Managed Identity (Azure-hosted)**
```bash
# Set in .env:
# AZURE_USE_MANAGED_IDENTITY=true
```

### Running the Platform

**Start Backend:**
```bash
cd api
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

uvicorn main:app --host 0.0.0.0 --port 8000
```

**Start Frontend:**
```bash
cd ui
npm start
```

Access the platform at: **http://localhost:3000**

## 🛡️ Security Features

### Authentication & Authorization
- **API Key Authentication**: Secure API access with hashed keys
- **Rate Limiting**: Configurable request limits (default: 100 req/min)
- **Audit Logging**: Complete audit trail of all operations
- **Role-Based Access Control**: Permission-based endpoint access

### Data Protection
- **Credential Encryption**: Fernet symmetric encryption for secrets
- **Secure Headers**: X-Frame-Options, CSP, HSTS enabled
- **Input Validation**: Sanitization of all user inputs
- **Azure Key Vault Integration**: Production credential storage

### Configuration (`.env`):
```bash
# Security Settings
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100        # Max requests per window
RATE_LIMIT_WINDOW=60           # Window in seconds
SECRET_KEY=<auto-generated>     # Encryption key
ENABLE_AUDIT_LOG=true          # Log all operations
API_MASTER_KEY=<generate-key>  # Optional API key
```

**Generate secure API key:**
```bash
# Windows PowerShell
$key = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
echo $key

# Linux/Mac
openssl rand -hex 32
```

## ⚡ Performance Optimization

### Caching
- **Enabled by default** with 5-minute TTL
- Caches Azure API responses to reduce latency
- Automatic cache invalidation

### Concurrent Processing
- **Async evaluations**: Run multiple checks in parallel
- **Batch processing**: Process resources in batches
- **Connection pooling**: Reuse Azure SDK connections

### Configuration (`.env`):
```bash
# Performance Settings
ENABLE_CACHING=true
CACHE_TTL=300                     # Cache lifetime in seconds
MAX_CONCURRENT_EVALUATIONS=5      # Parallel evaluations
BATCH_SIZE=50                     # Resources per batch
QUERY_PAGE_SIZE=100               # Results per page
```

**Tuning for Large Environments:**
- Increase `MAX_CONCURRENT_EVALUATIONS` to 10-15 on high-CPU systems
- Reduce `CACHE_TTL` to 60-120 for frequently changing environments
- Increase `BATCH_SIZE` to 100-200 for better throughput

## 🔄 Keeping Benchmarks Up-to-Date

### Automatic Update Checker

Check for Microsoft baseline updates:

```bash
cd api
source venv/bin/activate  # or venv\Scripts\activate on Windows
python -m scripts.update_benchmarks
```

This will:
1. Check Azure Security Benchmark (ASB) for updates
2. Download latest versions from Microsoft GitHub
3. Compare against cached versions
4. Update local control definitions if changes detected

### Scheduled Updates (Recommended)

**Windows Task Scheduler:**
```batch
# Create task to run monthly
schtasks /create /tn "Azure Audit Benchmark Update" /tr "C:\path\to\Audit-Azure\scripts\update_benchmarks.bat" /sc monthly
```

**Linux Cron:**
```bash
# Add to crontab (monthly on 1st at 2 AM)
0 2 1 * * cd /path/to/Audit-Azure && ./venv/bin/python -m scripts.update_benchmarks
```

### Manual Framework Checks

The platform tracks these frameworks:
- **Azure Security Benchmark v3.0** (auto-update supported)
- **CIS Azure Foundations** (manual check required)
- **NIST SP 800-53 Rev. 5** (manual check required)
- **PCI-DSS v4.0** (manual check required)
- **ISO 27001:2013** (manual check required)

Visit framework URLs quarterly to check for updates:
```bash
python -m scripts.update_benchmarks --show-framework-info
```
- **evaluators/** - Pluggable evaluation modules (identity, networking, data, etc.)
- **controls/** - Control catalog definitions
- **tests/** - Pytest test suite
- **docs/** - Comprehensive documentation
- **scripts/** - Utility scripts

## Quick Start

### Backend (API)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/Audit-Azure.git
   cd Audit-Azure
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or install in development mode:
   ```bash
   pip install -e .
   ```

3. **Run the API:**
   ```bash
   cd api
   uvicorn main:app --reload
   ```
   The API will be available at `http://localhost:8000`

4. **View API documentation:**
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

### Frontend (UI)

1. **Navigate to the UI directory:**
   ```bash
   cd ui
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```
   The UI will open at `http://localhost:3000`

### Running Tests

```bash
cd tests
pytest -v
```

## Using the Platform

1. **Start the backend API** (see Backend Quick Start above)
2. **Start the frontend UI** (see Frontend Quick Start above)
3. **Navigate to** `http://localhost:3000` in your browser
4. **Use the UI to:**
   - View the dashboard with audit statistics
   - Browse and create evidence items
   - View findings and filter by severity
   - Browse the control catalog
   - Run evaluations on specific controls

## API Endpoints

- `GET /evidence` - List all evidence
- `POST /evidence` - Create new evidence
- `GET /findings` - List all findings
- `GET /controls` - List all controls
- `POST /evaluate` - Run evaluation for a control

See `docs/API_REFERENCE.md` for complete API documentation.

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **DESIGN.md** - System architecture and design
- **API_REFERENCE.md** - Complete API documentation
- **SETUP.md** - Detailed setup and configuration
- **EVALUATOR_GUIDE.md** - Guide for writing custom evaluators
- **CONTROL_CATALOG.md** - Control definitions and mappings
- **TEST_STRATEGY.md** - Testing approach and guidelines
- **CHANGELOG.md** - Version history

## Project Structure

```
Audit-Azure/
├── api/              # FastAPI application
├── ui/               # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── api.js       # API client
│   │   └── App.js       # Main app
│   └── public/
├── persistence/      # Database models
├── evaluators/       # Evaluation logic
│   ├── identity.py
│   ├── networking.py
│   └── data/
├── controls/         # Control definitions
├── tests/            # Test suite
├── docs/             # Documentation
└── scripts/          # Utility scripts
```

## Development

### Adding a New Evaluator

1. Create a new module in `evaluators/`
2. Define evaluation functions that return findings
3. Register the control-to-function mapping in `evaluators/registry.py`
4. Add tests in `tests/`

See `docs/EVALUATOR_GUIDE.md` for detailed instructions.

### Database Configuration

By default, the project uses SQLite for development and testing. For production:

1. Set up a PostgreSQL database
2. Configure the connection string in `persistence/db.py`
3. Run migrations if needed

## Contributing

Pull requests are welcome! Please:

1. Follow the existing code structure
2. Add tests for new features
3. Update documentation as needed
4. Ensure all tests pass before submitting

## License

MIT License - see LICENSE file for details

## Contact

**Adrian Johnson**  
📧 adrian207@gmail.com

---

Built with ❤️ for Azure security and compliance
