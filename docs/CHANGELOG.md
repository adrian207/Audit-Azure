# Audit-Azure Changelog

**Author:** Adrian Johnson <adrian207@gmail.com>

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2025-10-28

### 🎉 Initial Public Release

This is the first official release of Audit-Azure, a comprehensive Azure security compliance platform.

### ✨ Added

#### Core Platform
- **FastAPI REST API** with OpenAPI/Swagger documentation
- **SQLAlchemy ORM** with support for SQLite and PostgreSQL databases
- **React-based Web UI** for visualization and reporting
- **Docker support** with Docker Compose configuration
- **Cross-platform scripts** for Windows (batch) and Linux/macOS (bash)

#### Security Evaluators
- **Identity & Access Management (IM)** - 12 controls
  - MFA enforcement checks
  - Privileged identity management
  - Service principal security
  - Guest user access policies
  - Password policies and security defaults
  
- **Network Security (NS)** - 11 controls
  - Network Security Group (NSG) rule analysis
  - Network segmentation validation
  - DDoS protection verification
  - Azure Firewall configuration
  - Private endpoint usage
  
- **Data Protection (DP)** - 8 controls
  - Storage account encryption
  - Key vault integration
  - Data classification
  - Backup policies
  - Disk encryption
  
- **Logging & Monitoring (LM)** - 9 controls
  - Diagnostic settings validation
  - Log Analytics workspace configuration
  - Security alerting
  - Audit log retention
  - Activity log integration
  
- **Asset Management (AM)** - 7 controls
  - Resource tagging compliance
  - Inventory management
  - Approved services validation
  
- **Posture & Vulnerability Management (PV)** - 8 controls
  - Microsoft Defender for Cloud integration
  - Secure Score calculation
  - Vulnerability assessment
  - Patch management compliance
  
- **Azure Policy (AP)** - 10 controls
  - Policy compliance checking
  - Initiative assignments
  - Governance validation
  
- **Endpoint Security (ES)** - 5 controls
  - EDR integration
  - Antimalware configuration
  
- **Backup & Recovery (BR)** - 4 controls
  - Backup policy validation
  - Disaster recovery configuration

#### Azure SDK Integration
- **Resource Graph API** for efficient resource querying
- **Microsoft Defender for Cloud** integration
- **Azure Monitor** client for logging and diagnostics
- **Entra ID (Azure AD)** client for identity checks
- **Policy Insights** client for compliance data
- **Multi-subscription support** with tenant-wide queries

#### Control Catalog
- **Azure Security Benchmark v3.0** complete implementation
- **CIS Azure Foundations Benchmark** partial coverage
- **YAML-based control definitions** for easy extension
- **74+ security controls** across all domains
- **Severity mapping** and risk scoring

#### API Endpoints
- `POST /evidence` - Submit evidence for evaluation
- `POST /evaluate` - Run evaluators on collected evidence
- `GET /findings` - Retrieve security findings
- `GET /findings/{id}` - Get specific finding details
- `POST /findings` - Create custom findings
- `GET /controls` - List available security controls
- `GET /controls/{id}` - Get control details
- `GET /secure-score` - Calculate overall security score
- `GET /health` - API health check

#### Authentication & Security
- **Azure CLI authentication** support
- **Service Principal** authentication
- **Managed Identity** support for Azure-hosted deployments
- **Environment-based configuration** via .env files
- **Secure credential handling** with azure-identity

#### Documentation
- **Getting Started Guide** - Quick setup in under 30 minutes
- **API Reference** - Complete endpoint documentation
- **Design Document** - Architecture and technical details
- **Evaluator Guide** - Creating custom security checks
- **Control Catalog** - Reference for all security controls
- **User Guide** - Platform usage and workflows
- **Test Strategy** - Testing approach and coverage
- **Setup Guide** - Detailed installation instructions

#### Testing
- **Pytest-based test suite** with 85%+ code coverage
- **Unit tests** for all evaluators
- **Integration tests** for API endpoints
- **Test fixtures** for Azure resource mocking
- **Automated test execution** in CI/CD

#### Automation Scripts
- **PowerShell remediation scripts** for common findings
  - MFA enforcement remediation
  - NSG rule fixes
  - Storage account security hardening
- **Data collection scripts** for evidence gathering
  - MFA status collection
  - NSG configuration collection
  - Storage account inventory
- **Benchmark update scripts** for keeping controls current

#### Developer Experience
- **Black code formatting** configuration
- **Flake8 linting** rules
- **MyPy type checking** setup
- **Pre-commit hooks** for code quality
- **VS Code workspace** configuration
- **Pyright configuration** for enhanced IDE support

#### Deployment Options
- **Local development** with hot reload
- **Docker containerization** for consistent environments
- **Docker Compose** for multi-service orchestration
- **Database migrations** with Alembic
- **Production-ready** configuration examples

### 🔄 Changed
- N/A (Initial release)

### 🐛 Fixed
- N/A (Initial release)

### 🗑️ Deprecated
- N/A (Initial release)

### 🚨 Security
- All dependencies pinned to specific versions
- Security scanning implemented for npm and Python packages
- Audit logs stored for all evaluation activities
- Input validation on all API endpoints

---

## [0.1.0] - 2025-10-20

### 🔧 Internal Development Release

- Initial project structure
- Basic FastAPI API endpoints for evidence, findings, evaluation
- SQLAlchemy models and SQLite support
- Pluggable evaluator system proof-of-concept
- Example evaluators for Identity, Networking, Data
- Basic pytest test suite
- Initial documentation framework

---

## Release Notes - Version 1.0.0

### Highlights

This release marks the first production-ready version of Audit-Azure. The platform now includes:

- **Complete Azure Security Benchmark v3.0 implementation** with 74+ security controls
- **Professional web interface** for easy security assessments
- **Comprehensive documentation** for users and developers
- **Docker deployment** for consistent environments
- **Multi-subscription support** for enterprise scenarios
- **Extensible architecture** for custom security checks

### Getting Started

```bash
# Quick installation
git clone https://github.com/adrian207/Audit-Azure.git
cd Audit-Azure
./install.sh  # or install.bat on Windows

# Start the platform
./run_all.sh  # or run_all.bat on Windows

# Access the UI at http://localhost:3000
```

### Upgrade Notes

This is the first public release. No upgrade path is provided.

### Breaking Changes

N/A (Initial release)

### Known Issues

1. **Performance**: Full environment audits with 1000+ resources may take 5-10 minutes
   - **Workaround**: Run individual domain evaluations first
   
2. **Azure Government Cloud**: Not yet supported
   - **Planned**: Version 1.2 (Q2 2026)
   
3. **Export formats**: Only JSON currently supported
   - **Planned**: PDF and Excel exports in v1.1

### Acknowledgments

Special thanks to:
- Microsoft Azure team for comprehensive SDK documentation
- The FastAPI community for an excellent framework
- Early testers who provided valuable feedback

---

## Versioning Strategy

- **Major version** (X.0.0): Breaking changes, major new features
- **Minor version** (1.X.0): New features, no breaking changes
- **Patch version** (1.0.X): Bug fixes, security updates

## Support

For questions about releases:
- **GitHub Releases**: https://github.com/adrian207/Audit-Azure/releases
- **Issues**: https://github.com/adrian207/Audit-Azure/issues
- **Email**: adrian207@gmail.com

---

**Maintained by Adrian Johnson <adrian207@gmail.com>**
