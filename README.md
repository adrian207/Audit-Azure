# Azure Audit Platform

**Author:** Adrian Johnson <adrian207@gmail.com>

Azure Audit Platform is a comprehensive, enterprise-grade security auditing and compliance management solution for Azure environments. Built with FastAPI, React, and modern cloud-native technologies, it provides automated security assessments, compliance reporting, and remediation capabilities.

## 🚀 Enterprise Features

### 8 Major Enterprise Systems
1. **🔧 Automated Remediation System** - Automatically fix common security issues
2. **⏰ Scheduled Audit Functionality** - Automated security assessments on schedule
3. **📊 Compliance Reporting System** - Multi-framework compliance reports (ASB, CIS, NIST, SOC2, ISO27001, PCI-DSS)
4. **🔐 User Authentication & RBAC** - Enterprise-grade security with role-based access control
5. **📝 Audit Trail & Logging** - Comprehensive activity tracking and security event logging
6. **📈 Executive Dashboard** - High-level KPIs and risk metrics for management
7. **🛠️ Custom Control Definitions** - Create and manage custom security controls
8. **📊 Trend Analysis & Risk Scoring** - Advanced analytics and predictive insights

### Key Capabilities
- **60+ REST API endpoints** across all enterprise systems
- **74+ security controls** covering Azure Security Benchmark
- **Multi-framework compliance** reporting and scoring
- **Automated remediation** for common security issues
- **Real-time analytics** and trend analysis
- **Role-based permissions** with 10 granular permission types
- **Comprehensive audit trails** with 28 activity types
- **Executive dashboards** with KPIs and risk metrics

## 🏗️ Architecture

- **Backend**: FastAPI with SQLAlchemy ORM
- **Frontend**: React.js with modern UI components
- **Database**: SQLite (dev) / PostgreSQL (production)
- **Authentication**: JWT with PBKDF2 password hashing
- **Azure Integration**: Azure SDK for Python with Resource Graph
- **Testing**: Pytest with comprehensive test coverage
- **Documentation**: Professional documentation with API references

## ⚡ Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/your-org/Audit-Azure.git
cd Audit-Azure
pip install -r api/requirements.txt
cd ui && npm install && cd ..
```

### 2. Configure Azure Credentials
```bash
# Option A: Azure CLI (Development)
az login
az account set --subscription "Your Subscription ID"

# Option B: Service Principal (Production)
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

### 3. Start the Application
```bash
# Start API server
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Start UI (optional)
cd ui && npm start
```

### 4. Access the Platform
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **UI Application**: http://localhost:3000

### 5. Create Your First User
```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@yourcompany.com", 
    "password": "SecurePassword123!",
    "role": "admin"
  }'
```

## 📚 Documentation

### Quick Start Guides
- **[Quick Start Guide](docs/QUICK_START.md)** - Get up and running in 5 minutes
- **[Enterprise Features Guide](docs/ENTERPRISE_FEATURES.md)** - Complete feature documentation
- **[Complete API Reference](docs/API_REFERENCE_COMPLETE.md)** - All 60+ endpoints documented

### Technical Documentation
- **[Design Documentation](docs/DESIGN.md)** - Architecture and design decisions
- **[API Reference](docs/API_REFERENCE.md)** - Core API documentation
- **[Setup Guide](docs/SETUP.md)** - Detailed setup instructions
- **[Evaluator Guide](docs/EVALUATOR_GUIDE.md)** - Creating custom evaluators
- **[Control Catalog](docs/CONTROL_CATALOG.md)** - Security control definitions
- **[Test Strategy](docs/TEST_STRATEGY.md)** - Testing approach and coverage

## 🔧 API Endpoints Overview

### Core Systems (60+ Endpoints)
- **Evidence & Findings** (6 endpoints) - Evidence collection and finding management
- **Controls** (9 endpoints) - Security control management and custom controls
- **Remediation** (2 endpoints) - Automated remediation preview and execution
- **Scheduling** (7 endpoints) - Audit scheduling and execution tracking
- **Compliance & Reporting** (5 endpoints) - Multi-framework compliance reporting
- **Executive Dashboard** (6 endpoints) - Management KPIs and risk metrics
- **Authentication** (5 endpoints) - User management and RBAC
- **Audit & Logging** (3 endpoints) - Activity tracking and security events
- **Analytics** (5 endpoints) - Trend analysis and risk scoring

## 🎯 Use Cases

### Security Teams
- **Continuous Security Monitoring** - Automated daily/weekly security assessments
- **Compliance Management** - Generate reports for ASB, CIS, NIST, SOC2, ISO27001, PCI-DSS
- **Risk Management** - Identify and prioritize security risks with dynamic scoring
- **Incident Response** - Quick identification and remediation of security issues

### Compliance Teams
- **Audit Preparation** - Comprehensive compliance reports and evidence collection
- **Framework Mapping** - Map controls across multiple compliance frameworks
- **Trend Analysis** - Track compliance improvements over time
- **Executive Reporting** - High-level dashboards for management reporting

### DevOps Teams
- **Infrastructure Security** - Automated security checks in CI/CD pipelines
- **Policy Enforcement** - Ensure security policies are consistently applied
- **Custom Controls** - Create organization-specific security controls
- **Automated Remediation** - Fix common security issues automatically

## 🚀 Production Ready

### Enterprise Features
- ✅ **Production-grade security** with JWT authentication and RBAC
- ✅ **Scalable architecture** with async FastAPI and SQLAlchemy
- ✅ **Comprehensive audit trails** for compliance and forensics
- ✅ **Automated remediation** reducing manual effort
- ✅ **Multi-framework compliance** reporting
- ✅ **Advanced analytics** with trend analysis and risk scoring
- ✅ **Custom control definitions** for organization-specific needs
- ✅ **Executive dashboards** for management visibility

### Deployment Options
- **Docker containers** for easy deployment
- **Azure App Service** for managed hosting
- **Kubernetes** for container orchestration
- **On-premises** deployment options

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test categories
pytest tests/test_api_flow.py
pytest tests/test_evaluators.py
pytest tests/test_storage.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code style and standards
- Testing requirements
- Documentation standards
- Pull request process

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `docs/` directory for comprehensive guides
- **API Reference**: Visit `/docs` when running the application
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Community**: Join our community discussions

---

**Ready to secure your Azure environment?** Start with our [Quick Start Guide](docs/QUICK_START.md) and have your enterprise-grade security auditing platform running in minutes!
