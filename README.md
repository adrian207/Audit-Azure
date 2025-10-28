<div align="center">

# 🛡️ Audit-Azure

### Enterprise-Grade Azure Security Compliance Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com/)
[![Azure](https://img.shields.io/badge/Azure-Security%20Benchmark-0078D4.svg)](https://azure.microsoft.com/)
[![Release](https://img.shields.io/badge/Release-v1.0.0-green.svg)](https://github.com/adrian207/Audit-Azure/releases)

**[Features](#-features)** • 
**[Quick Start](#-quick-start)** • 
**[Documentation](#-documentation)** • 
**[Architecture](#-architecture)** • 
**[Contributing](#-contributing)**

</div>

---

## 📖 About

**Audit-Azure** is a comprehensive, modular platform designed to audit Azure cloud environments for security compliance, operational best practices, and regulatory adherence. Built on FastAPI and powered by Azure SDK, it provides automated security assessments aligned with the **Azure Security Benchmark** and **CIS Azure Foundations Benchmark**.

**Author:** Adrian Johnson <adrian207@gmail.com>

### 🎯 Why Audit-Azure?

- **Comprehensive Coverage**: 74+ security controls across all Azure Security Benchmark domains
- **Real-Time Auditing**: Live evaluation of your Azure environment with instant findings
- **Evidence-Based**: All findings backed by collected evidence and remediation guidance
- **Extensible Architecture**: Plugin-based evaluator system for custom security checks
- **Production Ready**: Enterprise-grade API with database persistence and web UI
- **Open Source**: MIT licensed, community-driven development

---

## ✨ Features

### 🔍 Security Assessment
- **Multi-Domain Coverage**: Identity, Network Security, Data Protection, Logging & Monitoring, Vulnerability Management
- **Azure Security Benchmark**: Full implementation of Microsoft's security baseline (v3.0)
- **CIS Benchmarks**: Compliance checking against CIS Azure Foundations
- **Secure Score Integration**: Direct integration with Microsoft Defender for Cloud

### 🎨 User Experience
- **Modern Web UI**: React-based dashboard for visualization and reporting
- **REST API**: Full-featured FastAPI backend with OpenAPI documentation
- **Real-Time Updates**: Live evaluation results and finding aggregation
- **Export Capabilities**: JSON, CSV, and PDF report generation

### 🏗️ Architecture
- **Pluggable Evaluators**: Python-based modular security checks
- **Evidence Collection**: Automated Azure resource data gathering via Resource Graph
- **Database Persistence**: SQLAlchemy ORM with SQLite/PostgreSQL support
- **Control Catalog**: YAML-based control definitions and mappings
- **Remediation Scripts**: PowerShell and Azure CLI automated fixes

### 🔐 Security Domains

| Domain | Controls | Description |
|--------|----------|-------------|
| **Identity & Access Management (IM)** | 12 | MFA, privileged access, service principals |
| **Network Security (NS)** | 11 | NSG rules, network segmentation, DDoS protection |
| **Data Protection (DP)** | 8 | Encryption, key management, data classification |
| **Logging & Monitoring (LM)** | 9 | Audit logs, security monitoring, alerting |
| **Asset Management (AM)** | 7 | Inventory, tagging, approved services |
| **Posture & Vulnerability Management (PV)** | 8 | Secure Score, vulnerability scanning, patching |
| **Azure Policy (AP)** | 10 | Policy compliance, governance, initiatives |
| **Endpoint Security (ES)** | 5 | EDR, antimalware, device compliance |
| **Backup & Recovery (BR)** | 4 | Backup policies, disaster recovery |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** ([Download](https://www.python.org/downloads/))
- **Node.js 18+** ([Download](https://nodejs.org/))
- **Azure Subscription** ([Free Trial](https://azure.microsoft.com/free/))
- **Azure CLI** (recommended) ([Install Guide](https://aka.ms/installazurecli))

### Installation

#### Windows
```batch
# Clone the repository
git clone https://github.com/adrian207/Audit-Azure.git
cd Audit-Azure

# Run automated installer
.\install.bat

# Start the platform
.\run_all.bat
```

#### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/adrian207/Audit-Azure.git
cd Audit-Azure

# Make scripts executable and install
chmod +x install.sh run_all.sh
sudo ./install.sh

# Start the platform
./run_all.sh
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Access the platform
# API: http://localhost:8000
# UI:  http://localhost:3000
```

### Azure Authentication

**Option 1: Azure CLI (Recommended for Development)**
```bash
az login
az account set --subscription "Your-Subscription-Name"
```

**Option 2: Service Principal (Recommended for Production)**
```bash
# Create a service principal
az ad sp create-for-rbac --name "AuditAzureSP" --role "Reader" --scopes /subscriptions/{subscription-id}

# Set environment variables
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### First Audit

1. **Open Web UI**: Navigate to http://localhost:3000
2. **Run Evaluation**: Select a control (e.g., "IM-2: Require MFA") and click "Run Evaluation"
3. **View Findings**: Review security findings with severity, affected resources, and remediation steps
4. **Export Report**: Download findings as JSON/CSV/PDF

---

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| **[Getting Started](docs/GETTING_STARTED.md)** | Step-by-step setup and first audit guide |
| **[API Reference](docs/API_REFERENCE.md)** | Complete REST API documentation |
| **[Design Document](docs/DESIGN.md)** | Architecture and technical design |
| **[Setup Guide](docs/SETUP.md)** | Detailed installation and configuration |
| **[Evaluator Guide](docs/EVALUATOR_GUIDE.md)** | Creating custom security evaluators |
| **[Control Catalog](docs/CONTROL_CATALOG.md)** | Available security controls reference |
| **[User Guide](docs/USER_GUIDE.md)** | Platform usage and workflows |
| **[Test Strategy](docs/TEST_STRATEGY.md)** | Testing approach and coverage |
| **[Changelog](docs/CHANGELOG.md)** | Release notes and version history |

### API Documentation

Interactive API documentation is available when running the platform:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Web UI (React)                       │
│                     http://localhost:3000                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST API
┌──────────────────────────▼──────────────────────────────────┐
│                   FastAPI Backend                            │
│                  http://localhost:8000                       │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐   │
│  │ Evidence   │  │ Evaluation │  │ Findings & Controls │   │
│  │ Collection │  │   Engine   │  │    Management       │   │
│  └────────────┘  └────────────┘  └─────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐
│  Evaluators  │  │   Azure SDK     │  │  Database  │
│   (Python)   │  │   Integration   │  │ (SQLite/   │
│              │  │                 │  │ Postgres)  │
│ • Identity   │  │ • Resource      │  │            │
│ • Network    │  │   Graph API     │  │ • Evidence │
│ • Data Prot. │  │ • Management    │  │ • Findings │
│ • Logging    │  │   APIs          │  │ • Controls │
│ • VM/Compute │  │ • Defender      │  │            │
└──────────────┘  └─────────────────┘  └────────────┘
```

### Key Components

1. **API Layer** (`api/`): FastAPI REST endpoints for evidence, findings, controls, and evaluation
2. **Evaluators** (`evaluators/`): Pluggable Python modules for domain-specific security checks
3. **Azure SDK** (`azure_sdk/`): Azure service client wrappers and authentication
4. **Persistence** (`persistence/`): SQLAlchemy models and database management
5. **Controls** (`controls/`): YAML-based control catalog and ASB mappings
6. **UI** (`ui/`): React-based web interface for visualization
7. **Scripts** (`scripts/`): PowerShell remediation and data collection utilities

---

## 🛠️ Development

### Project Structure

```
Audit-Azure/
├── api/                    # FastAPI application
│   ├── main.py            # API entry point
│   ├── security.py        # Authentication & authorization
│   └── schemas/           # Pydantic models
├── evaluators/            # Security check modules
│   ├── identity.py        # Identity & access management
│   ├── network_security.py # Network security controls
│   ├── data_protection.py  # Data protection checks
│   └── ...
├── azure_sdk/             # Azure API integrations
│   ├── auth.py            # Azure authentication
│   ├── resource_graph.py  # Resource Graph queries
│   └── ...
├── persistence/           # Database layer
│   ├── models.py          # SQLAlchemy models
│   └── db.py              # Database configuration
├── controls/              # Control definitions
│   ├── asb_controls.py    # Azure Security Benchmark
│   └── starter_catalog.yaml
├── ui/                    # React web interface
├── scripts/               # Automation scripts
├── tests/                 # Test suite
└── docs/                  # Documentation
```

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_evaluators.py
```

### Local Development

```bash
# Backend only
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend only
cd ui
npm start

# Database migrations
alembic upgrade head
```

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute

- 🐛 **Report Bugs**: Open an issue with detailed reproduction steps
- 💡 **Suggest Features**: Share your ideas for new capabilities
- 📝 **Improve Documentation**: Help make docs clearer and more comprehensive
- 🔧 **Submit Pull Requests**: Fix bugs or implement new features
- 🎨 **Enhance UI/UX**: Improve the web interface design

### Contribution Guidelines

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards
   - Use Black for Python code formatting
   - Follow PEP 8 guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   pytest
   black . --check
   flake8 .
   ```

4. **Commit with clear messages** following Minto Pyramid Principle
   ```bash
   git commit -m "Add: Brief description of feature
   
   Detailed explanation of changes and motivation."
   ```

5. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Audit-Azure.git
cd Audit-Azure

# Install in development mode
pip install -e ".[dev]"
cd ui && npm install

# Run in development mode
./run_all.sh  # or run_all.bat on Windows
```

### Adding New Evaluators

See [EVALUATOR_GUIDE.md](docs/EVALUATOR_GUIDE.md) for detailed instructions on creating custom security evaluators.

---

## 📊 Roadmap

### Version 1.1 (Q1 2026)
- [ ] Multi-tenant support
- [ ] RBAC and authentication
- [ ] Advanced filtering and search
- [ ] Scheduled audits and automation
- [ ] Email notifications for critical findings

### Version 1.2 (Q2 2026)
- [ ] Azure Government Cloud support
- [ ] Compliance frameworks (HIPAA, PCI-DSS, SOC 2)
- [ ] Custom control definitions via UI
- [ ] Integration with SIEM platforms
- [ ] API rate limiting and caching improvements

### Version 2.0 (Q3 2026)
- [ ] Machine learning for anomaly detection
- [ ] Predictive security scoring
- [ ] AWS and GCP support
- [ ] Enterprise features (SSO, advanced reporting)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Adrian Johnson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

- **Microsoft Azure** - For comprehensive SDK and documentation
- **FastAPI** - Modern, high-performance web framework
- **Azure Security Benchmark** - Security baseline and control framework
- **CIS Benchmarks** - Independent security configuration standards
- **Open Source Community** - For invaluable tools and contributions

---

## 📞 Support & Contact

### Getting Help

- **📖 Documentation**: Check the [docs/](docs/) directory for comprehensive guides
- **🐛 Issues**: [GitHub Issues](https://github.com/adrian207/Audit-Azure/issues) for bug reports and feature requests
- **💬 Discussions**: [GitHub Discussions](https://github.com/adrian207/Audit-Azure/discussions) for questions and community support
- **📧 Email**: adrian207@gmail.com for direct inquiries

### Reporting Security Vulnerabilities

[Inference] If you discover a security vulnerability, please email adrian207@gmail.com directly rather than opening a public issue. We take security seriously and will respond promptly.

---

## 📈 Project Status

![GitHub stars](https://img.shields.io/github/stars/adrian207/Audit-Azure?style=social)
![GitHub forks](https://img.shields.io/github/forks/adrian207/Audit-Azure?style=social)
![GitHub issues](https://img.shields.io/github/issues/adrian207/Audit-Azure)
![GitHub pull requests](https://img.shields.io/github/issues-pr/adrian207/Audit-Azure)

**Active Development** - This project is actively maintained and accepting contributions.

---

<div align="center">

### ⭐ If you find this project useful, please consider giving it a star! ⭐

**Made with ❤️ by [Adrian Johnson](mailto:adrian207@gmail.com)**

[Report Bug](https://github.com/adrian207/Audit-Azure/issues) • 
[Request Feature](https://github.com/adrian207/Audit-Azure/issues) • 
[View Documentation](docs/) • 
[Contributing](CONTRIBUTING.md)

</div>
