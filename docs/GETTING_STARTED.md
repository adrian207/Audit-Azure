# Getting Started with Azure Audit Platform

Welcome! This guide will help you set up and run your first Azure security audit in under 30 minutes.

## 📋 Prerequisites

Before you begin, ensure you have:

- ✅ **Python 3.8 or higher** - [Download here](https://www.python.org/downloads/)
- ✅ **Node.js 18 or higher** - [Download here](https://nodejs.org/)
- ✅ **Azure Subscription** - [Get free trial](https://azure.microsoft.com/free/)
- ✅ **Azure CLI** (recommended) - [Install guide](https://aka.ms/installazurecli)
- ✅ **Administrator/sudo access** - For installation

**System Requirements:**
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB for installation
- **Internet**: Required for Azure API access

## 🚀 5-Minute Quick Start

### Step 1: Install (10-15 minutes)

**Windows:**
```batch
# Open PowerShell as Administrator
cd C:\path\to\Audit-Azure
.\install.bat
```

**Linux/Mac:**
```bash
cd /path/to/Audit-Azure
chmod +x install.sh
sudo ./install.sh
```

☕ **Grab a coffee!** The installer will:
- Download ~500MB of Python packages
- Install ~200MB of Node.js dependencies
- Set up your environment configuration

### Step 2: Configure Azure Access (5 minutes)

**Easiest Method - Azure CLI:**
```bash
az login
az account show  # Verify you're logged into the right subscription
```

**Alternative - Edit `.env` file:**
```bash
# Open .env file in your favorite editor
notepad .env  # Windows
nano .env     # Linux/Mac

# Update these values:
AZURE_TENANT_ID=your-tenant-id
AZURE_SUBSCRIPTION_ID=your-subscription-id
```

💡 **Tip:** You can find your tenant and subscription IDs in the [Azure Portal](https://portal.azure.com) under "Azure Active Directory" and "Subscriptions"

### Step 3: Start the Platform (30 seconds)

**Windows:**
```batch
run_all.bat
```

**Linux/Mac:**
```bash
chmod +x run_all.sh
./run_all.sh
```

This opens TWO windows:
- 🔧 **API Server** - Running on http://localhost:8000
- 🎨 **Web UI** - Opening automatically at http://localhost:3000

### Step 4: Run Your First Audit (2-5 minutes)

1. **Open your browser** to http://localhost:3000
2. **Click "Evaluation"** in the navigation menu
3. **Select a control** from the dropdown (try "IM-2: Require MFA")
4. **Click "Run Evaluation"**
5. **View results!** See findings, affected resources, and remediation steps

## 📊 Understanding Your Results

### Dashboard Overview

The dashboard shows:
- **Evidence Count**: Azure resources collected for analysis
- **Findings Count**: Security issues discovered
- **Controls Count**: Total security controls available (74+)
- **Recent Findings**: Latest security issues with severity

### Severity Levels

- 🔴 **Critical**: Immediate action required (e.g., no MFA, public storage)
- 🟠 **High**: Important security gaps (e.g., missing encryption)
- 🟡 **Medium**: Security improvements needed (e.g., policy gaps)
- 🔵 **Low**: Best practice recommendations
- ⚪ **Informational**: Awareness items

### Secure Score

Your **Secure Score** (0-100%) shows overall security posture:
- **90-100%**: Excellent - Well-secured environment
- **70-89%**: Good - Minor improvements needed
- **50-69%**: Fair - Multiple security gaps
- **Below 50%**: Poor - Significant security risks

## 🎯 Common Tasks

### Check Multiple Subscriptions

Edit `.env` to add multiple subscriptions:
```bash
AZURE_SUBSCRIPTION_IDS=sub-id-1,sub-id-2,sub-id-3
```

### Run Full Audit

1. Go to **Evaluation** page
2. Select "Run All Controls"
3. Wait 5-45 minutes (depends on environment size)
4. View comprehensive report

### Export Results

1. Navigate to **Findings** page
2. Click "Export" button
3. Choose format (PDF/Excel/JSON)
4. Download report

### Update Security Baselines

Run monthly to get latest Microsoft guidelines:

**Windows:**
```batch
check_updates.bat
```

**Linux/Mac:**
```bash
./check_updates.sh
```

## 🔧 Troubleshooting

### "Import errors" when starting API

**Cause:** Dependencies not installed

**Fix:**
```bash
cd api
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### "Authentication failed" errors

**Cause:** Azure credentials not configured

**Fix:** Ensure you've run `az login` OR updated `.env` with service principal credentials

### "Rate limit exceeded"

**Cause:** Too many API requests to Azure

**Fix:** Wait 60 seconds or increase `RATE_LIMIT_WINDOW` in `.env`

### API/UI won't start

**Cause:** Port already in use

**Fix:** Change ports in `.env`:
```bash
API_PORT=8001  # Change from 8000
```
And in `ui/package.json`:
```json
"proxy": "http://localhost:8001"
```

## 📚 Next Steps

Now that you're up and running:

1. **Read the [API Reference](./API_REFERENCE.md)** - Learn about all evaluators
2. **Review [Design Document](./DESIGN.md)** - Understand the architecture
3. **Check [Security Guide](./SECURITY.md)** - Production deployment tips
4. **Explore Controls** - Browse all 74+ Azure Security Benchmark controls

## 💡 Tips for Success

### Performance
- **Enable caching** (default ON) for faster repeated queries
- **Run during off-peak hours** for better Azure API response times
- **Start small** - Test with one control before running full audits

### Security
- **Use Service Principal** in production (not Azure CLI)
- **Store secrets in Azure Key Vault** for production deployments
- **Enable audit logging** (default ON) for compliance

### Best Practices
- **Run monthly audits** to track security posture over time
- **Check for benchmark updates** quarterly
- **Review Critical/High findings first** - Maximum impact
- **Use auto-remediation scripts** (PowerShell/CLI/Bicep) to fix issues faster

## 🆘 Getting Help

- **Documentation**: Check `docs/` folder for detailed guides
- **API Docs**: Visit http://localhost:8000/docs when running
- **GitHub Issues**: [Report bugs](https://github.com/adrian207/Audit-Azure/issues)
- **Email**: adrian207@gmail.com

## 🎉 You're Ready!

You now have a powerful Azure security audit platform running locally. Start exploring your Azure environment's security posture!

**Recommended First Audits:**
1. Identity & Access Management (IM controls)
2. Data Protection (DP controls)  
3. Network Security (NS controls)
4. Run full Secure Score calculation

Happy auditing! 🔍🛡️
