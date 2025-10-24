# Azure Audit Platform - Quick Start Guide

## 🚀 Get Started in 5 Minutes

This guide will help you get the Azure Audit Platform up and running quickly with all enterprise features.

## Prerequisites

- **Python 3.8+** installed
- **Azure CLI** configured with appropriate permissions
- **Git** for cloning the repository

## Step 1: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/Audit-Azure.git
cd Audit-Azure

# Install Python dependencies
pip install -r api/requirements.txt

# Install UI dependencies
cd ui
npm install
cd ..
```

## Step 2: Configure Azure Credentials

### Option A: Azure CLI (Recommended for Development)
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "Your Subscription ID"

# Verify access
az account show
```

### Option B: Service Principal (Recommended for Production)
```bash
# Set environment variables
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

## Step 3: Start the Application

### Start the API Server
```bash
# Start FastAPI server
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Start the UI (Optional)
```bash
# In a new terminal
cd ui
npm start
```

## Step 4: Verify Installation

### Check API Health
```bash
curl http://localhost:8000/health
```

### Check Azure Connectivity
```bash
curl http://localhost:8000/preflight
```

### Access API Documentation
Open your browser and go to: http://localhost:8000/docs

## Step 5: Create Your First User

```bash
# Register an admin user
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@yourcompany.com",
    "password": "SecurePassword123!",
    "role": "admin"
  }'
```

## Step 6: Login and Get Token

```bash
# Login
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

Save the `access_token` from the response for API calls.

## Step 7: Run Your First Audit

```bash
# Run a security audit
curl -X POST "http://localhost:8000/run-evaluation" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"control_id": "IM-2"}'
```

## Step 8: Explore Enterprise Features

### 1. Automated Remediation
```bash
# Get remediation preview
curl -X POST "http://localhost:8000/remediation/preview" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"findingId": "finding-id-here"}'
```

### 2. Scheduled Audits
```bash
# Create a daily schedule
curl -X POST "http://localhost:8000/schedules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "name": "Daily Security Check",
    "description": "Daily audit of critical controls",
    "frequency": "daily",
    "controls": ["IM-2", "IM-3", "NS-1", "DP-1"],
    "enabled": true
  }'
```

### 3. Compliance Reporting
```bash
# Generate ASB compliance report
curl -X POST "http://localhost:8000/reports/generate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "framework": "asb",
    "format": "json",
    "scope": {"time_range": {"start_date": "2024-01-01", "end_date": "2024-12-31"}}
  }'
```

### 4. Executive Dashboard
```bash
# Get executive summary
curl "http://localhost:8000/executive/summary?days=30" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 5. Custom Controls
```bash
# Get control templates
curl "http://localhost:8000/custom-controls/templates" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 6. Trend Analysis
```bash
# Get compliance trend
curl "http://localhost:8000/analytics/compliance-trend?days=90" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 7. Audit Logs
```bash
# Get audit logs
curl "http://localhost:8000/audit/logs?limit=50" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## 🎯 Next Steps

### 1. Configure Production Environment
- Set up PostgreSQL database
- Configure environment variables
- Set up SSL/TLS certificates
- Configure Azure service principal

### 2. Set Up Monitoring
- Configure Azure Monitor integration
- Set up alerting rules
- Configure log analytics

### 3. Customize Controls
- Review existing controls
- Create custom controls for your environment
- Configure compliance frameworks

### 4. Set Up Automation
- Configure scheduled audits
- Set up automated remediation
- Configure notification webhooks

## 🔧 Configuration Options

### Environment Variables
```bash
# Database
export AZ_AUDIT_DB="postgresql://user:pass@localhost/audit_db"

# Azure Configuration
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

# Security
export JWT_SECRET_KEY="your-secret-key-change-in-production"
export JWT_ALGORITHM="HS256"
export ACCESS_TOKEN_EXPIRE_MINUTES=30

# Features
export ENABLE_SCHEDULER=true
export ENABLE_REMEDIATION=true
export ENABLE_ANALYTICS=true
```

### Database Configuration
```bash
# For production, use PostgreSQL
pip install psycopg2-binary

# Set database URL
export AZ_AUDIT_DB="postgresql://user:password@localhost:5432/audit_platform"
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Azure Authentication Errors
```bash
# Check Azure CLI login
az account show

# Verify subscription access
az account list --output table
```

#### 2. Database Connection Issues
```bash
# Check database URL
echo $AZ_AUDIT_DB

# Test database connection
python -c "from persistence.db import init_db; init_db()"
```

#### 3. API Errors
```bash
# Check API logs
tail -f api.log

# Test API health
curl http://localhost:8000/health
```

#### 4. Permission Errors
```bash
# Check user permissions
curl "http://localhost:8000/auth/permissions" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Getting Help

1. **Check the logs**: Look for error messages in the console output
2. **Verify configuration**: Ensure all environment variables are set correctly
3. **Test connectivity**: Use the `/preflight` endpoint to verify Azure access
4. **Review documentation**: Check the full API documentation at `/docs`

## 📚 Additional Resources

- **Full API Documentation**: http://localhost:8000/docs
- **Enterprise Features Guide**: [docs/ENTERPRISE_FEATURES.md](docs/ENTERPRISE_FEATURES.md)
- **Complete API Reference**: [docs/API_REFERENCE_COMPLETE.md](docs/API_REFERENCE_COMPLETE.md)
- **Design Documentation**: [docs/DESIGN.md](docs/DESIGN.md)

## 🎉 You're Ready!

Your Azure Audit Platform is now running with all enterprise features enabled. You can:

- ✅ **Audit Azure resources** for security compliance
- ✅ **Automate remediation** of common issues
- ✅ **Schedule regular audits** for continuous monitoring
- ✅ **Generate compliance reports** for multiple frameworks
- ✅ **Track trends and risks** with advanced analytics
- ✅ **Manage users and permissions** with RBAC
- ✅ **Create custom controls** for your specific needs
- ✅ **Monitor all activities** with comprehensive audit trails

## 🚀 Production Deployment

For production deployment, see the [Production Deployment Guide](docs/PRODUCTION_DEPLOYMENT.md) for detailed instructions on:

- Docker containerization
- Azure App Service deployment
- Database setup and migration
- Security hardening
- Monitoring and alerting
- Backup and disaster recovery

---

**Need help?** Check the troubleshooting section above or refer to the comprehensive documentation in the `docs/` folder.
