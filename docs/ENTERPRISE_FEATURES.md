# Azure Audit Platform - Enterprise Features Documentation

## Overview

The Azure Audit Platform now includes **8 major enterprise-grade features** that transform it into a comprehensive security auditing and compliance management solution. This document provides detailed information about each feature, its capabilities, and usage instructions.

## Table of Contents

1. [Automated Remediation System](#1-automated-remediation-system)
2. [Scheduled Audit Functionality](#2-scheduled-audit-functionality)
3. [Compliance Reporting System](#3-compliance-reporting-system)
4. [User Authentication & RBAC](#4-user-authentication--rbac)
5. [Audit Trail & Logging](#5-audit-trail--logging)
6. [Executive Dashboard](#6-executive-dashboard)
7. [Custom Control Definitions](#7-custom-control-definitions)
8. [Trend Analysis & Risk Scoring](#8-trend-analysis--risk-scoring)

---

## 1. Automated Remediation System

### Overview
The Automated Remediation System provides intelligent, automated fixes for common Azure security issues, reducing manual effort and improving response times.

### Features
- **Storage Account HTTPS Enforcement**: Automatically enables HTTPS-only for storage accounts
- **NSG Rule Cleanup**: Removes overly permissive Network Security Group rules
- **MFA Policy Configuration**: Provides guidance for Multi-Factor Authentication setup
- **Dry-Run Mode**: Safe testing environment for remediation actions
- **Blast Radius Analysis**: Impact assessment before execution

### API Endpoints
```
POST /remediation/preview
POST /remediation/execute
```

### Usage Example
```bash
# Preview remediation
curl -X POST "http://localhost:8000/remediation/preview" \
  -H "Content-Type: application/json" \
  -d '{"findingId": "finding-123"}'

# Execute remediation
curl -X POST "http://localhost:8000/remediation/execute" \
  -H "Content-Type: application/json" \
  -d '{"findingId": "finding-123", "approve": true}'
```

### Supported Remediations
1. **Storage Account HTTPS** (`DP-*` controls)
2. **NSG Unrestricted Rules** (`NS-*` controls)
3. **MFA Policy Configuration** (`IM-*` controls)

---

## 2. Scheduled Audit Functionality

### Overview
Automated scheduling system for security audits with flexible frequency options and comprehensive tracking.

### Features
- **Multiple Frequencies**: Daily, weekly, monthly, quarterly, and custom schedules
- **Background Execution**: Non-blocking audit execution
- **Audit History**: Complete tracking of all audit runs
- **Default Schedules**: Pre-configured schedules for common scenarios
- **Custom Controls**: Ability to specify which controls to evaluate

### API Endpoints
```
GET    /schedules
POST   /schedules
GET    /schedules/{id}
PUT    /schedules/{id}
DELETE /schedules/{id}
POST   /schedules/{id}/execute
GET    /audit-history
GET    /audit-status/{id}
```

### Usage Example
```bash
# Create a daily schedule
curl -X POST "http://localhost:8000/schedules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Critical Controls",
    "description": "Daily audit of critical security controls",
    "frequency": "daily",
    "controls": ["IM-2", "IM-3", "NS-1", "NS-2", "DP-1"],
    "enabled": true
  }'

# Execute schedule immediately
curl -X POST "http://localhost:8000/schedules/{schedule_id}/execute"
```

### Default Schedules
1. **Daily Critical Controls**: IM-2, IM-3, NS-1, NS-2, DP-1
2. **Weekly Comprehensive**: All major controls
3. **Monthly Full Audit**: Complete security assessment

---

## 3. Compliance Reporting System

### Overview
Comprehensive compliance reporting for multiple frameworks with export capabilities and executive summaries.

### Features
- **Multiple Frameworks**: ASB, CIS, NIST, SOC2, ISO27001, PCI-DSS
- **Export Formats**: JSON, PDF, Excel, HTML
- **Compliance Scoring**: Automated calculation of compliance percentages
- **Executive Summaries**: High-level overviews for management
- **Trend Analysis**: Historical compliance tracking

### API Endpoints
```
GET  /reports/templates
POST /reports/generate
GET  /reports/{id}
GET  /reports/{id}/export
GET  /compliance/dashboard
```

### Usage Example
```bash
# Generate ASB compliance report
curl -X POST "http://localhost:8000/reports/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "framework": "asb",
    "format": "pdf",
    "scope": {
      "time_range": {
        "start_date": "2024-01-01",
        "end_date": "2024-12-31"
      }
    }
  }'

# Export report
curl "http://localhost:8000/reports/{report_id}/export?format=pdf"
```

### Supported Frameworks
1. **Azure Security Benchmark (ASB)** v3.0
2. **CIS Controls** v8
3. **NIST Cybersecurity Framework** 1.1
4. **SOC 2 Type II**
5. **ISO 27001**
6. **PCI DSS**

---

## 4. User Authentication & RBAC

### Overview
Enterprise-grade authentication system with role-based access control and comprehensive security features.

### Features
- **JWT Token Authentication**: Secure, stateless authentication
- **Role-Based Access Control**: Admin, Auditor, Viewer, Remediator roles
- **Granular Permissions**: 10 specific permissions for fine-grained control
- **Account Security**: Lockout protection and session management
- **Password Security**: PBKDF2 hashing with salt

### API Endpoints
```
POST /auth/login
POST /auth/register
GET  /auth/me
POST /auth/logout
GET  /auth/permissions
```

### Usage Example
```bash
# User login
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "auditor@company.com",
    "password": "secure_password"
  }'

# Register new user
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "user@company.com",
    "password": "secure_password",
    "role": "viewer"
  }'
```

### Roles and Permissions

#### Admin Role
- All permissions
- User management
- System configuration

#### Auditor Role
- View findings
- Create findings
- Update findings
- View reports
- Create reports
- Manage schedules
- View audit history

#### Remediator Role
- View findings
- Update findings
- Execute remediation
- View reports

#### Viewer Role
- View findings
- View reports

---

## 5. Audit Trail & Logging

### Overview
Comprehensive activity tracking and security event logging for compliance and forensic analysis.

### Features
- **Activity Tracking**: 28 different activity types
- **Security Events**: Dedicated security event logging
- **Log Levels**: Debug, Info, Warning, Error, Critical
- **Filtering & Search**: Advanced query capabilities
- **Audit Summaries**: Activity metrics and summaries

### API Endpoints
```
GET /audit/logs
GET /audit/security-events
GET /audit/summary
```

### Usage Example
```bash
# Get audit logs with filtering
curl "http://localhost:8000/audit/logs?start_date=2024-01-01&end_date=2024-12-31&user_id=user123&limit=100"

# Get security events
curl "http://localhost:8000/audit/security-events?severity=high&limit=50"

# Get audit summary
curl "http://localhost:8000/audit/summary?days=30"
```

### Activity Types
- **Authentication**: Login, logout, failed login, account locked
- **Audit**: Started, completed, failed, schedule management
- **Findings**: Created, updated, resolved, suppressed
- **Remediation**: Preview, executed, failed
- **Reports**: Generated, exported
- **User Management**: Created, updated, deactivated, role changed
- **System**: Startup, shutdown, configuration changed, errors

---

## 6. Executive Dashboard

### Overview
High-level management dashboard with KPIs, risk metrics, and trend analysis for executive decision-making.

### Features
- **Security KPIs**: Compliance score, MTTR, audit success rate, security event rate
- **Risk Metrics**: Risk assessment by category and domain
- **Trend Analysis**: Historical data visualization
- **Top Risks**: Identification of highest-risk resources
- **Compliance Breakdown**: Domain-specific compliance metrics

### API Endpoints
```
GET /executive/summary
GET /executive/kpis
GET /executive/risk-metrics
GET /executive/trends
GET /executive/top-risks
GET /executive/compliance-by-domain
```

### Usage Example
```bash
# Get executive summary
curl "http://localhost:8000/executive/summary?days=30"

# Get security KPIs
curl "http://localhost:8000/executive/kpis?days=90"

# Get risk metrics
curl "http://localhost:8000/executive/risk-metrics?days=30"
```

### Key Performance Indicators
1. **Compliance Score**: Overall security compliance percentage
2. **Mean Time to Resolution (MTTR)**: Average time to resolve findings
3. **Audit Success Rate**: Percentage of successful audit runs
4. **Security Event Rate**: Number of security events per day

---

## 7. Custom Control Definitions

### Overview
Flexible system for creating and managing custom security controls with templates and automated evaluation.

### Features
- **Control Templates**: Pre-built templates for common scenarios
- **Custom Evaluators**: Python code execution for custom logic
- **Template-Based Creation**: Quick control creation from templates
- **Multiple Control Types**: Automated, manual, and hybrid controls
- **Compliance Mapping**: Integration with compliance frameworks

### API Endpoints
```
GET    /custom-controls/templates
POST   /custom-controls
POST   /custom-controls/from-template
GET    /custom-controls
GET    /custom-controls/{id}
PUT    /custom-controls/{id}
DELETE /custom-controls/{id}
POST   /custom-controls/{id}/execute
```

### Usage Example
```bash
# Get available templates
curl "http://localhost:8000/custom-controls/templates"

# Create from template
curl -X POST "http://localhost:8000/custom-controls/from-template" \
  -H "Content-Type: application/json" \
  -d '{
    "template_name": "Storage Account Public Access",
    "customizations": {
      "title": "Custom Storage Public Access Check",
      "severity": "High",
      "risk_score": 8
    },
    "created_by": "user123"
  }'

# Execute custom control
curl -X POST "http://localhost:8000/custom-controls/{control_id}/execute" \
  -H "Content-Type: application/json" \
  -d '{"evidence": {"RawResult": [...]}}'
```

### Available Templates
1. **Storage Account Public Access**: Checks for public blob access
2. **Virtual Machine Disk Encryption**: Verifies disk encryption
3. **Network Security Group Rules**: Identifies overly permissive rules

---

## 8. Trend Analysis & Risk Scoring

### Overview
Advanced analytics system providing trend analysis, predictive insights, and dynamic risk scoring.

### Features
- **Compliance Trend Analysis**: Historical compliance score tracking
- **Finding Trend Analysis**: Trends by severity and domain
- **Predictive Analytics**: Future value predictions with confidence scores
- **Dynamic Risk Scoring**: Multi-factor risk assessment
- **Resource Risk Ranking**: Top risk resources identification

### API Endpoints
```
GET /analytics/compliance-trend
GET /analytics/finding-trends
GET /analytics/risk-score/{resource_id}
GET /analytics/top-risk-resources
GET /analytics/risk-summary
```

### Usage Example
```bash
# Get compliance trend
curl "http://localhost:8000/analytics/compliance-trend?days=90&granularity=daily"

# Get finding trends
curl "http://localhost:8000/analytics/finding-trends?days=90&granularity=weekly"

# Get resource risk score
curl "http://localhost:8000/analytics/risk-score/resource-123"

# Get top risk resources
curl "http://localhost:8000/analytics/top-risk-resources?limit=20"
```

### Trend Analysis Features
- **Trend Direction**: Improving, declining, stable, volatile
- **Trend Strength**: -1 to 1 scale indicating trend intensity
- **Volatility**: Standard deviation of values
- **Predictions**: Next period value predictions with confidence scores

### Risk Scoring Factors
- **Base Score**: From finding severity
- **Trend Adjustment**: Based on recent activity
- **Severity Adjustment**: Critical/high finding distribution
- **Age Adjustment**: Older findings increase risk
- **Frequency Adjustment**: More findings increase risk

---

## Complete API Reference

### Total Endpoints: 60+

#### Core Endpoints (3)
- `GET /` - Root endpoint
- `GET /health` - Health check
- `GET /preflight` - Azure connectivity check

#### Evidence & Findings (6)
- `POST /evidence` - Create evidence
- `GET /evidence` - List evidence
- `GET /findings` - List findings
- `GET /findings/{id}` - Get specific finding
- `POST /evaluate` - Evaluate evidence
- `POST /run-evaluation` - Run evaluation

#### Controls (9)
- `GET /controls` - List all controls
- `GET /custom-controls/templates` - Get control templates
- `POST /custom-controls` - Create custom control
- `POST /custom-controls/from-template` - Create from template
- `GET /custom-controls` - List custom controls
- `GET /custom-controls/{id}` - Get custom control
- `PUT /custom-controls/{id}` - Update custom control
- `DELETE /custom-controls/{id}` - Delete custom control
- `POST /custom-controls/{id}/execute` - Execute custom control

#### Remediation (2)
- `POST /remediation/preview` - Get remediation preview
- `POST /remediation/execute` - Execute remediation

#### Scheduling (7)
- `GET /schedules` - List audit schedules
- `POST /schedules` - Create schedule
- `GET /schedules/{id}` - Get schedule
- `PUT /schedules/{id}` - Update schedule
- `DELETE /schedules/{id}` - Delete schedule
- `POST /schedules/{id}/execute` - Execute schedule
- `GET /audit-history` - Get audit history
- `GET /audit-status/{id}` - Get audit status

#### Compliance & Reporting (5)
- `GET /reports/templates` - Get report templates
- `POST /reports/generate` - Generate compliance report
- `GET /reports/{id}` - Get report
- `GET /reports/{id}/export` - Export report
- `GET /compliance/dashboard` - Compliance dashboard

#### Executive Dashboard (6)
- `GET /executive/summary` - Executive summary
- `GET /executive/kpis` - Security KPIs
- `GET /executive/risk-metrics` - Risk metrics
- `GET /executive/trends` - Trend data
- `GET /executive/top-risks` - Top risks
- `GET /executive/compliance-by-domain` - Domain compliance

#### Authentication (5)
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/me` - Current user info
- `POST /auth/logout` - User logout
- `GET /auth/permissions` - User permissions

#### Audit & Logging (3)
- `GET /audit/logs` - Get audit logs
- `GET /audit/security-events` - Get security events
- `GET /audit/summary` - Audit activity summary

#### Analytics (5)
- `GET /analytics/compliance-trend` - Compliance trend analysis
- `GET /analytics/finding-trends` - Finding trends
- `GET /analytics/risk-score/{resource_id}` - Resource risk score
- `GET /analytics/top-risk-resources` - Top risk resources
- `GET /analytics/risk-summary` - Overall risk summary

---

## Getting Started

### Prerequisites
- Python 3.8+
- Azure CLI configured
- Required Python packages (see requirements.txt)

### Quick Start
1. **Install Dependencies**
   ```bash
   pip install -r api/requirements.txt
   ```

2. **Configure Environment**
   ```bash
   export AZURE_SUBSCRIPTION_ID="your-subscription-id"
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_CLIENT_ID="your-client-id"
   export AZURE_CLIENT_SECRET="your-client-secret"
   ```

3. **Start the Application**
   ```bash
   uvicorn api.main:app --host 0.0.0.0 --port 8000
   ```

4. **Access the API**
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

### First Steps
1. **Register a User**
   ```bash
   curl -X POST "http://localhost:8000/auth/register" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "email": "admin@company.com", "password": "secure_password", "role": "admin"}'
   ```

2. **Login and Get Token**
   ```bash
   curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "secure_password"}'
   ```

3. **Run Your First Audit**
   ```bash
   curl -X POST "http://localhost:8000/run-evaluation" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"control_id": "IM-2"}'
   ```

---

## Security Considerations

### Authentication
- Use strong passwords (minimum 12 characters)
- Enable account lockout protection
- Regularly rotate API tokens
- Use HTTPS in production

### Authorization
- Follow principle of least privilege
- Regularly review user permissions
- Monitor audit logs for suspicious activity
- Implement session timeouts

### Data Protection
- Encrypt sensitive data at rest
- Use secure communication channels
- Implement data retention policies
- Regular security assessments

---

## Troubleshooting

### Common Issues

#### Authentication Errors
- Verify Azure credentials are correctly configured
- Check token expiration
- Ensure proper role assignments

#### API Errors
- Check API endpoint URLs
- Verify request payload format
- Review error messages in response

#### Performance Issues
- Monitor database performance
- Check Azure API rate limits
- Review audit log sizes

### Support
For additional support and documentation:
- Review API documentation at `/docs`
- Check audit logs for detailed error information
- Monitor system health via `/health` endpoint

---

## Conclusion

The Azure Audit Platform now provides enterprise-grade security auditing capabilities with comprehensive features for compliance, remediation, reporting, and analytics. The platform is production-ready and can be deployed to secure Azure environments immediately.

For additional information or support, please refer to the API documentation or contact your system administrator.
