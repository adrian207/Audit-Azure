# Azure Audit Platform - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [User Interface Overview](#user-interface-overview)
3. [Running Evaluations](#running-evaluations)
4. [Understanding Results](#understanding-results)
5. [Managing Findings](#managing-findings)
6. [Remediation](#remediation)
7. [Reports & Export](#reports--export)
8. [Advanced Features](#advanced-features)

## Introduction

The Azure Audit Platform provides a user-friendly interface for assessing your Azure environment against Microsoft's security best practices and compliance frameworks.

### What Can You Do?

- ✅ **Assess Security Posture**: Evaluate against 74+ Azure Security Benchmark controls
- ✅ **Track Compliance**: Map to CIS, NIST, PCI-DSS, ISO 27001
- ✅ **Remediate Issues**: Get step-by-step remediation guidance
- ✅ **Monitor Trends**: Track security score over time
- ✅ **Generate Reports**: Export findings for stakeholders

## User Interface Overview

### Navigation Menu

The platform has 5 main sections:

#### 1. 🏠 Dashboard
**Purpose**: Executive overview of security posture

**What You See:**
- Total evidence, findings, and controls
- Recent critical/high findings
- Quick statistics

**When to Use**: Daily check-in to see current state

#### 2. 📦 Evidence  
**Purpose**: View collected Azure resources

**What You See:**
- List of all Azure resources scanned
- Resource metadata (type, region, tags)
- Collection timestamps

**When to Use**: 
- Verify correct resources are being scanned
- Add manual evidence items
- Troubleshoot missing resources

#### 3. 🔍 Findings
**Purpose**: Browse and filter security issues

**What You See:**
- All findings with severity, status, timestamps
- Filter by severity level
- Detailed finding information

**When to Use**:
- Review security issues
- Prioritize remediation efforts
- Track resolution progress

#### 4. 📋 Controls
**Purpose**: Browse security control catalog

**What You See:**
- All 74+ Azure Security Benchmark controls
- Control domains (Identity, Network, Data, etc.)
- Control descriptions and mappings

**When to Use**:
- Understand what's being evaluated
- Learn about security requirements
- Plan evaluation strategy

#### 5. ⚙️ Evaluation
**Purpose**: Run security assessments

**What You See:**
- Control selector dropdown
- Run button to execute evaluations
- Real-time results display

**When to Use**:
- Run on-demand security checks
- Test specific controls
- Generate fresh findings

## Running Evaluations

### Single Control Evaluation

**Step-by-step:**

1. Navigate to **Evaluation** page
2. Click the **control dropdown**
3. Select a control (e.g., "IM-2: Require MFA for all users")
4. Click **"Run Evaluation"** button
5. Wait 30-90 seconds for results
6. Review findings in the results panel

**What Happens:**
- Platform queries Azure APIs
- Evaluates resources against control requirements
- Creates findings for non-compliant resources
- Displays results with remediation guidance

**Expected Time:**
- Identity controls: 30-90 seconds
- Network controls: 1-3 minutes
- Data controls: 1-2 minutes
- Full audit: 5-45 minutes (based on environment size)

### Batch Evaluation

**Running Multiple Controls:**

Option 1: **Domain-based** (e.g., all Identity controls)
```
Select "IM-*" controls and run sequentially
```

Option 2: **Compliance Framework** (e.g., all PCI-DSS controls)
```
Select controls tagged with PCI-DSS mappings
```

Option 3: **Full Audit**
```
Run all 74+ controls (allow 45-120 minutes)
```

### Evaluation Status

During evaluation, you'll see:

- ⏳ **Running**: Evaluation in progress
- ✅ **Success**: Evaluation completed
- ❌ **Error**: Evaluation failed (check permissions)
- ⚠️ **Partial**: Some resources failed

## Understanding Results

### Finding Anatomy

Each finding contains:

**Header:**
- **Control ID**: ASB control (e.g., IM-2)
- **Severity**: Critical/High/Medium/Low
- **Title**: Brief description
- **Status**: Open/In Progress/Resolved

**Details:**
- **Description**: What the issue is
- **Affected Resources**: Specific Azure resources
- **Impact**: Why it matters
- **Recommendation**: How to fix
- **Remediation**: Step-by-step scripts

**Metadata:**
- **Timestamp**: When discovered
- **Evaluator**: Which check found it
- **Framework Mappings**: CIS/NIST/PCI/ISO references

### Severity Interpretation

#### 🔴 Critical (Score Impact: 100%)
**What it means**: Severe security risk with immediate exploitation potential

**Examples:**
- No MFA enabled for any users
- Storage accounts publicly accessible
- Admin accounts without security policies
- Unencrypted sensitive data

**Action**: Fix within 24-48 hours

#### 🟠 High (Score Impact: 70%)
**What it means**: Significant security gap that increases risk

**Examples:**
- Missing Conditional Access policies
- No encryption in transit
- Legacy authentication enabled
- Missing security monitoring

**Action**: Fix within 1-2 weeks

#### 🟡 Medium (Score Impact: 40%)
**What it means**: Security improvement opportunity

**Examples:**
- Incomplete security policies
- Missing tags on resources
- Suboptimal configurations
- Missing backups

**Action**: Fix within 1 month

#### 🔵 Low (Score Impact: 20%)
**What it means**: Best practice recommendation

**Examples:**
- Documentation gaps
- Optimization opportunities
- Non-critical configuration items

**Action**: Address when convenient

### Secure Score Explained

**Score Calculation:**
```
Secure Score = (Points Earned / Total Points) × 100%

Points are weighted by:
- Control weight (1-3)
- Finding severity (Critical=1.0, High=0.7, Medium=0.4, Low=0.2)
```

**Score Ranges:**
- **90-100%**: 🌟 Excellent - Enterprise-grade security
- **70-89%**: ✅ Good - Minor improvements needed
- **50-69%**: ⚠️ Fair - Several security gaps
- **30-49%**: ❌ Poor - Significant risks
- **Below 30%**: 🚨 Critical - Immediate action required

**Improvement Impact:**

The platform shows potential score improvement for each finding:
- Fixing a Critical finding on a weight-3 control: +3-5%
- Fixing a High finding on a weight-2 control: +1-2%
- Fixing a Medium finding: +0.5-1%

## Managing Findings

### Filtering Findings

Use the **severity filter** dropdown:
- All Findings
- Critical Only
- High Only
- Medium Only
- Low Only

### Finding Lifecycle

**Status Flow:**
```
Open → In Progress → Resolved → Verified
```

**Status Meanings:**
- **Open**: Newly discovered, not yet addressed
- **In Progress**: Remediation underway
- **Resolved**: Fix applied, awaiting verification
- **Verified**: Confirmed resolved by re-scan

### Bulk Actions

Select multiple findings to:
- Export to Excel/PDF
- Assign to team members (future feature)
- Change status in bulk
- Generate remediation script package

## Remediation

### Getting Remediation Guidance

1. Click on a **finding**
2. Scroll to **"Remediation"** section
3. Choose your preferred method:
   - **Azure Portal**: Manual steps
   - **PowerShell**: Automated PowerShell script
   - **Azure CLI**: Command-line script
   - **Bicep/Terraform**: Infrastructure-as-code (future)

### Example: Remediating "No MFA" Finding

**Finding:**
```
Control: IM-2
Title: MFA Not Enforced for All Users
Severity: Critical
Affected: 15 users without MFA
```

**Remediation Options:**

**Option 1: Azure Portal**
```
1. Go to Azure AD → Security → Conditional Access
2. Create new policy: "Require MFA for All Users"
3. Assignments: All users
4. Grant controls: Require multi-factor authentication
5. Enable policy
```

**Option 2: PowerShell**
```powershell
# Copy provided script
$policy = New-AzureADMSConditionalAccessPolicy `
    -DisplayName "Require MFA for All Users" `
    -State "Enabled" `
    -Conditions @{Users = @{IncludeUsers = "All"}} `
    -GrantControls @{Operator = "OR"; BuiltInControls = @("mfa")}
```

**Option 3: Azure CLI**
```bash
# Use generated CLI commands
az ad policy create ...
```

### Validation

After remediation:
1. Wait 5-10 minutes for Azure to apply changes
2. Re-run the evaluation
3. Verify finding is resolved
4. Check Secure Score improvement

## Reports & Export

### Export Options

**From Findings Page:**
- Click **"Export"** button
- Choose format:
  - **Excel**: For detailed analysis
  - **PDF**: For executive reporting
  - **JSON**: For tool integration
  - **CSV**: For data analysis

**Report Contents:**
- All findings with full details
- Severity distribution
- Affected resources list
- Remediation recommendations
- Compliance framework mappings

### Scheduled Reports (Future Feature)

Configure automatic weekly/monthly reports:
- Email delivery to stakeholders
- Trend analysis over time
- Score change tracking
- New findings highlights

## Advanced Features

### API Integration

Access the REST API at `http://localhost:8000`

**Common Endpoints:**
```
GET  /evidence       - List collected resources
POST /evidence       - Add evidence manually
GET  /findings       - List all findings
GET  /controls       - List available controls
POST /evaluation     - Run evaluation
GET  /secure-score   - Get current score
```

**API Documentation**: Visit `http://localhost:8000/docs`

### Performance Tuning

**For Large Environments (1000+ resources):**

Edit `.env`:
```bash
MAX_CONCURRENT_EVALUATIONS=10    # Increase parallelism
CACHE_TTL=600                     # Longer cache (10 min)
BATCH_SIZE=100                    # Larger batches
```

**Expected Speedup**: 2-3x faster for large audits

### Security Hardening

**For Production Use:**

1. **Enable API Key Authentication:**
```bash
# Generate secure key
API_MASTER_KEY=$(openssl rand -hex 32)
```

2. **Configure Rate Limiting:**
```bash
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

3. **Use Service Principal** (not Azure CLI)
4. **Enable HTTPS** with reverse proxy
5. **Enable audit logging** for compliance

### Multi-Subscription Support

Audit multiple subscriptions:

```bash
# In .env
AZURE_SUBSCRIPTION_IDS=sub-1,sub-2,sub-3
```

Platform will:
- Scan all subscriptions sequentially
- Aggregate findings across subscriptions
- Show subscription-level breakdowns
- Calculate combined Secure Score

## Tips & Best Practices

### 🎯 Prioritization Strategy

1. **Week 1**: Fix all Critical findings
2. **Week 2**: Address High findings in Identity/Access domain
3. **Week 3**: Address High findings in Data Protection domain
4. **Week 4**: Work on Medium findings, run full re-audit

### ⏰ Scheduling Recommendations

- **Daily**: Check dashboard for new Critical findings
- **Weekly**: Run quick audit (key controls only)
- **Monthly**: Run full comprehensive audit
- **Quarterly**: Check for benchmark updates

### 📊 Reporting to Stakeholders

**For Executives:**
- Show Secure Score trend
- Highlight score improvements
- Focus on business risk reduction
- Use PDF reports with graphs

**For Technical Teams:**
- Provide detailed Excel exports
- Share remediation scripts
- Include framework mappings (PCI/NIST)
- Show resource-level details

### 🚀 Continuous Improvement

1. **Track Score Over Time**: Run audits monthly to see trends
2. **Set Score Goals**: Aim for 70% (good), 90% (excellent)
3. **Automate Remediation**: Use scripts for common fixes
4. **Stay Current**: Update benchmarks quarterly

## Need Help?

- **Documentation**: Check `docs/` folder
- **API Reference**: See `docs/API_REFERENCE.md`
- **Getting Started**: See `docs/GETTING_STARTED.md`
- **GitHub**: https://github.com/adrian207/Audit-Azure
- **Email**: adrian207@gmail.com

---

**Happy auditing!** 🔍🛡️
