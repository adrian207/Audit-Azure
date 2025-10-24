# Azure Audit Platform - Quick Reference

## 🚀 Quick Commands

### Installation & Setup
```bash
# Windows (as Administrator)
install.bat

# Linux/Mac
chmod +x install.sh && sudo ./install.sh

# Azure Login
az login
```

### Start Platform
```bash
# Start both API + UI
run_all.bat        # Windows
./run_all.sh       # Linux/Mac

# Start individually
run_api.bat        # API only (Windows)
run_ui.bat         # UI only (Windows)
./run_api.sh       # API only (Linux/Mac)
./run_ui.sh        # UI only (Linux/Mac)
```

### Check for Updates
```bash
# Check for Microsoft baseline updates
check_updates.bat  # Windows
./check_updates.sh # Linux/Mac

# Show framework info
python -m scripts.update_benchmarks --show-framework-info

# Apply updates
python -m scripts.update_benchmarks --update-controls
```

## 🌐 URLs

- **UI Dashboard**: http://localhost:3000
- **API Server**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **API Docs (ReDoc)**: http://localhost:8000/redoc

## ⚙️ Configuration (.env)

### Authentication
```bash
# Azure CLI (Easiest)
AZURE_USE_CLI=true

# Service Principal (Production)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id

# Managed Identity (Azure-hosted)
AZURE_USE_MANAGED_IDENTITY=true
```

### Security
```bash
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100        # Requests per window
RATE_LIMIT_WINDOW=60           # Window in seconds
SECRET_KEY=auto-generated      # Don't change
ENABLE_AUDIT_LOG=true
API_MASTER_KEY=optional        # Generate with: openssl rand -hex 32
```

### Performance
```bash
ENABLE_CACHING=true
CACHE_TTL=300                  # Cache lifetime (seconds)
MAX_CONCURRENT_EVALUATIONS=5   # Parallel evals
BATCH_SIZE=50                  # Resources per batch
QUERY_PAGE_SIZE=100            # Results per page
```

## 📊 Execution Times

| Environment Size | Audit Time | Resources |
| ---------------- | ---------- | --------- |
| Small            | 2-5 min    | <50       |
| Medium           | 5-15 min   | 50-500    |
| Large            | 15-45 min  | 500-5000  |
| Enterprise       | 45-120 min | 5000+     |

**Individual Evaluators:**
- Identity (Entra ID): 30-90 seconds
- Network Security: 1-3 minutes
- Policy Compliance: 2-5 minutes
- Data Protection: 1-2 minutes
- Secure Score: 5-10 seconds

## 🎯 Common Tasks

### Run First Audit
1. Open http://localhost:3000
2. Click "Evaluation"
3. Select "IM-2: Require MFA"
4. Click "Run Evaluation"
5. Wait 30-90 seconds
6. Review findings

### View Secure Score
1. Run full audit (all controls)
2. Check API: `GET http://localhost:8000/secure-score`
3. Or calculate from findings in UI

### Export Findings
1. Go to "Findings" page
2. Click "Export" button
3. Choose format (Excel/PDF/JSON)
4. Download report

### Fix Critical Findings
1. Filter by "Critical" severity
2. Click on finding for details
3. Copy remediation script
4. Execute in PowerShell/CLI
5. Re-run evaluation to verify

## 🛡️ Security Severity

| Level    | Icon | Score Impact | Action                  |
| -------- | ---- | ------------ | ----------------------- |
| Critical | 🔴    | 100%         | Fix in 24-48 hours      |
| High     | 🟠    | 70%          | Fix in 1-2 weeks        |
| Medium   | 🟡    | 40%          | Fix in 1 month          |
| Low      | 🔵    | 20%          | Address when convenient |

## 📈 Secure Score Ranges

| Score   | Grade | Status    |
| ------- | ----- | --------- |
| 90-100% | 🌟     | Excellent |
| 70-89%  | ✅     | Good      |
| 50-69%  | ⚠️     | Fair      |
| 30-49%  | ❌     | Poor      |
| <30%    | 🚨     | Critical  |

## 🔧 Troubleshooting

### Import Errors
```bash
cd api
source venv/bin/activate  # or venv\Scripts\activate
pip install -r requirements.txt
```

### Authentication Failed
```bash
# Re-login to Azure
az login
az account show

# Or update .env with credentials
```

### Port Already in Use
```bash
# Change in .env
API_PORT=8001  # instead of 8000

# Update ui/package.json proxy
"proxy": "http://localhost:8001"
```

### Rate Limit Exceeded
```bash
# Wait 60 seconds, or increase in .env
RATE_LIMIT_REQUESTS=200
RATE_LIMIT_WINDOW=60
```

## 📚 Azure Security Benchmark Controls

### Identity & Access (IM)
- IM-1: Use centralized identity and authentication system
- **IM-2: Require MFA for all users**
- IM-3: Implement Conditional Access
- IM-4: Block legacy authentication
- IM-5: Manage guest access
- IM-6: Secure service principals
- IM-7: Restrict admin accounts
- IM-8: Automate credential rotation
- IM-9: Regular access reviews

### Privileged Access (PA)
- **PA-1: Protect and monitor privileged accounts**
- PA-2: Avoid permanent privileged access
- **PA-3: Use Privileged Identity Management (PIM)**
- PA-4: Require approval for activation
- PA-5: Set maximum activation time
- PA-6: Use secure workstations for admin tasks
- PA-7: Follow least privilege principle
- PA-8: Regular privileged access reviews

### Network Security (NS)
- NS-1: Establish network segmentation boundaries
- NS-2: Secure cloud services with network controls
- NS-3: Deploy firewall at network edge
- NS-4: Deploy DDoS protection
- NS-5: Detect and disable insecure services
- NS-6: Implement secure remote access
- NS-7: Simplify network security rules

### Data Protection (DP)
- DP-1: Discover, classify, and label sensitive data
- DP-2: Monitor data exfiltration
- DP-3: Encrypt data at rest
- DP-4: Encrypt sensitive data in transit
- DP-5: Use customer-managed keys
- DP-6: Secure access to data stores
- DP-7: Regular backup of critical data
- DP-8: Ensure data residency requirements

### Governance & Strategy (GS)
- GS-1: Define and implement security strategy
- GS-2: Define and implement security ownership
- GS-3: Define security stakeholder engagement
- GS-4: Align organization roles, responsibilities
- GS-5: Define security monitoring strategy
- GS-6: Define security incident response

## 🔑 API Endpoints

### Evidence
```bash
GET  /evidence              # List all evidence
POST /evidence              # Create new evidence
GET  /evidence/{id}         # Get specific evidence
```

### Findings
```bash
GET  /findings              # List all findings
GET  /findings?severity=Critical  # Filter by severity
GET  /findings/{id}         # Get specific finding
```

### Controls
```bash
GET  /controls              # List all controls
GET  /controls/{id}         # Get specific control
GET  /controls?domain=IM    # Filter by domain
```

### Evaluation
```bash
POST /evaluation            # Run evaluation
  Body: {"control_id": "IM-2"}
```

### Secure Score
```bash
GET  /secure-score          # Get current score
GET  /secure-score/trend    # Get score history
GET  /secure-score/domain/{domain}  # Domain score
```

## 📞 Getting Help

- **Documentation**: `docs/` folder
- **Getting Started**: `docs/GETTING_STARTED.md`
- **User Guide**: `docs/USER_GUIDE.md`
- **API Reference**: `docs/API_REFERENCE.md`
- **GitHub Issues**: https://github.com/adrian207/Audit-Azure/issues
- **Email**: adrian207@gmail.com

## 🎓 Best Practices

### Daily
- ✅ Check dashboard for new Critical findings
- ✅ Review audit log for suspicious activity

### Weekly
- ✅ Run quick audit (Identity + Network controls)
- ✅ Address new High severity findings
- ✅ Review Secure Score trend

### Monthly
- ✅ Run full comprehensive audit (all 74 controls)
- ✅ Generate executive report
- ✅ Track score improvement
- ✅ Update remediation status

### Quarterly
- ✅ Check for benchmark updates (`check_updates.bat/sh`)
- ✅ Review compliance framework mappings
- ✅ Audit privileged accounts
- ✅ Test incident response procedures

## 🚀 Performance Tuning

### For Large Environments (1000+ resources)
```bash
# In .env
MAX_CONCURRENT_EVALUATIONS=10   # Increase parallelism
CACHE_TTL=600                    # Longer cache (10 min)
BATCH_SIZE=100                   # Larger batches
QUERY_PAGE_SIZE=200              # More results per page
```

### For Better Azure API Performance
- Run during off-peak hours (2-6 AM local time)
- Enable caching (default ON)
- Use batch processing
- Increase concurrent evaluations on high-CPU systems

---

**Quick Tip**: Bookmark this page for instant reference! 📌
