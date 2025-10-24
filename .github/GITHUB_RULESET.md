# GitHub Repository Ruleset Configuration

## Overview
This configuration provides comprehensive protection for the Azure Audit Platform repository with security, compliance, and collaboration rules.

## Repository Ruleset (GitHub API Format)

```json
{
  "name": "Azure Audit Platform Protection Rules",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["main", "develop", "release/*"]
    }
  },
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "required_status_checks": {
          "strict": true,
          "contexts": [
            "ci/tests",
            "ci/security-scan",
            "ci/code-quality",
            "ci/dependency-check"
          ]
        }
      }
    },
    {
      "type": "required_pull_request_reviews",
      "parameters": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews": true,
        "require_code_owner_reviews": true,
        "require_last_push_approval": true
      }
    },
    {
      "type": "required_signatures",
      "parameters": {
        "required_signatures": true
      }
    },
    {
      "type": "required_linear_history",
      "parameters": {
        "required_linear_history": true
      }
    },
    {
      "type": "required_deployments",
      "parameters": {
        "required_deployments": {
          "environments": ["production", "staging"]
        }
      }
    },
    {
      "type": "required_conversation_resolution",
      "parameters": {
        "required_conversation_resolution": true
      }
    },
    {
      "type": "lock_branch",
      "parameters": {
        "lock_branch": true
      }
    },
    {
      "type": "required_signatures",
      "parameters": {
        "required_signatures": true
      }
    }
  ]
}
```

## Security Rules

### 1. Branch Protection Rules
```yaml
# .github/branch-protection.yml
name: Branch Protection
on:
  push:
    branches: [main, develop]

jobs:
  protect-branches:
    runs-on: ubuntu-latest
    steps:
      - name: Protect main branch
        uses: actions/github-script@v6
        with:
          script: |
            await github.rest.repos.updateBranchProtection({
              owner: context.repo.owner,
              repo: context.repo.repo,
              branch: 'main',
              required_status_checks: {
                strict: true,
                contexts: ['ci/tests', 'ci/security-scan', 'ci/code-quality']
              },
              enforce_admins: true,
              required_pull_request_reviews: {
                required_approving_review_count: 2,
                dismiss_stale_reviews: true,
                require_code_owner_reviews: true
              },
              restrictions: null
            });
```

### 2. Code Security Scanning
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
      
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v2
        with:
          languages: python, javascript
```

### 3. Dependency Security
```yaml
# .github/workflows/dependency-check.yml
name: Dependency Security Check
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday
  push:
    branches: [main]

jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install safety bandit
          cd api && pip install -r requirements.txt
      
      - name: Run safety check
        run: safety check --json --output safety-report.json
      
      - name: Run bandit security linter
        run: bandit -r api/ -f json -o bandit-report.json
      
      - name: Upload security reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            safety-report.json
            bandit-report.json
```

## Compliance Rules

### 4. Code Quality Gates
```yaml
# .github/workflows/code-quality.yml
name: Code Quality
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install linting tools
        run: |
          pip install black flake8 mypy isort
          cd ui && npm install
      
      - name: Run Black formatter
        run: black --check api/
      
      - name: Run Flake8 linter
        run: flake8 api/ --max-line-length=100
      
      - name: Run MyPy type checker
        run: mypy api/
      
      - name: Run isort import sorter
        run: isort --check-only api/
      
      - name: Run ESLint
        run: cd ui && npm run lint
```

### 5. Test Coverage Requirements
```yaml
# .github/workflows/test-coverage.yml
name: Test Coverage
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test-coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov
          pip install -r api/requirements.txt
      
      - name: Run tests with coverage
        run: |
          pytest tests/ --cov=api --cov-report=xml --cov-report=html
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          flags: unittests
          name: codecov-umbrella
          fail_ci_if_error: true
          threshold: 80%
```

## Collaboration Rules

### 6. Pull Request Templates
```markdown
# .github/pull_request_template.md
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Security enhancement

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Input validation implemented
- [ ] Authentication/authorization checked
- [ ] Security tests added

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed
- [ ] Security testing completed

## Compliance
- [ ] Follows coding standards
- [ ] Documentation updated
- [ ] API changes documented
- [ ] Breaking changes noted

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] No console.log statements left
- [ ] No hardcoded credentials
```

### 7. Issue Templates
```markdown
# .github/ISSUE_TEMPLATE/bug_report.md
---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''

---

**Describe the Bug**
A clear description of what the bug is.

**Security Impact**
- [ ] No security impact
- [ ] Low security impact
- [ ] Medium security impact
- [ ] High security impact
- [ ] Critical security impact

**To Reproduce**
Steps to reproduce the behavior.

**Expected Behavior**
What you expected to happen.

**Environment**
- OS: [e.g. Windows, Linux, macOS]
- Python Version: [e.g. 3.11]
- Azure SDK Version: [e.g. 1.0.0]

**Additional Context**
Add any other context about the problem here.
```

## Access Control Rules

### 8. CODEOWNERS File
```
# .github/CODEOWNERS

# Global owners
* @adrian207

# API and backend
/api/ @adrian207 @security-team
/persistence/ @adrian207 @security-team
/evaluators/ @adrian207 @security-team
/azure_sdk/ @adrian207 @security-team

# Frontend
/ui/ @adrian207 @frontend-team

# Documentation
/docs/ @adrian207 @documentation-team
README.md @adrian207

# Security critical files
.github/workflows/ @adrian207 @security-team
Dockerfile @adrian207 @security-team
docker-compose.yml @adrian207 @security-team

# Configuration files
*.yml @adrian207 @security-team
*.yaml @adrian207 @security-team
requirements.txt @adrian207 @security-team
package.json @adrian207 @frontend-team

# Database and migrations
/alembic/ @adrian207 @security-team
/persistence/alembic/ @adrian207 @security-team
```

### 9. Repository Settings
```yaml
# Repository configuration recommendations
repository_settings:
  # General
  has_issues: true
  has_projects: true
  has_wiki: false
  has_downloads: true
  
  # Security
  allow_squash_merge: true
  allow_merge_commit: false
  allow_rebase_merge: true
  allow_auto_merge: false
  delete_branch_on_merge: true
  
  # Vulnerability alerts
  vulnerability_alerts: true
  
  # Security policy
  security_policy_enabled: true
  
  # Dependabot
  dependabot_alerts: true
  dependabot_security_updates: true
```

## Deployment Rules

### 10. Environment Protection
```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy to Azure
        run: |
          echo "Deploying to production..."
          # Add your deployment commands here
      
      - name: Notify deployment
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          channel: '#deployments'
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

## Monitoring Rules

### 11. Repository Monitoring
```yaml
# .github/workflows/monitor.yml
name: Repository Monitoring
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check for security vulnerabilities
        run: |
          echo "Checking for known vulnerabilities..."
          # Add security monitoring checks
      
      - name: Check dependency freshness
        run: |
          echo "Checking dependency freshness..."
          # Add dependency monitoring
      
      - name: Generate security report
        run: |
          echo "Generating weekly security report..."
          # Generate comprehensive security report
```

## Implementation Instructions

### Step 1: Create GitHub Ruleset
1. Go to your repository on GitHub
2. Navigate to Settings > Rules > Rulesets
3. Click "New ruleset"
4. Use the JSON configuration above

### Step 2: Set up Workflows
1. Create `.github/workflows/` directory
2. Add all workflow files
3. Configure required secrets and variables

### Step 3: Configure Branch Protection
1. Go to Settings > Branches
2. Add rule for `main` branch
3. Configure protection settings

### Step 4: Set up CODEOWNERS
1. Create `.github/CODEOWNERS` file
2. Add team members and permissions
3. Configure review requirements

### Step 5: Enable Security Features
1. Enable Dependabot alerts
2. Enable vulnerability alerts
3. Set up security policy
4. Configure secret scanning

This ruleset provides comprehensive protection for your Azure Audit Platform repository with security, compliance, and collaboration rules that ensure code quality and maintain security standards.
