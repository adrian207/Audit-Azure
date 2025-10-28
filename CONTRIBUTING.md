# Contributing to Audit-Azure

**Author:** Adrian Johnson <adrian207@gmail.com>

First off, thank you for considering contributing to Audit-Azure! It's people like you that make this platform a great tool for the Azure security community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Writing Evaluators](#writing-evaluators)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

---

## 🤝 Code of Conduct

### Our Standards

This project adheres to professional and respectful collaboration:

- **Be Respectful**: Value diverse perspectives and experiences
- **Be Constructive**: Provide helpful feedback and accept it graciously
- **Be Professional**: Focus on what's best for the project and community
- **Be Inclusive**: Welcome newcomers and help them contribute

### Enforcement

Instances of unacceptable behavior may be reported to adrian207@gmail.com. All complaints will be reviewed and investigated promptly.

---

## 🎯 How Can I Contribute?

### Reporting Bugs

**Before submitting a bug report:**
- Check the [existing issues](https://github.com/adrian207/Audit-Azure/issues) to avoid duplicates
- Update to the latest version to see if the issue persists
- Collect relevant information (logs, screenshots, environment details)

**When submitting a bug report, include:**

```markdown
**Description**: Clear description of the bug

**Steps to Reproduce**:
1. Step one
2. Step two
3. ...

**Expected Behavior**: What should happen

**Actual Behavior**: What actually happens

**Environment**:
- OS: [e.g., Windows 11, Ubuntu 22.04]
- Python Version: [e.g., 3.11.2]
- Audit-Azure Version: [e.g., 1.0.0]
- Azure CLI Version: [e.g., 2.45.0]

**Logs/Screenshots**: If applicable

**Additional Context**: Any other relevant information
```

### Suggesting Features

**Before submitting a feature request:**
- Check if it's already been suggested
- Consider if it aligns with the project's goals
- Think about how it would benefit other users

**When suggesting a feature, include:**
- Clear use case and motivation
- Proposed implementation (if you have ideas)
- Potential alternatives considered
- Examples from other tools (if applicable)

### Code Contributions

We welcome pull requests for:
- Bug fixes
- New evaluators for security controls
- Performance improvements
- Documentation enhancements
- UI/UX improvements
- Test coverage expansion

---

## 🛠️ Development Setup

### Prerequisites

- Python 3.8 or higher
- Node.js 18 or higher
- Git
- Azure CLI (optional but recommended)
- Code editor (VS Code recommended)

### Initial Setup

```bash
# 1. Fork the repository on GitHub
# Click "Fork" at https://github.com/adrian207/Audit-Azure

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/Audit-Azure.git
cd Audit-Azure

# 3. Add upstream remote
git remote add upstream https://github.com/adrian207/Audit-Azure.git

# 4. Create a virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# 5. Install dependencies
pip install -e ".[dev]"

# 6. Install UI dependencies
cd ui
npm install
cd ..

# 7. Set up pre-commit hooks (optional but recommended)
pre-commit install
```

### Running Locally

```bash
# Terminal 1 - API Server
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 - UI Development Server
cd ui
npm start

# Terminal 3 - Run tests
pytest
```

### Keeping Your Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge upstream main into your main
git checkout main
git merge upstream/main

# Push updates to your fork
git push origin main
```

---

## 📏 Coding Standards

### Python Code Style

We follow [PEP 8](https://peps.python.org/pep-0008/) and use automated tools:

```bash
# Format code with Black
black . --line-length 100

# Check code style
flake8 . --max-line-length=100

# Type checking
mypy evaluators/ api/ persistence/

# Run all quality checks
black . && flake8 . && mypy evaluators/
```

### Python Best Practices

```python
# Good: Clear function names and type hints
def evaluate_mfa_policy(users: List[Dict[str, Any]]) -> List[Finding]:
    """
    Evaluate MFA compliance for Azure AD users.
    
    Args:
        users: List of user dictionaries from Azure AD
        
    Returns:
        List of Finding objects for non-compliant users
    """
    findings = []
    for user in users:
        if not user.get("isMfaRegistered", False):
            findings.append(create_finding(user))
    return findings

# Bad: Unclear names, no type hints, no docstring
def check(u):
    r = []
    for x in u:
        if not x.get("mfa"):
            r.append(make(x))
    return r
```

### JavaScript/React Code Style

```javascript
// Good: Functional components with clear prop types
import PropTypes from 'prop-types';

const FindingCard = ({ finding, onRemediate }) => {
  const { severity, title, affectedResources } = finding;
  
  return (
    <Card severity={severity}>
      <h3>{title}</h3>
      <ResourceList resources={affectedResources} />
      <Button onClick={() => onRemediate(finding.id)}>
        Remediate
      </Button>
    </Card>
  );
};

FindingCard.propTypes = {
  finding: PropTypes.object.isRequired,
  onRemediate: PropTypes.func.isRequired,
};

export default FindingCard;
```

### Commit Messages

Follow the Minto Pyramid Principle (as per user rules):

```bash
# Good: Clear summary, then details
git commit -m "Fix: MFA evaluator not detecting conditional access policies

The evaluator was only checking user-level MFA settings and missing
conditional access policies that enforce MFA. Updated to query both
Graph API endpoints and aggregate results.

- Added conditional access policy check
- Updated tests to cover both scenarios
- Added documentation for the change"

# Bad: Vague message
git commit -m "Fixed bug"
```

### Naming Conventions

| Type | Convention | Example |
|------|-----------|---------|
| Python Files | `snake_case.py` | `network_security.py` |
| Python Classes | `PascalCase` | `NetworkSecurityEvaluator` |
| Python Functions | `snake_case()` | `evaluate_nsg_rules()` |
| Python Constants | `UPPER_SNAKE_CASE` | `MAX_RETRY_ATTEMPTS` |
| React Components | `PascalCase.js` | `FindingCard.js` |
| React Functions | `camelCase()` | `handleSubmit()` |

---

## 🔄 Submitting Changes

### Branch Naming

```bash
# Feature branches
git checkout -b feature/add-aws-support
git checkout -b feature/mfa-evaluator-enhancement

# Bug fix branches
git checkout -b fix/api-timeout-handling
git checkout -b fix/ui-rendering-issue

# Documentation branches
git checkout -b docs/update-api-reference
git checkout -b docs/add-troubleshooting-guide
```

### Pull Request Process

1. **Create a feature branch** from `main`

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following coding standards

3. **Add tests** for new functionality

   ```bash
   # Run tests
   pytest
   
   # Check coverage
   pytest --cov=. --cov-report=html
   ```

4. **Update documentation** as needed

5. **Commit your changes** with clear messages

6. **Push to your fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub

### Pull Request Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
How was this tested?
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Screenshots (if applicable)
Add screenshots for UI changes

## Checklist
- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No new linter warnings

## Related Issues
Closes #123
Relates to #456
```

### Review Process

- Maintainers will review your PR within 3-5 business days
- Address review feedback promptly
- Be open to suggestions and discussion
- Once approved, maintainers will merge your PR

---

## 🔐 Writing Evaluators

Evaluators are the core of Audit-Azure's security assessment capabilities.

### Evaluator Structure

```python
"""
Network Security Evaluator
Author: Adrian Johnson <adrian207@gmail.com>

Evaluates Azure network security configurations against security best practices.
"""

from typing import List, Dict, Any
from evaluators.registry import register_evaluator


@register_evaluator("NS-1")
def evaluate_network_segmentation(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    NS-1: Network segmentation
    
    Checks if virtual networks have proper subnet segmentation.
    
    Args:
        evidence: Dictionary containing:
            - vnets: List of virtual network configurations
            - subnets: List of subnet configurations
            
    Returns:
        List of finding dictionaries with keys:
            - control_id: Control identifier
            - severity: Finding severity (Critical/High/Medium/Low)
            - title: Brief description
            - description: Detailed finding information
            - affected_resources: List of non-compliant resource IDs
            - remediation: Recommended actions
            - evidence: Supporting evidence
    """
    findings = []
    vnets = evidence.get("vnets", [])
    
    for vnet in vnets:
        subnets = vnet.get("subnets", [])
        
        # Check: VNet should have multiple subnets
        if len(subnets) < 2:
            findings.append({
                "control_id": "NS-1",
                "severity": "Medium",
                "title": "Insufficient network segmentation",
                "description": f"Virtual network {vnet['name']} has only {len(subnets)} subnet(s). "
                              f"Best practice is to segment networks by function.",
                "affected_resources": [vnet["id"]],
                "remediation": "Create additional subnets to separate workloads by tier or function.",
                "evidence": {"vnet": vnet["name"], "subnet_count": len(subnets)}
            })
    
    return findings


@register_evaluator("NS-2")
def evaluate_nsg_rules(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    NS-2: Network Security Group rules
    
    Evaluates NSG rules for security issues.
    """
    findings = []
    nsgs = evidence.get("network_security_groups", [])
    
    for nsg in nsgs:
        # Check for overly permissive rules
        for rule in nsg.get("security_rules", []):
            if rule.get("source_address_prefix") == "*" and \
               rule.get("destination_port_range") == "*":
                findings.append({
                    "control_id": "NS-2",
                    "severity": "High",
                    "title": "Overly permissive NSG rule",
                    "description": f"NSG '{nsg['name']}' has rule '{rule['name']}' "
                                  f"allowing all traffic from any source.",
                    "affected_resources": [nsg["id"]],
                    "remediation": "Restrict source IP ranges and destination ports to minimum required.",
                    "evidence": {"nsg": nsg["name"], "rule": rule["name"]}
                })
    
    return findings
```

### Evaluator Best Practices

1. **Registration**: Always use `@register_evaluator` decorator
2. **Documentation**: Include comprehensive docstrings
3. **Error Handling**: Handle missing or malformed evidence gracefully
4. **Performance**: Optimize for large datasets
5. **Testing**: Write unit tests for each evaluator

### Testing Evaluators

```python
"""
Test Network Security Evaluator
Author: Adrian Johnson <adrian207@gmail.com>
"""

import pytest
from evaluators.network_security import evaluate_network_segmentation, evaluate_nsg_rules


def test_network_segmentation_single_subnet():
    """Test detection of insufficient network segmentation."""
    evidence = {
        "vnets": [
            {
                "id": "/subscriptions/.../vnet1",
                "name": "vnet1",
                "subnets": [{"name": "default"}]
            }
        ]
    }
    
    findings = evaluate_network_segmentation(evidence)
    
    assert len(findings) == 1
    assert findings[0]["control_id"] == "NS-1"
    assert findings[0]["severity"] == "Medium"
    assert "vnet1" in findings[0]["affected_resources"][0]


def test_nsg_overly_permissive_rule():
    """Test detection of overly permissive NSG rules."""
    evidence = {
        "network_security_groups": [
            {
                "id": "/subscriptions/.../nsg1",
                "name": "nsg1",
                "security_rules": [
                    {
                        "name": "allow-all",
                        "source_address_prefix": "*",
                        "destination_port_range": "*"
                    }
                ]
            }
        ]
    }
    
    findings = evaluate_nsg_rules(evidence)
    
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
```

---

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_evaluators.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run with verbose output
pytest -v

# Run only tests matching pattern
pytest -k "test_network"
```

### Writing Tests

```python
"""
Test template for evaluators
Author: Adrian Johnson <adrian207@gmail.com>
"""

import pytest
from evaluators.your_module import your_evaluator


class TestYourEvaluator:
    """Test suite for your evaluator."""
    
    def test_compliant_scenario(self):
        """Test that compliant resources produce no findings."""
        evidence = {
            # Compliant evidence data
        }
        findings = your_evaluator(evidence)
        assert len(findings) == 0
    
    def test_non_compliant_scenario(self):
        """Test that non-compliant resources are detected."""
        evidence = {
            # Non-compliant evidence data
        }
        findings = your_evaluator(evidence)
        assert len(findings) > 0
        assert findings[0]["severity"] in ["Critical", "High", "Medium", "Low"]
    
    def test_empty_evidence(self):
        """Test handling of empty evidence."""
        findings = your_evaluator({})
        assert isinstance(findings, list)
    
    def test_malformed_evidence(self):
        """Test handling of malformed evidence."""
        evidence = {"invalid": "data"}
        findings = your_evaluator(evidence)
        assert isinstance(findings, list)
```

### Test Coverage Goals

- **Minimum**: 70% overall coverage
- **Target**: 85% overall coverage
- **Evaluators**: 90%+ coverage (critical code paths)

---

## 📝 Documentation

### Docstring Format

Use Google-style docstrings:

```python
def evaluate_control(evidence: Dict[str, Any], config: Dict[str, Any]) -> List[Finding]:
    """
    Evaluate security control compliance.
    
    This function assesses Azure resources against a specific security control
    and returns findings for non-compliant resources.
    
    Args:
        evidence: Dictionary containing resource evidence with keys:
            - resources: List of Azure resource configurations
            - metadata: Collection metadata
        config: Evaluator configuration with keys:
            - strict_mode: Whether to apply strict interpretation
            - excluded_resources: Resource IDs to exclude
    
    Returns:
        List of Finding objects containing:
            - control_id: Control identifier
            - severity: Finding severity level
            - affected_resources: List of non-compliant resource IDs
    
    Raises:
        ValueError: If evidence is missing required fields
        KeyError: If config is malformed
    
    Examples:
        >>> evidence = {"resources": [...], "metadata": {...}}
        >>> config = {"strict_mode": True}
        >>> findings = evaluate_control(evidence, config)
        >>> len(findings)
        3
    """
    pass
```

### Updating Documentation

When making changes:
- Update relevant `.md` files in `docs/`
- Update inline code comments
- Update API docstrings
- Update README if adding major features
- Update CHANGELOG.md

### Documentation Structure

```
docs/
├── GETTING_STARTED.md     # First-time user guide
├── API_REFERENCE.md       # Complete API documentation
├── DESIGN.md              # Architecture overview
├── EVALUATOR_GUIDE.md     # Creating custom evaluators
├── CONTROL_CATALOG.md     # Available security controls
├── USER_GUIDE.md          # Platform usage
├── TEST_STRATEGY.md       # Testing approach
└── CHANGELOG.md           # Version history
```

---

## 📧 Questions?

If you have questions about contributing:

- **Check existing documentation** in `docs/`
- **Search existing issues** for similar questions
- **Open a discussion** on GitHub Discussions
- **Email** adrian207@gmail.com for direct help

---

## 🎉 Recognition

Contributors will be:
- Listed in CHANGELOG.md for their contributions
- Mentioned in release notes
- Added to a CONTRIBUTORS.md file (coming soon)

Thank you for contributing to Audit-Azure! 🙏

---

**Happy Coding!**

Adrian Johnson <adrian207@gmail.com>

