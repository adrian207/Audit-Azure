# Security Policy

**Author:** Adrian Johnson <adrian207@gmail.com>

## 🔒 Security Commitment

Audit-Azure is a security auditing platform, and we take the security of the project itself very seriously. We appreciate the security research community's efforts to responsibly disclose vulnerabilities.

---

## 🛡️ Supported Versions

We actively support the following versions with security updates:

| Version | Supported          | Support Status |
| ------- | ------------------ | -------------- |
| 1.0.x   | ✅ Yes             | Active support |
| 0.1.x   | ❌ No              | Development only, not for production |
| < 0.1   | ❌ No              | Pre-release, unsupported |

---

## 🚨 Reporting a Vulnerability

### Please Do Not

- ❌ Open a public GitHub issue for security vulnerabilities
- ❌ Discuss the vulnerability in public forums or social media
- ❌ Exploit the vulnerability beyond what is necessary to demonstrate it

### Please Do

- ✅ Email security reports to **adrian207@gmail.com** with subject line: `[SECURITY] Audit-Azure Vulnerability Report`
- ✅ Provide detailed information to help us understand and reproduce the issue
- ✅ Allow reasonable time for us to fix the vulnerability before public disclosure
- ✅ Work with us on coordinated disclosure

### Report Format

When reporting a security vulnerability, please include:

```markdown
**Summary**: Brief description of the vulnerability

**Severity**: [Critical/High/Medium/Low]

**Affected Version(s)**: [e.g., 1.0.0, all versions, etc.]

**Vulnerability Type**: [e.g., SQL Injection, XSS, Authentication Bypass, etc.]

**Description**: Detailed description of the vulnerability

**Steps to Reproduce**:
1. Step 1
2. Step 2
3. ...

**Proof of Concept**: 
[Code snippet, screenshots, or video demonstrating the vulnerability]

**Impact**: 
What can an attacker do with this vulnerability?

**Proposed Mitigation**:
If you have suggestions for fixing the issue

**Discoverer**: 
Your name/handle (for acknowledgment)

**Contact**: 
Your email for follow-up questions
```

---

## 🔄 Vulnerability Response Process

### Our Commitment

[Inference] We aim to respond to security reports according to the following timeline:

| Timeframe | Action |
|-----------|--------|
| **24-48 hours** | Initial response acknowledging receipt |
| **3-5 days** | Assessment of severity and impact |
| **7-30 days** | Develop and test fix (depending on severity) |
| **Upon fix** | Coordinated disclosure with reporter |

### Severity Levels

We assess vulnerabilities using the following criteria:

#### Critical (CVSS 9.0-10.0)
- Remote code execution
- Authentication bypass with full system access
- SQL injection with database compromise
- **Response time**: Immediate, fix within 7 days

#### High (CVSS 7.0-8.9)
- Privilege escalation
- Sensitive data exposure
- Authentication bypass (limited access)
- **Response time**: Fix within 14 days

#### Medium (CVSS 4.0-6.9)
- Cross-site scripting (XSS)
- Information disclosure
- Denial of service (limited impact)
- **Response time**: Fix within 30 days

#### Low (CVSS 0.1-3.9)
- Minor information leakage
- Best practice violations
- **Response time**: Fix in next minor release

---

## 🎯 Security Scope

### In Scope

The following components are in scope for security reports:

- **API Backend** (`api/`)
  - Authentication and authorization
  - Input validation
  - SQL injection prevention
  - API endpoint security
  
- **Web UI** (`ui/`)
  - XSS vulnerabilities
  - CSRF protection
  - Client-side security
  
- **Database Layer** (`persistence/`)
  - SQL injection
  - Data validation
  
- **Azure Integration** (`azure_sdk/`)
  - Credential handling
  - Authentication flows
  
- **Dependencies**
  - Known vulnerabilities in third-party packages

### Out of Scope

The following are typically out of scope:

- ❌ Social engineering attacks
- ❌ Physical access to servers
- ❌ Denial of service (unless easily exploitable)
- ❌ Issues in third-party Azure services
- ❌ Theoretical vulnerabilities without proof of concept
- ❌ Vulnerabilities requiring excessive user interaction
- ❌ Issues in unsupported versions

---

## 🔐 Security Best Practices

### For Users

When deploying Audit-Azure:

#### Authentication
- ✅ Use Service Principal authentication in production
- ✅ Store credentials in Azure Key Vault
- ✅ Rotate credentials regularly (90 days recommended)
- ✅ Apply principle of least privilege
- ❌ Don't use Azure CLI authentication in production
- ❌ Don't store credentials in code or config files

#### Network Security
- ✅ Deploy behind Azure Application Gateway or similar WAF
- ✅ Use HTTPS/TLS for all connections
- ✅ Implement network segmentation
- ✅ Use Azure Private Link when possible
- ❌ Don't expose API directly to internet in production

#### Database Security
- ✅ Use PostgreSQL instead of SQLite in production
- ✅ Enable database encryption at rest
- ✅ Use TLS for database connections
- ✅ Implement database backups
- ❌ Don't use default credentials

#### Monitoring
- ✅ Enable Azure Monitor logging
- ✅ Set up security alerts
- ✅ Monitor API access logs
- ✅ Review audit logs regularly

### For Developers

When contributing to Audit-Azure:

#### Code Security
- ✅ Use parameterized queries (SQLAlchemy ORM does this)
- ✅ Validate all user inputs
- ✅ Sanitize outputs to prevent XSS
- ✅ Use type hints for better code safety
- ✅ Follow OWASP Top 10 guidelines

#### Dependency Management
- ✅ Pin dependency versions
- ✅ Regularly update dependencies
- ✅ Review dependency security advisories
- ✅ Use `pip audit` or `safety` for Python
- ✅ Use `npm audit` for Node.js

#### Testing
- ✅ Write security-focused unit tests
- ✅ Test authentication and authorization
- ✅ Test input validation
- ✅ Test error handling (don't leak info)

---

## 📜 Security Disclosures

We maintain a record of security vulnerabilities and their fixes:

### Published Security Advisories

No security advisories have been published yet for Audit-Azure v1.0.0.

### Security Updates

Check [CHANGELOG.md](docs/CHANGELOG.md) for security-related updates in each release.

---

## 🏆 Security Researchers Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

<!-- Security researchers will be listed here after responsible disclosure -->

*No vulnerabilities reported yet*

### Recognition

For valid vulnerability reports, we offer:

- 📜 Public acknowledgment (if desired)
- 🏆 Recognition in release notes
- 📧 Direct communication with maintainers
- 🤝 Potential collaboration opportunities

**Note:** [Inference] This is an open-source project maintained by volunteers. We do not offer monetary bug bounties at this time.

---

## 📞 Contact

### Security Issues
- **Email**: adrian207@gmail.com
- **Subject**: `[SECURITY] Audit-Azure Vulnerability Report`
- **PGP**: Coming soon

### General Security Questions
- **Email**: adrian207@gmail.com
- **Subject**: `[SECURITY QUESTION] ...`

### Non-Security Issues
- **GitHub Issues**: https://github.com/adrian207/Audit-Azure/issues
- **GitHub Discussions**: https://github.com/adrian207/Audit-Azure/discussions

---

## 🔄 Updates to This Policy

This security policy may be updated periodically. Material changes will be announced in:

- Release notes
- README.md
- GitHub security advisories

**Last Updated:** October 28, 2025  
**Version:** 1.0

---

## 📚 Additional Resources

### Security Guides
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Audit-Azure Security Documentation
- [Setup Guide](docs/SETUP.md) - Secure deployment instructions
- [API Reference](docs/API_REFERENCE.md) - API security features
- [Contributing Guide](CONTRIBUTING.md) - Secure coding practices

---

**Thank you for helping keep Audit-Azure and its users safe!** 🔒

---

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Project**: https://github.com/adrian207/Audit-Azure  
**License**: MIT

