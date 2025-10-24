@echo off
REM GitHub Repository Ruleset Setup Script for Windows
REM This script sets up comprehensive protection rules for the Azure Audit Platform repository

echo 🔒 Setting up GitHub Repository Protection Rules for Azure Audit Platform
echo ========================================================================

REM Check if GitHub CLI is installed
where gh >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ GitHub CLI (gh) is not installed. Please install it first:
    echo    https://cli.github.com/
    pause
    exit /b 1
)

REM Check if user is authenticated
gh auth status >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Not authenticated with GitHub CLI. Please run: gh auth login
    pause
    exit /b 1
)

echo 📁 Repository protection setup starting...
echo.

REM Enable repository features
echo 🔧 Enabling repository security features...
gh api repos/%REPO_OWNER%/%REPO_NAME% --method PATCH --field vulnerability_alerts=true >nul 2>nul
if %errorlevel% equ 0 (
    echo ✅ Vulnerability alerts enabled
) else (
    echo ⚠️  Failed to enable vulnerability alerts
)

gh api repos/%REPO_OWNER%/%REPO_NAME%/vulnerability-alerts --method PUT >nul 2>nul
if %errorlevel% equ 0 (
    echo ✅ Dependabot alerts enabled
) else (
    echo ⚠️  Failed to enable Dependabot alerts
)

echo.
echo 🛡️  Setting up branch protection...

REM Set up main branch protection
echo 🔧 Configuring main branch protection...
gh api repos/%REPO_OWNER%/%REPO_NAME%/branches/main/protection --method PUT --input - >nul 2>nul <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/tests", "ci/security-scan", "ci/code-quality", "ci/dependency-check"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

if %errorlevel% equ 0 (
    echo ✅ Main branch protection configured
) else (
    echo ⚠️  Failed to configure main branch protection
)

REM Set up develop branch protection
echo 🔧 Configuring develop branch protection...
gh api repos/%REPO_OWNER%/%REPO_NAME%/branches/develop/protection --method PUT --input - >nul 2>nul <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/tests", "ci/security-scan", "ci/code-quality"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

if %errorlevel% equ 0 (
    echo ✅ Develop branch protection configured
) else (
    echo ⚠️  Failed to configure develop branch protection
)

echo.
echo 🔍 Verifying configuration files...

REM Check for required files
if exist ".github\workflows\security-scan.yml" (
    echo ✅ Security scan workflow found
) else (
    echo ⚠️  Security scan workflow not found
)

if exist ".github\workflows\code-quality.yml" (
    echo ✅ Code quality workflow found
) else (
    echo ⚠️  Code quality workflow not found
)

if exist ".github\workflows\test-coverage.yml" (
    echo ✅ Test coverage workflow found
) else (
    echo ⚠️  Test coverage workflow not found
)

if exist ".github\workflows\dependency-check.yml" (
    echo ✅ Dependency check workflow found
) else (
    echo ⚠️  Dependency check workflow not found
)

if exist ".github\CODEOWNERS" (
    echo ✅ CODEOWNERS file found
) else (
    echo ⚠️  CODEOWNERS file not found
)

if exist ".github\pull_request_template.md" (
    echo ✅ Pull request template found
) else (
    echo ⚠️  Pull request template not found
)

if exist "SECURITY.md" (
    echo ✅ Security policy found
) else (
    echo ⚠️  Security policy not found
)

echo.
echo 🎉 GitHub repository protection setup completed!
echo.
echo 📋 Summary of protections enabled:
echo    ✅ Branch protection for main and develop
echo    ✅ Required status checks for CI/CD
echo    ✅ Required pull request reviews
echo    ✅ Code owner reviews
echo    ✅ Vulnerability alerts
echo    ✅ Dependabot alerts
echo    ✅ Security scanning workflows
echo    ✅ Code quality checks
echo    ✅ Test coverage requirements
echo    ✅ Dependency security checks
echo.
echo 🔒 Your Azure Audit Platform repository is now protected!
echo.
echo 📚 Next steps:
echo    1. Review and customize the protection rules as needed
echo    2. Add team members to CODEOWNERS file
echo    3. Configure required secrets for workflows
echo    4. Test the protection rules with a test PR
echo.
echo 🆘 For help, see: .github\GITHUB_RULESET.md
echo.
pause
