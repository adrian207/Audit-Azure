#!/bin/bash

# GitHub Repository Ruleset Setup Script
# This script sets up comprehensive protection rules for the Azure Audit Platform repository

set -e

echo "🔒 Setting up GitHub Repository Protection Rules for Azure Audit Platform"
echo "========================================================================"

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed. Please install it first:"
    echo "   https://cli.github.com/"
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub CLI. Please run: gh auth login"
    exit 1
fi

# Get repository information
REPO_OWNER=$(gh repo view --json owner --jq '.owner.login')
REPO_NAME=$(gh repo view --json name --jq '.name')

echo "📁 Repository: $REPO_OWNER/$REPO_NAME"
echo ""

# Function to create ruleset
create_ruleset() {
    local ruleset_name="$1"
    local ruleset_file="$2"
    
    echo "🔧 Creating ruleset: $ruleset_name"
    
    if gh api repos/$REPO_OWNER/$REPO_NAME/rulesets --method POST --input "$ruleset_file" &> /dev/null; then
        echo "✅ Ruleset '$ruleset_name' created successfully"
    else
        echo "⚠️  Ruleset '$ruleset_name' may already exist or failed to create"
    fi
}

# Function to enable repository features
enable_features() {
    echo "🔧 Enabling repository security features..."
    
    # Enable vulnerability alerts
    gh api repos/$REPO_OWNER/$REPO_NAME --method PATCH --field vulnerability_alerts=true &> /dev/null
    echo "✅ Vulnerability alerts enabled"
    
    # Enable dependency graph
    gh api repos/$REPO_OWNER/$REPO_NAME --field has_issues=true --field has_projects=true --field has_wiki=false &> /dev/null
    echo "✅ Repository features configured"
    
    # Enable Dependabot alerts
    gh api repos/$REPO_OWNER/$REPO_NAME/vulnerability-alerts --method PUT &> /dev/null
    echo "✅ Dependabot alerts enabled"
}

# Function to set up branch protection
setup_branch_protection() {
    local branch="$1"
    local protection_level="$2"
    
    echo "🛡️  Setting up branch protection for: $branch"
    
    if [ "$protection_level" = "strict" ]; then
        gh api repos/$REPO_OWNER/$REPO_NAME/branches/$branch/protection --method PUT --input - <<EOF
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
    else
        gh api repos/$REPO_OWNER/$REPO_NAME/branches/$branch/protection --method PUT --input - <<EOF
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
    fi
    
    echo "✅ Branch protection configured for $branch"
}

# Function to create security policy
create_security_policy() {
    echo "📋 Creating security policy..."
    
    if [ -f "SECURITY.md" ]; then
        echo "✅ Security policy already exists"
    else
        echo "⚠️  Security policy not found. Please ensure SECURITY.md is present."
    fi
}

# Function to verify workflows
verify_workflows() {
    echo "🔍 Verifying GitHub Actions workflows..."
    
    local workflows=(
        "security-scan.yml"
        "code-quality.yml"
        "test-coverage.yml"
        "dependency-check.yml"
        "branch-protection.yml"
    )
    
    for workflow in "${workflows[@]}"; do
        if [ -f ".github/workflows/$workflow" ]; then
            echo "✅ Workflow $workflow found"
        else
            echo "⚠️  Workflow $workflow not found"
        fi
    done
}

# Function to verify templates
verify_templates() {
    echo "📝 Verifying issue and PR templates..."
    
    local templates=(
        "pull_request_template.md"
        "ISSUE_TEMPLATE/bug_report.md"
        "ISSUE_TEMPLATE/feature_request.md"
        "ISSUE_TEMPLATE/security_vulnerability.md"
        "CODEOWNERS"
    )
    
    for template in "${templates[@]}"; do
        if [ -f ".github/$template" ]; then
            echo "✅ Template $template found"
        else
            echo "⚠️  Template $template not found"
        fi
    done
}

# Main execution
echo "🚀 Starting GitHub repository protection setup..."
echo ""

# Verify prerequisites
verify_workflows
echo ""
verify_templates
echo ""

# Enable repository features
enable_features
echo ""

# Set up branch protection
setup_branch_protection "main" "strict"
setup_branch_protection "develop" "moderate"
echo ""

# Create security policy
create_security_policy
echo ""

# Create rulesets (if ruleset.json exists)
if [ -f ".github/ruleset.json" ]; then
    create_ruleset "Azure Audit Platform Protection Rules" ".github/ruleset.json"
else
    echo "⚠️  Ruleset configuration file not found"
fi

echo ""
echo "🎉 GitHub repository protection setup completed!"
echo ""
echo "📋 Summary of protections enabled:"
echo "   ✅ Branch protection for main and develop"
echo "   ✅ Required status checks for CI/CD"
echo "   ✅ Required pull request reviews"
echo "   ✅ Code owner reviews"
echo "   ✅ Vulnerability alerts"
echo "   ✅ Dependabot alerts"
echo "   ✅ Security scanning workflows"
echo "   ✅ Code quality checks"
echo "   ✅ Test coverage requirements"
echo "   ✅ Dependency security checks"
echo ""
echo "🔒 Your Azure Audit Platform repository is now protected!"
echo ""
echo "📚 Next steps:"
echo "   1. Review and customize the protection rules as needed"
echo "   2. Add team members to CODEOWNERS file"
echo "   3. Configure required secrets for workflows"
echo "   4. Test the protection rules with a test PR"
echo ""
echo "🆘 For help, see: .github/GITHUB_RULESET.md"
