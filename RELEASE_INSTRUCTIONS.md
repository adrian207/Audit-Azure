# Release Instructions for Audit-Azure

**Author:** Adrian Johnson <adrian207@gmail.com>

This document provides step-by-step instructions for creating a new release of Audit-Azure on GitHub.

---

## 📋 Pre-Release Checklist

Before creating a release, ensure:

- [ ] All tests pass locally (`pytest`)
- [ ] Code is formatted (`black .`)
- [ ] No linter errors (`flake8 .`)
- [ ] Documentation is up to date
- [ ] CHANGELOG.md is updated with new version
- [ ] Version number is updated in `setup.py`
- [ ] All changes are committed to `main` branch
- [ ] Working tree is clean (`git status`)

---

## 🚀 Creating a GitHub Release (Manual Method)

### Step 1: Prepare Release Files

Ensure these files are in your repository:
```
✅ README.md (updated and professional)
✅ CHANGELOG.md (version entry added)
✅ RELEASE_NOTES_v1.0.0.md (detailed release notes)
✅ CONTRIBUTING.md
✅ SECURITY.md
✅ setup.py (version updated to 1.0.0)
```

### Step 2: Commit and Push

```bash
# Commit all changes
git add .
git commit -m "Release: Version 1.0.0

- Updated README with professional documentation
- Added comprehensive release notes
- Updated CHANGELOG for v1.0.0
- Enhanced setup.py with metadata
- Added GitHub templates and workflows"

# Push to main branch
git push origin main
```

### Step 3: Create and Push Tag

```bash
# Create annotated tag
git tag -a v1.0.0 -m "Release v1.0.0: Initial Public Release"

# Push tag to GitHub
git push origin v1.0.0
```

### Step 4: Create Release on GitHub

#### Option A: Web Interface (Easiest)

1. Go to your repository: https://github.com/adrian207/Audit-Azure

2. Click on **"Releases"** in the right sidebar

3. Click **"Draft a new release"** or **"Create a new release"**

4. Fill in the release form:
   - **Choose a tag**: Select `v1.0.0` (or create if it doesn't exist)
   - **Release title**: `Release v1.0.0 - Initial Public Release`
   - **Description**: Copy the contents from `RELEASE_NOTES_v1.0.0.md`

5. Attach files (optional but recommended):
   - Click "Attach binaries" and add:
     - Source code (automatically included)
     - `RELEASE_NOTES_v1.0.0.md`
     - Any distribution files

6. Options:
   - [ ] Set as a pre-release (unchecked for stable release)
   - [ ] Set as latest release (checked)
   - [ ] Create a discussion for this release (optional)

7. Click **"Publish release"**

#### Option B: GitHub CLI (Faster)

```bash
# Install GitHub CLI if not already installed
# Windows: winget install GitHub.cli
# Linux: sudo apt install gh
# macOS: brew install gh

# Authenticate (first time only)
gh auth login

# Create release with release notes
gh release create v1.0.0 \
  --title "Release v1.0.0 - Initial Public Release" \
  --notes-file RELEASE_NOTES_v1.0.0.md \
  --latest

# Or create release with inline notes
gh release create v1.0.0 \
  --title "Release v1.0.0 - Initial Public Release" \
  --notes "🎉 First official release of Audit-Azure..." \
  --latest
```

#### Option C: Automatic with GitHub Actions

The GitHub Actions workflow (`.github/workflows/release.yml`) will automatically:
- Trigger on tag push (e.g., `v1.0.0`)
- Build Python package
- Create GitHub release
- Attach distribution files
- Use release notes from `RELEASE_NOTES_v1.0.0.md`

To use this method, just push the tag:
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
# Wait for GitHub Actions to complete
```

---

## 📦 Release Assets

### Automatically Included
- Source code (zip)
- Source code (tar.gz)

### Manually Attach (Optional)
- `RELEASE_NOTES_v1.0.0.md` - Detailed release notes
- Python wheel: `dist/azure_audit-1.0.0-py3-none-any.whl`
- Source distribution: `dist/azure-audit-1.0.0.tar.gz`

To build distribution files:
```bash
# Install build tools
pip install build

# Build distribution packages
python -m build

# Files will be in dist/ directory
ls dist/
# azure_audit-1.0.0-py3-none-any.whl
# azure-audit-1.0.0.tar.gz
```

---

## 🏷️ Versioning Guidelines

Audit-Azure follows [Semantic Versioning](https://semver.org/):

### Version Format: `MAJOR.MINOR.PATCH`

- **MAJOR** (1.x.x): Breaking changes, major new features
  - Example: v2.0.0 - Complete architecture redesign

- **MINOR** (x.1.x): New features, no breaking changes
  - Example: v1.1.0 - Add multi-tenant support

- **PATCH** (x.x.1): Bug fixes, security updates
  - Example: v1.0.1 - Fix authentication bug

### Version Tags

```bash
# Stable releases
v1.0.0, v1.1.0, v2.0.0

# Pre-releases (optional)
v1.1.0-beta.1
v1.1.0-rc.1
v2.0.0-alpha.1
```

---

## 📝 Release Notes Template

For future releases, create `RELEASE_NOTES_vX.Y.Z.md`:

```markdown
# 🎉 Audit-Azure vX.Y.Z - Release Title

**Release Date:** YYYY-MM-DD
**Author:** Adrian Johnson <adrian207@gmail.com>

## 🌟 Highlights

Brief overview of major changes in this release.

## ✨ New Features

- Feature 1: Description
- Feature 2: Description

## 🐛 Bug Fixes

- Fix 1: Description
- Fix 2: Description

## 🔄 Changes

- Change 1: Description
- Change 2: Description

## 🗑️ Deprecated

- Deprecation 1: Description and migration path

## 🚨 Breaking Changes

- Breaking change 1: Description and migration steps

## 🔒 Security

- Security update 1: Description

## 📦 Dependencies

- Updated dependency X to version Y
- Added dependency Z for feature W

## 📚 Documentation

- Added/updated documentation for X
- New guide for Y

## 🙏 Contributors

Thanks to everyone who contributed to this release:
- @contributor1
- @contributor2

## 📥 Installation

\`\`\`bash
git clone https://github.com/adrian207/Audit-Azure.git
cd Audit-Azure
./install.sh
\`\`\`

## 🔄 Upgrading

\`\`\`bash
git pull origin main
git checkout vX.Y.Z
./install.sh
\`\`\`

---

Full changelog: https://github.com/adrian207/Audit-Azure/blob/main/docs/CHANGELOG.md
```

---

## 🔄 Post-Release Steps

After creating the release:

1. **Verify Release**
   - [ ] Check release page on GitHub
   - [ ] Verify assets are attached
   - [ ] Test download and installation

2. **Update Documentation**
   - [ ] Update main README if needed
   - [ ] Add release to CHANGELOG.md (if not done)
   - [ ] Update version references in docs

3. **Announce Release**
   - [ ] Create announcement in GitHub Discussions
   - [ ] Update project website (if applicable)
   - [ ] Share on social media (if applicable)
   - [ ] Notify users via email list (if applicable)

4. **Start Next Version**
   - [ ] Create milestone for next version
   - [ ] Update version in `setup.py` to next dev version
   - [ ] Begin tracking issues for next release

---

## 🐛 Hotfix Releases

For urgent bug fixes:

```bash
# Create hotfix branch from release tag
git checkout -b hotfix/1.0.1 v1.0.0

# Make fixes
# ... edit files ...

# Commit fixes
git commit -am "Fix: Critical bug in authentication"

# Update version in setup.py to 1.0.1
# Update CHANGELOG.md

# Merge to main
git checkout main
git merge hotfix/1.0.1

# Create new tag
git tag -a v1.0.1 -m "Hotfix v1.0.1: Fix authentication bug"

# Push everything
git push origin main
git push origin v1.0.1

# Create release on GitHub
gh release create v1.0.1 \
  --title "Hotfix v1.0.1" \
  --notes "Fixes critical authentication bug. All users should upgrade."
```

---

## 📊 Release Checklist (Full)

### Pre-Release
- [ ] All features for this version are complete
- [ ] All tests pass (`pytest`)
- [ ] Code is formatted (`black .`)
- [ ] No linter warnings (`flake8 .`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md has entry for new version
- [ ] RELEASE_NOTES created for this version
- [ ] Version updated in `setup.py`
- [ ] Dependencies are up to date and secure
- [ ] Security review completed

### Release
- [ ] Changes committed to main
- [ ] Tag created and pushed
- [ ] GitHub release created
- [ ] Release notes populated
- [ ] Assets attached (if applicable)
- [ ] Release published (not draft)

### Post-Release
- [ ] Release verified and tested
- [ ] Documentation updated
- [ ] Announcement made
- [ ] Next milestone created
- [ ] Issues triaged for next version

---

## 📞 Questions?

If you have questions about the release process:

- **Email**: adrian207@gmail.com
- **Docs**: Check this file and CONTRIBUTING.md
- **Issues**: https://github.com/adrian207/Audit-Azure/issues

---

## 🎯 Quick Reference

### Create Release (Full Process)

```bash
# 1. Update version and docs
# Edit setup.py, CHANGELOG.md, create RELEASE_NOTES_vX.Y.Z.md

# 2. Commit and push
git add .
git commit -m "Release: Version X.Y.Z"
git push origin main

# 3. Create and push tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z

# 4. Create release on GitHub (choose one method above)
# - Web interface
# - GitHub CLI
# - GitHub Actions (automatic)

# 5. Verify and announce
```

---

**Happy Releasing!** 🚀

---

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Project**: https://github.com/adrian207/Audit-Azure  
**License**: MIT

