# Quick Start Guide

## Installation (5 minutes)

### 1. Install System Dependencies

**On Ubuntu/Debian:**
```bash
# Install Composer
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer

# Install Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.1_linux_x64.tar.gz

# Install Node.js/NPM (optional, for theme scanning)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**On macOS:**
```bash
# Install Composer
brew install composer

# Install Gitleaks
brew install gitleaks

# Install Node.js/NPM (optional)
brew install node
```

### 2. Download the Script

```bash
# Navigate to your project directory
cd /path/to/your/project

# Download the script
wget https://raw.githubusercontent.com/your-repo/drupal_security_audit.py
# OR
curl -O https://raw.githubusercontent.com/your-repo/drupal_security_audit.py

# Make executable
chmod +x drupal_security_audit.py
```

### 3. Verify Installation

```bash
python3 drupal_security_audit.py --help
```

## Common Usage Scenarios

### Scenario 1: Quick Security Check (Beginner)

**Use case:** You just want to check for security vulnerabilities in dependencies and secrets.

```bash
cd /path/to/drupal
python3 /path/to/drupal_security_audit.py .
```

**What it checks:**
- ✓ Composer packages for known vulnerabilities
- ✓ Entire codebase for exposed secrets
- ✗ Code quality (skipped)
- ✗ JavaScript dependencies (skipped)

**Time:** ~1-2 minutes

---

### Scenario 2: Full Custom Code Audit (Intermediate)

**Use case:** You want to check custom modules and themes for coding standards and security issues.

```bash
cd /path/to/drupal
python3 /path/to/drupal_security_audit.py . \
  --phpcs-paths web/modules/custom web/themes/custom
```

**What it checks:**
- ✓ Composer packages
- ✓ Secrets
- ✓ Custom module code quality (PHPCS)
- ✓ Custom theme code quality (PHPCS)
- ✗ JavaScript dependencies (skipped if no --themes-path)

**Time:** ~3-5 minutes (depending on codebase size)

---

### Scenario 3: Complete Audit with JS Dependencies (Advanced)

**Use case:** Full security and quality audit including JavaScript packages.

```bash
cd /path/to/drupal
python3 /path/to/drupal_security_audit.py . \
  --phpcs-paths web/modules/custom web/themes/custom \
  --themes-path web/themes/custom \
  --output audit-$(date +%Y%m%d-%H%M%S).json
```

**What it checks:**
- ✓ Composer packages
- ✓ Secrets
- ✓ PHP code quality
- ✓ JavaScript package vulnerabilities
- ✓ Saves detailed JSON report

**Time:** ~5-10 minutes

---

### Scenario 4: CI/CD Integration (DevOps)

**Use case:** Automated security checks in your deployment pipeline.

**Add to your deployment script:**
```bash
#!/bin/bash
set -e

echo "Running Drupal Security Audit..."

python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom \
  --output /tmp/audit-report.json

# Check exit code
if [ $? -ne 0 ]; then
  echo "❌ Security audit failed! Deployment blocked."
  exit 1
else
  echo "✅ Security audit passed! Proceeding with deployment."
fi
```

---

### Scenario 5: Scheduled Audits (Cron Job)

**Use case:** Weekly automated security audits.

**Add to crontab:**
```bash
# Edit crontab
crontab -e

# Add this line (runs every Monday at 9 AM)
0 9 * * 1 cd /var/www/drupal && python3 /usr/local/bin/drupal_security_audit.py . --phpcs-paths web/modules/custom --themes-path web/themes/custom --output /var/log/drupal-audit-$(date +\%Y\%m\%d).json 2>&1 | mail -s "Drupal Security Audit Report" admin@example.com
```

---

## Common Path Structures

### Standard Drupal 9/10/11 Structure
```bash
drupal_root/
├── composer.json          # ← Point script here
├── web/
│   ├── core/
│   ├── modules/
│   │   ├── contrib/
│   │   └── custom/        # ← Scan this with --phpcs-paths
│   ├── themes/
│   │   ├── contrib/
│   │   └── custom/        # ← Scan this with --phpcs-paths and --themes-path
│   └── profiles/
│       └── custom/        # ← Optionally scan with --phpcs-paths
```

**Command:**
```bash
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom web/themes/custom web/profiles/custom \
  --themes-path web/themes/custom
```

### Legacy Drupal 7 Structure
```bash
drupal_root/
├── composer.json          # ← If using Composer
├── sites/
│   ├── all/
│   │   ├── modules/
│   │   │   └── custom/    # ← Scan this
│   │   └── themes/
│   │       └── custom/    # ← Scan this
```

**Command:**
```bash
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths sites/all/modules/custom sites/all/themes/custom \
  --themes-path sites/all/themes/custom
```

---

## Interpreting Results

### Exit Codes
- **0** = All checks passed ✓
- **1** = One or more checks failed ✗

### Status Indicators
- **✓ PASSED** (Green) = No issues found
- **✗ FAILED** (Red) = Issues found, needs attention
- **⊘ SKIPPED** (Yellow) = Check was skipped (tool missing or no paths specified)
- **? ERROR** (Yellow) = Check encountered an error

### Priority Levels

**Critical (Fix Immediately):**
1. Gitleaks findings (exposed secrets)
2. Composer Critical/High vulnerabilities
3. NPM Critical/High vulnerabilities

**High (Fix This Week):**
1. Composer Moderate vulnerabilities
2. NPM Moderate vulnerabilities
3. PHPCS errors in security-sensitive code

**Medium (Fix This Sprint):**
1. PHPCS errors in general code
2. Composer Low vulnerabilities
3. NPM Low vulnerabilities

**Low (Plan for Future):**
1. PHPCS warnings
2. Code style inconsistencies

---

## Troubleshooting Common Issues

### Issue: "composer: command not found"
**Solution:**
```bash
# Install Composer
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

### Issue: "gitleaks: command not found"
**Solution:**
```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### Issue: "No composer.json found"
**Solution:** Make sure you're in the Drupal root directory (where composer.json exists)
```bash
# Check current directory
ls -la composer.json

# Or specify full path
python3 drupal_security_audit.py /var/www/drupal
```

### Issue: PHPCS takes too long
**Solution:** Scan only specific directories instead of everything
```bash
# Instead of this (slow):
--phpcs-paths web/modules web/themes

# Do this (fast):
--phpcs-paths web/modules/custom web/themes/custom
```

### Issue: False positives in Gitleaks
**Solution:** Create a `.gitleaksignore` file in your Drupal root
```bash
# .gitleaksignore
tests/**
*.test.php
web/sites/default/settings.local.php
```

---

## What to Do When Checks Fail

### Composer Vulnerabilities Found
1. Review the CVE details and affected packages
2. Run `composer update` to get latest versions
3. If a fix isn't available, check Drupal security advisories
4. Consider using `composer require package/name:^safer-version`

### PHPCS Errors Found
1. Auto-fix what you can: `vendor/bin/phpcbf --standard=Drupal web/modules/custom`
2. Review remaining issues manually
3. Fix critical security-related issues first
4. Create a remediation plan for non-critical issues

### NPM Vulnerabilities Found
1. Navigate to the theme directory: `cd web/themes/custom/mytheme`
2. Run `npm audit fix` to auto-fix
3. For breaking changes: `npm audit fix --force` (test thoroughly!)
4. Update package.json manually if needed

### Secrets Found
1. **IMMEDIATELY** rotate the exposed credentials
2. Remove secrets from git history:
   ```bash
   # Using git-filter-repo (recommended)
   git filter-repo --path path/to/file --invert-paths
   ```
3. Add secrets to .gitignore
4. Use environment variables or secret management tools

---

## Next Steps

1. **Run your first audit** using Scenario 1 above
2. **Review the results** and prioritize fixes
3. **Set up automated audits** (cron job or CI/CD)
4. **Create a remediation plan** for any issues found
5. **Schedule regular audits** (weekly or before each deployment)

Need help? Check the full README.md for detailed documentation.
