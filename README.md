# Drupal 11 Security Audit Tool

A comprehensive Python-based security auditing tool for Drupal 11 applications that performs:
- Composer dependency vulnerability scanning
- PHPCS static code analysis with Drupal coding standards
- NPM package security auditing for custom themes
- Secret detection using Gitleaks

## Prerequisites

Before running this script, ensure you have the following installed on your system:

### Required

1. **Python 3.6+**
   ```bash
   python3 --version
   ```

2. **Composer** (for Drupal dependency management)
   ```bash
   composer --version
   ```
   
   Installation: https://getcomposer.org/download/

3. **Gitleaks** (for secret scanning)
   ```bash
   gitleaks version
   ```
   
   Installation:
   ```bash
   # macOS
   brew install gitleaks
   
   # Linux
   wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
   tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
   sudo mv gitleaks /usr/local/bin/
   
   # Windows
   # Download from: https://github.com/gitleaks/gitleaks/releases
   ```

### Optional (for NPM scanning)

4. **Node.js and NPM** (if scanning custom themes with JavaScript dependencies)
   ```bash
   npm --version
   ```
   
   Installation: https://nodejs.org/

## Installation

1. **Download the script**
   ```bash
   wget https://raw.githubusercontent.com/your-repo/drupal_security_audit.py
   # OR
   curl -O https://raw.githubusercontent.com/your-repo/drupal_security_audit.py
   ```

2. **Make it executable**
   ```bash
   chmod +x drupal_security_audit.py
   ```

3. **Verify installation**
   ```bash
   python3 drupal_security_audit.py --help
   ```

## Usage

### Basic Syntax

```bash
python3 drupal_security_audit.py [DRUPAL_ROOT] [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `drupal_root` | Yes | Path to your Drupal root directory (where composer.json is located) |
| `--phpcs-paths` | No | Space-separated list of paths to run PHPCS on (relative to drupal_root) |
| `--themes-path` | No | Path to custom themes directory for NPM security scanning |
| `--output` | No | Output file path for JSON audit report |

### Examples

#### 1. Minimal Audit (Composer + Gitleaks only)

```bash
python3 drupal_security_audit.py /var/www/drupal
```

This runs:
- ✓ Composer security audit
- ✗ PHPCS (skipped - no paths specified)
- ✗ NPM audit (skipped - no themes path specified)
- ✓ Gitleaks secret scanning

#### 2. Full Audit with Custom Modules

```bash
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom web/themes/custom
```

This runs PHPCS on:
- `web/modules/custom`
- `web/themes/custom`

#### 3. Full Audit with NPM Scanning

```bash
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom
```

This additionally scans all `package.json` files in `web/themes/custom` recursively.

#### 4. Complete Audit with JSON Report

```bash
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom web/profiles/custom \
  --themes-path web/themes/custom \
  --output /tmp/audit-report-$(date +%Y%m%d).json
```

This runs all checks and saves a detailed JSON report.

#### 5. Audit Specific Directories Only

```bash
# Only scan a specific module
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom/my_module

# Scan multiple specific paths
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom/module1 web/modules/custom/module2 web/themes/custom/mytheme
```

## What the Script Does

### 1. Composer Security Audit

- Runs `composer audit` to check all PHP dependencies
- Identifies known security vulnerabilities in:
  - Drupal core
  - Contributed modules
  - Third-party PHP libraries
- Reports CVE numbers, severity levels, and fix recommendations

**Sample Output:**
```
================================================================================
                        COMPOSER SECURITY AUDIT                         
================================================================================

Running composer audit...
✗ Found security vulnerabilities:

Package: drupal/core
Title: Drupal core - Critical - Access bypass
Severity: critical
CVE: CVE-2023-12345
Link: https://www.drupal.org/sa-core-2023-001
--------------------------------------------------------------------------------

Total vulnerabilities found: 3
```

### 2. PHPCS Static Code Analysis

- Automatically installs PHPCS and Drupal Coder if not present
- Analyzes PHP code against:
  - Drupal coding standards
  - DrupalPractice standards
- Scans: `.php`, `.module`, `.inc`, `.install`, `.test`, `.profile`, `.theme` files
- Reports coding standard violations, potential bugs, and best practice issues

**Sample Output:**
```
================================================================================
                       PHPCS STATIC CODE ANALYSIS                       
================================================================================

Analyzing: web/modules/custom
Found 15 errors and 42 warnings
  Line 45: Missing function documentation comment (Drupal.Commenting.FunctionComment.Missing)
  Line 67: Expected 1 space after CASE keyword; 0 found (Drupal.WhiteSpace.ControlStructureSpacing.SpacingAfterCase)
  ... and more issues
```

### 3. NPM Package Security Audit

- Recursively finds all `package.json` files in custom themes
- Runs `npm audit` on each theme
- Identifies vulnerable JavaScript dependencies
- Reports severity levels (Critical, High, Moderate, Low)

**Sample Output:**
```
================================================================================
                       NPM PACKAGE SECURITY AUDIT                       
================================================================================

Found 2 package.json file(s)

Scanning theme: mytheme
  Path: mytheme/package.json
  ✗ Found 8 vulnerabilities
    Critical: 1
    High: 2
    Moderate: 4
    Low: 1
```

### 4. Gitleaks Secret Scanning

- Scans entire codebase for exposed secrets
- Detects:
  - API keys
  - Passwords
  - Database credentials
  - Private keys
  - OAuth tokens
  - Generic secrets
- Creates detailed report of findings

**Sample Output:**
```
================================================================================
                       GITLEAKS SECRET SCANNING                         
================================================================================

Scanning for secrets with gitleaks...
✗ Found 3 potential secret(s):

Finding #1:
  File: web/modules/custom/my_module/config/settings.php
  Rule: Generic API Key
  Line: 23
  Secret: api_key_abc123def456...
--------------------------------------------------------------------------------

Full report saved to: /var/www/drupal/gitleaks-report.json
```

### 5. Audit Summary

At the end, you'll see a comprehensive summary:

```
================================================================================
                              AUDIT SUMMARY                              
================================================================================

✓ Composer Security Audit: PASSED
✗ PHPCS Code Analysis: FAILED
⊘ NPM Security Audit: SKIPPED
✓ Gitleaks Secret Scan: PASSED

Overall Status: ✗ 1 CHECK(S) FAILED
```

## Automated Dependencies Installation

The script automatically handles dependency installation:

1. **PHPCS**: If not found in `vendor/bin/phpcs`, it will be installed via Composer
2. **Drupal Coder**: Automatically installed to provide Drupal coding standards
3. **PHPCS Standards**: Configured to use Drupal and DrupalPractice rulesets

You don't need to manually install these - the script handles it!

## Output Files

### JSON Audit Report

When using `--output`, a comprehensive JSON report is generated with structure:

```json
{
  "timestamp": "2024-02-14T10:30:00",
  "drupal_root": "/var/www/drupal",
  "composer_audit": {
    "status": "failed",
    "vulnerabilities_count": 3,
    "details": { ... }
  },
  "phpcs_analysis": {
    "status": "passed",
    "paths": { ... }
  },
  "npm_security": {
    "status": "passed",
    "themes_scanned": 2,
    "themes": { ... }
  },
  "gitleaks": {
    "status": "failed",
    "secrets_found": 5,
    "report_path": "/var/www/drupal/gitleaks-report.json"
  }
}
```

### Gitleaks Report

If secrets are found, a detailed `gitleaks-report.json` is created in the Drupal root with:
- File paths
- Line numbers
- Secret types
- Matched content

## Exit Codes

The script returns appropriate exit codes for CI/CD integration:

- `0`: All audits passed
- `1`: One or more audits failed or encountered errors

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Drupal Security Audit

on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install Gitleaks
        run: |
          wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
          sudo mv gitleaks /usr/local/bin/
      
      - name: Install Composer dependencies
        run: composer install
      
      - name: Run Security Audit
        run: |
          python3 drupal_security_audit.py . \
            --phpcs-paths web/modules/custom \
            --themes-path web/themes/custom \
            --output audit-report.json
      
      - name: Upload Audit Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-audit-report
          path: audit-report.json
```

### GitLab CI Example

```yaml
security_audit:
  stage: test
  image: php:8.1
  before_script:
    - apt-get update && apt-get install -y python3 wget
    - wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
    - tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
    - mv gitleaks /usr/local/bin/
    - composer install
  script:
    - python3 drupal_security_audit.py . --phpcs-paths web/modules/custom --output audit-report.json
  artifacts:
    paths:
      - audit-report.json
    when: always
```

## Troubleshooting

### "Composer is not installed"

Install Composer from https://getcomposer.org/download/

### "Gitleaks is not installed"

Follow the installation instructions in the Prerequisites section.

### "No composer.json found"

Ensure you're pointing to the correct Drupal root directory (where `composer.json` exists).

### PHPCS installation fails

Try manually installing:
```bash
cd /path/to/drupal
composer require --dev squizlabs/php_codesniffer
composer require --dev drupal/coder
```

### NPM audit fails

Ensure Node.js and npm are installed:
```bash
node --version
npm --version
```

If npm is installed but themes fail, try running `npm install` in the theme directory first.

### Permission denied errors

Make sure the script has execute permissions:
```bash
chmod +x drupal_security_audit.py
```

And that you have read/write access to the Drupal directory.

## Best Practices

1. **Run regularly**: Schedule audits weekly or before deployments
2. **Version control**: Don't commit the JSON reports or gitleaks reports
3. **Fix secrets immediately**: If Gitleaks finds secrets, rotate them and remove from git history
4. **Update dependencies**: Address Composer vulnerabilities promptly
5. **Address PHPCS issues**: Fix coding standard violations to maintain code quality
6. **Monitor NPM packages**: Keep JavaScript dependencies updated

## Customization

### Skip Specific PHPCS Rules

Create a `phpcs.xml` in your Drupal root:

```xml
<?xml version="1.0"?>
<ruleset name="Custom">
  <rule ref="Drupal"/>
  <rule ref="DrupalPractice"/>
  
  <!-- Exclude specific rules -->
  <rule ref="Drupal.Commenting.FunctionComment">
    <exclude name="Drupal.Commenting.FunctionComment.Missing"/>
  </rule>
</ruleset>
```

Then the script will use this configuration automatically.

### Exclude Files from Gitleaks

Create a `.gitleaksignore` file in your Drupal root:

```
# Ignore test files
tests/**
*.test

# Ignore specific files
web/sites/default/settings.local.php
```

## License

MIT License - Feel free to use and modify as needed.

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Check Drupal security advisories: https://www.drupal.org/security
- Gitleaks documentation: https://github.com/gitleaks/gitleaks

## Changelog

### Version 1.0.0 (2024-02-14)
- Initial release
- Composer audit support
- PHPCS integration with Drupal standards
- NPM package scanning
- Gitleaks secret detection
- JSON report generation
- Color-coded terminal output
