# 🎉 Drupal Security Audit Tool - Enhanced Edition

## What's New - Database & Dashboard Features

### ✨ Major Enhancements

Your Drupal security audit tool now includes:

1. **📊 Interactive D3.js Dashboard**
   - Beautiful visualizations with charts and graphs
   - Real-time data rendering
   - Responsive design (works on mobile too!)

2. **💾 SQLite Database Storage**
   - Automatic history tracking
   - Query audit data with SQL
   - No configuration needed

3. **📈 Trend Analysis**
   - See security improvements over time
   - Track vulnerability patterns
   - Identify recurring issues

4. **🔄 Run Comparisons**
   - Automatic comparison with previous audit
   - Highlighted improvements/regressions
   - Color-coded change indicators

## Quick Comparison

### Before (Original Version)
```bash
python3 drupal_security_audit.py /path/to/drupal
# ✓ Runs audit
# ✓ Shows results in terminal
# ✓ Optionally saves JSON report
```

### After (Enhanced Version)
```bash
python3 drupal_security_audit.py /path/to/drupal
# ✓ Runs audit
# ✓ Shows results in terminal with comparison
# ✓ Saves to SQLite database automatically
# ✓ Generates interactive dashboard
# ✓ Optionally saves JSON report
# ✓ Opens in browser for visualization
```

## New Command-Line Options

```bash
python3 drupal_security_audit.py <drupal_root> [options]

New Options:
  --db-path PATH       Custom database location
  --no-dashboard       Disable dashboard (use for CI/CD)
```

## File Structure

After running the enhanced version:

```
Your System:
  ~/.drupal_audit/
    └── audit_history.db          # SQLite database with all history

Your Drupal Project:
  /path/to/drupal/
    ├── audit-dashboard/
    │   ├── index.html            # Interactive dashboard
    │   └── audit_data.json       # Latest audit data (JSON)
    └── gitleaks-report.json      # If secrets found (same as before)
```

## Dashboard Features Breakdown

### 1. Overview Cards

Four summary cards at the top showing:

**Composer Security**
- Total vulnerabilities: 8 (+2 ↑)
- Critical: 1
- High: 3
- Moderate: 3
- Low: 1
- Status: Failed

**Code Quality (PHPCS)**
- Errors: 15 (−10 ↓)
- Warnings: 42
- Status: Passed

**NPM Security**
- Total vulnerabilities: 0 (No change)
- Status: Passed

**Secret Detection**
- Secrets found: 0 (−3 ↓)
- Status: Passed

### 2. Severity Breakdown Charts

Bar charts showing:
- **Composer Vulnerabilities** - By severity (Critical/High/Moderate/Low)
- **NPM Vulnerabilities** - By severity
- **PHPCS Issues** - Errors vs Warnings
- **Secrets** - Total count

Interactive features:
- Hover to see exact numbers
- Color-coded by severity
- Automatically scaled

### 3. Trend Line Charts

**Vulnerability Trends Over Time**
- Shows last 30 audit runs
- Three lines:
  - 🔴 Composer vulnerabilities
  - 🟠 NPM vulnerabilities  
  - 🟣 Secrets found
- Hover on points to see date and value

**Code Quality Trends**
- PHPCS errors and warnings over time
- Two lines:
  - 🔴 Errors
  - 🟠 Warnings

### 4. Comparison Indicators

Every metric shows change from previous run:

- **Green badge "−5 ↓"** = 5 fewer issues (improvement)
- **Red badge "+3 ↑"** = 3 more issues (regression)
- **Gray badge "No change"** = Same as last time

## Database Schema

The SQLite database includes 5 tables:

1. **audit_runs** - Main metadata
   - id, timestamp, drupal_root, duration, overall_status

2. **composer_audits** - PHP security
   - total_vulnerabilities, critical_count, high_count, moderate_count, low_count

3. **phpcs_audits** - Code quality
   - total_errors, total_warnings, files_scanned

4. **npm_audits** - JavaScript security
   - total_vulnerabilities, critical_count, high_count, moderate_count, low_count

5. **gitleaks_audits** - Secret detection
   - secrets_found

## Usage Examples

### Example 1: First Audit Run

```bash
python3 drupal_security_audit.py /var/www/drupal
```

Output:
```
✓ Composer Security Audit: PASSED
✓ PHPCS Code Analysis: PASSED
✓ NPM Security Audit: PASSED
✓ Gitleaks Secret Scan: PASSED

Overall Status: ✓ ALL CHECKS PASSED

✓ Audit results saved to database (Run ID: 1)
✓ Dashboard generated: /var/www/drupal/audit-dashboard/index.html
  Open in browser: file:///var/www/drupal/audit-dashboard/index.html
```

### Example 2: Second Audit Run (Shows Comparison)

```bash
python3 drupal_security_audit.py /var/www/drupal
```

Output:
```
✓ Composer Security Audit: FAILED
✗ PHPCS Code Analysis: FAILED
✓ NPM Security Audit: PASSED
✓ Gitleaks Secret Scan: PASSED

Comparison with Previous Run:
Previous run: 2024-02-13T10:30:00
  Composer: +2 vulnerabilities (0 → 2) ↑
  PHPCS: +5 errors (0 → 5) ↑
  NPM: No change (0 vulnerabilities)
  Gitleaks: No change (0 secrets)

Overall Status: ✗ 2 CHECK(S) FAILED

✓ Audit results saved to database (Run ID: 2)
✓ Dashboard updated
```

### Example 3: CI/CD Mode (No Dashboard)

```bash
python3 drupal_security_audit.py /var/www/drupal \
  --no-dashboard \
  --output report.json
```

Use this in automated pipelines where you don't need visualization.

### Example 4: Custom Database Location

```bash
python3 drupal_security_audit.py /var/www/drupal \
  --db-path /shared/audits/team-drupal.db
```

Use this for:
- Team shared dashboards
- Network storage
- Multiple projects

## Viewing the Dashboard

### Option 1: Auto-Open (Recommended)

The script tells you where the dashboard is:
```
✓ Dashboard generated: /path/to/drupal/audit-dashboard/index.html
  Open in browser: file:///path/to/drupal/audit-dashboard/index.html
```

Just click the link or copy-paste into your browser.

### Option 2: Manual Open

```bash
# macOS
open /path/to/drupal/audit-dashboard/index.html

# Linux
xdg-open /path/to/drupal/audit-dashboard/index.html

# Windows
start /path/to/drupal/audit-dashboard/index.html
```

### Option 3: Serve via Web Server

```bash
# Copy dashboard to web root
cp -r audit-dashboard /var/www/html/security-reports/

# Access via browser
# https://yoursite.com/security-reports/
```

## Technical Details

### Technologies Used

- **Backend**: Python 3.6+ with SQLite3
- **Frontend**: D3.js v7 for visualizations
- **Styling**: Pure CSS (no frameworks)
- **Data Format**: JSON

### Performance

- Dashboard loads instantly (client-side only)
- Database queries are milliseconds
- Supports hundreds of audit runs
- No server required

### Browser Compatibility

Works on:
- ✅ Chrome/Edge (v90+)
- ✅ Firefox (v88+)
- ✅ Safari (v14+)
- ✅ Mobile browsers

### Data Privacy

- All data stored locally
- No external services contacted
- No analytics or tracking
- Dashboard works offline

## Migration from Original Version

### If you're upgrading:

1. **Backup existing JSON reports** (if any)
   ```bash
   cp audit-report.json audit-report-backup.json
   ```

2. **Replace the script**
   ```bash
   mv drupal_security_audit.py drupal_security_audit.py.old
   # Download new version
   wget https://your-repo/drupal_security_audit.py
   ```

3. **Download dashboard template**
   ```bash
   wget https://your-repo/dashboard_template.html
   ```

4. **Run first audit**
   ```bash
   python3 drupal_security_audit.py /path/to/drupal
   ```

### Backward Compatibility

The enhanced version is 100% backward compatible:

- All original command-line options work
- JSON output format unchanged
- Terminal output enhanced (not changed)
- Add `--no-dashboard` to get original behavior

## Common Workflows

### Weekly Security Review

```bash
#!/bin/bash
# weekly-audit.sh

python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom

echo "Dashboard available at: /var/www/drupal/audit-dashboard/index.html"
```

Schedule with cron:
```bash
0 9 * * 1 /path/to/weekly-audit.sh
```

### Pre-Production Deployment

```bash
#!/bin/bash
# pre-deploy-check.sh

python3 drupal_security_audit.py /var/www/drupal

# Check if critical issues exist
if [ $? -ne 0 ]; then
  echo "❌ Security audit failed. Fix issues before deploying."
  exit 1
fi

echo "✅ Security audit passed. Safe to deploy."
```

### Team Dashboard

```bash
# Run on shared server
python3 drupal_security_audit.py /var/www/drupal \
  --db-path /shared/drupal-audit.db

# Dashboard accessible to all team members
cp -r audit-dashboard /var/www/html/team-security/
```

## Troubleshooting

### Issue: Dashboard shows no data

**Solution**: Ensure `audit_data.json` exists
```bash
ls audit-dashboard/
# Should show: index.html and audit_data.json
```

### Issue: Charts not rendering

**Solutions**:
1. Check JavaScript console for errors
2. Ensure d3js.org is not blocked
3. Try different browser
4. Disable ad blockers

### Issue: "Database is locked"

**Solution**: Only one instance can write at a time
```bash
# Use different database file
python3 drupal_security_audit.py . --db-path /tmp/audit.db
```

### Issue: Dashboard template not found

**Solution**: Place `dashboard_template.html` in same directory as script
```bash
ls -la drupal_security_audit.py dashboard_template.html
# Both should be in same directory
```

## What You Get

### Files Included

1. **drupal_security_audit.py** - Enhanced main script
2. **dashboard_template.html** - D3.js dashboard template
3. **README_WITH_DASHBOARD.md** - Updated documentation
4. **DASHBOARD_GUIDE.md** - Dashboard user guide
5. **Original files** - README.md, QUICKSTART.md, etc.

### What Changed

**Modified**: drupal_security_audit.py
- Added SQLite database support
- Added dashboard generation
- Added comparison logic
- Enhanced summary output

**New**: dashboard_template.html
- Interactive D3.js visualizations
- Responsive design
- Self-contained (works offline)

**New**: Documentation
- Dashboard usage guide
- Updated README
- Examples and workflows

### What Stayed the Same

- All original audit checks (Composer, PHPCS, NPM, Gitleaks)
- Command-line interface
- JSON output format
- Exit codes for CI/CD
- Configuration files (.gitleaksignore, phpcs.xml)

## Next Steps

1. ✅ Download the enhanced version
2. ✅ Place both `.py` and `.html` files together
3. ✅ Run your first audit
4. ✅ Open the dashboard
5. ✅ Run another audit next week
6. ✅ Compare the trends
7. ✅ Set security improvement goals

## Support

For issues or questions:
- Check DASHBOARD_GUIDE.md for usage help
- Review README_WITH_DASHBOARD.md for details
- Check original README.md for audit basics

---

**Happy Auditing with Visualizations! 📊🔒**
