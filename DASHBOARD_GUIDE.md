# Dashboard User Guide

## 🎯 Quick Start

### 1. Run Your First Audit

```bash
# Navigate to your Drupal project
cd /path/to/drupal

# Run the audit
python3 drupal_security_audit.py . \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom
```

### 2. Open the Dashboard

After the audit completes, you'll see:

```
✓ Dashboard generated: /path/to/drupal/audit-dashboard/index.html
  Open in browser: file:///path/to/drupal/audit-dashboard/index.html
```

Open this file in your web browser.

## 📊 Dashboard Components

### Overview Cards (Top Row)

Four main cards showing current status:

1. **Composer Security**
   - Total vulnerabilities
   - Breakdown: Critical, High, Moderate, Low
   - Status badge (Passed/Failed)
   - Comparison with previous run

2. **Code Quality (PHPCS)**
   - Total errors
   - Total warnings
   - Comparison with previous run

3. **NPM Security**
   - Total vulnerabilities
   - Breakdown by severity
   - Comparison with previous run

4. **Secret Detection**
   - Number of secrets found
   - Comparison with previous run

### Comparison Badges

Each metric shows how it changed from the last run:

- **Green badge "−5 ↓"** = Improved (5 fewer issues)
- **Red badge "+3 ↑"** = Worsened (3 more issues)
- **Gray badge "No change"** = Same as before

### Severity Breakdown Charts

Bar charts showing vulnerability distribution:

- **Composer Vulnerabilities** - PHP package issues
- **NPM Vulnerabilities** - JavaScript package issues
- **PHPCS Issues** - Code quality problems
- **Secrets Found** - Exposed credentials

Hover over bars to see exact counts.

### Trend Charts

**Vulnerability Trends Over Time**
- Red line: Composer vulnerabilities
- Orange line: NPM vulnerabilities
- Purple line: Secrets found

**Code Quality Trends**
- Red line: PHPCS errors
- Orange line: PHPCS warnings

Hover over data points to see:
- Exact value
- Date of that audit run

## 🔄 Understanding Trends

### Good Trends (Lines Going Down)
- Vulnerabilities decreasing over time
- Fewer secrets being exposed
- Code quality improving

### Bad Trends (Lines Going Up)
- New vulnerabilities being introduced
- More secrets accidentally committed
- Code quality degrading

### Stable Trends (Flat Lines)
- No new issues (good if at zero)
- Issues not being addressed (bad if above zero)

## 📈 Use Cases

### 1. Weekly Security Review

```bash
# Run audit every Monday
python3 drupal_security_audit.py /var/www/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom

# Open dashboard and review:
# - Did vulnerabilities decrease?
# - Were new secrets introduced?
# - Is code quality improving?
```

### 2. Pre-Deployment Check

```bash
# Before deploying to production
python3 drupal_security_audit.py .

# Check dashboard for:
# - Zero critical/high vulnerabilities
# - No secrets found
# - Acceptable error count
```

### 3. Sprint Retrospective

```bash
# At end of sprint, review dashboard
# - Did we improve security?
# - Did we fix more issues than we created?
# - What's our trend direction?
```

## 💾 Database Information

### Where is data stored?

```
~/.drupal_audit/audit_history.db
```

This SQLite database contains:
- All audit run history
- Detailed vulnerability data
- Trend data for charts

### How much data is kept?

- Dashboard shows last 30 runs
- Database keeps all history indefinitely
- You can manually clean old data if needed

### Can I share the dashboard?

Yes! The dashboard folder is self-contained:

```bash
# Copy dashboard to web server
cp -r audit-dashboard /var/www/html/security-reports/

# Now accessible at:
# https://yoursite.com/security-reports/
```

**Note**: The dashboard is static HTML/JavaScript. No server-side processing needed.

## 🔧 Advanced Usage

### Custom Database Location

```bash
python3 drupal_security_audit.py . \
  --db-path /shared/team-audits/drupal.db
```

Use this for:
- Shared team dashboards
- Network storage
- Backup purposes

### Disable Dashboard (CLI Only)

```bash
python3 drupal_security_audit.py . --no-dashboard
```

Use when:
- Running in CI/CD (no browser)
- You only want JSON output
- Minimal overhead needed

### View Historical Data

Query the database directly:

```bash
sqlite3 ~/.drupal_audit/audit_history.db

# List all audit runs
SELECT timestamp, overall_status FROM audit_runs ORDER BY timestamp DESC;

# Get vulnerability counts over time
SELECT 
  timestamp,
  total_vulnerabilities 
FROM audit_runs ar
JOIN composer_audits ca ON ar.id = ca.audit_run_id
ORDER BY timestamp;
```

## 🎨 Dashboard Customization

The dashboard reads from `audit_data.json`. You can:

1. **Modify the template** - Edit `dashboard_template.html`
2. **Add custom charts** - Use D3.js to create new visualizations
3. **Change colors** - Update the color scheme in the `<style>` section
4. **Add metrics** - Extend the database schema and update queries

## 📱 Mobile Viewing

The dashboard is responsive and works on:
- Desktop browsers (Chrome, Firefox, Safari, Edge)
- Tablets
- Mobile phones

## 🐛 Troubleshooting

### Dashboard shows "No data"

**Solution**: Make sure `audit_data.json` exists in the same folder

```bash
ls audit-dashboard/
# Should show: index.html and audit_data.json
```

### Charts not rendering

**Possible causes**:
1. JavaScript disabled in browser
2. File opened from restricted location
3. Ad blocker blocking D3.js CDN

**Solution**: 
- Enable JavaScript
- Copy dashboard to web server
- Whitelist d3js.org

### "Previous run" comparison not showing

**Cause**: This is your first audit run

**Solution**: Run the audit again to see comparisons

### Old data showing

**Solution**: Hard refresh the page
- Windows/Linux: `Ctrl + Shift + R`
- Mac: `Cmd + Shift + R`

## 📊 Interpreting the Data

### What's a "good" score?

**Excellent**:
- 0 critical/high vulnerabilities
- 0 secrets found
- < 10 PHPCS errors
- < 50 PHPCS warnings

**Acceptable**:
- 0 critical vulnerabilities
- < 3 high vulnerabilities
- 0 secrets found
- < 50 PHPCS errors

**Needs Attention**:
- Any critical vulnerabilities
- Any secrets found
- > 100 PHPCS errors

### Prioritization

Fix in this order:
1. **Secrets** (immediate)
2. **Critical vulnerabilities** (this week)
3. **High vulnerabilities** (this sprint)
4. **PHPCS errors** (ongoing)
5. **Moderate/Low vulnerabilities** (backlog)
6. **PHPCS warnings** (code cleanup)

## 🚀 Best Practices

1. **Run regularly** - Weekly at minimum
2. **Track trends** - Don't just look at current numbers
3. **Set goals** - Aim to reduce issues over time
4. **Share dashboards** - Make security visible to the team
5. **Act on data** - Don't just collect metrics, fix issues
6. **Celebrate wins** - Acknowledge when trends improve

## 📞 Getting Help

If you encounter issues:

1. Check this guide
2. Review the main README.md
3. Check browser console for JavaScript errors
4. Verify database file exists and is readable
5. Try running with `--no-dashboard` to isolate issues

## 🎯 Next Steps

1. ✅ Run your first audit
2. ✅ Open the dashboard
3. ✅ Review the current status
4. ✅ Run another audit in a week
5. ✅ Compare trends
6. ✅ Set improvement goals
7. ✅ Track progress monthly

Happy auditing! 🔒
