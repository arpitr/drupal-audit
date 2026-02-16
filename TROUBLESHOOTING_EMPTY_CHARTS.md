# Troubleshooting Empty Dashboard Charts

## Problem: Composer Severity Chart Shows Empty

Even though vulnerabilities exist in the JSON report, the dashboard chart is empty.

## Root Cause

The severity counts weren't being properly extracted and stored in the database. This happens when:

1. The `severity` field is missing from vulnerability data
2. The severity field has a different name (e.g., `Severity` vs `severity`)
3. Old database records were created before the fix

## Solution Steps

### Step 1: Diagnose the Issue

Run the diagnostic script to see what's in your database:

```bash
python3 diagnose_dashboard.py
```

This will show you:
- What's stored in the database
- What's in the dashboard JSON
- Sample vulnerability structure
- Where the mismatch is occurring

**Look for:**
```
Composer Audit (from database):
  Critical: 0
  High: 0
  Moderate: 0
  Low: 0

But also:
  Number of vulnerabilities in details: 5  ← Vulnerabilities exist!
```

### Step 2: Fix Existing Records (If Needed)

If you have old audit runs with incorrect counts:

```bash
python3 fix_severity_counts.py
```

This will:
- Read all existing composer audits
- Recount severities from the stored details
- Update the database with correct counts

### Step 3: Run Fresh Audit

Use the updated script to run a new audit:

```bash
python3 drupal_security_audit.py /path/to/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom
```

**Look for this output:**
```
Dashboard Export - Composer Severity Counts:
  Critical: 1
  High: 3
  Moderate: 4
  Low: 2
```

If you see counts here, the dashboard should now work!

### Step 4: Verify Dashboard

1. Open the dashboard:
   ```bash
   cd /path/to/drupal/audit-dashboard
   python3 -m http.server 8000
   ```

2. Open browser: `http://localhost:8000`

3. Check the Composer Severity chart - should now show bars!

## Quick Fix Commands

```bash
# Full fix process
cd /path/to/your/scripts

# 1. Diagnose
python3 diagnose_dashboard.py

# 2. Fix old records
python3 fix_severity_counts.py

# 3. Run fresh audit
python3 drupal_security_audit.py /path/to/drupal

# 4. View dashboard
cd /path/to/drupal/audit-dashboard
python3 -m http.server 8000
# Open: http://localhost:8000
```

## Manual Database Check

Verify the fix worked:

```bash
sqlite3 ~/.drupal_audit/audit_history.db

# Check latest composer audit
SELECT 
  ca.total_vulnerabilities,
  ca.critical_count,
  ca.high_count,
  ca.moderate_count,
  ca.low_count
FROM composer_audits ca
JOIN audit_runs ar ON ca.audit_run_id = ar.id
ORDER BY ar.created_at DESC
LIMIT 1;
```

**Expected output:**
```
5|1|2|1|1  ← Shows actual counts, not all zeros
```

## Check Dashboard JSON

```bash
cat /path/to/drupal/audit-dashboard/audit_data.json | python3 -m json.tool
```

Look for:
```json
{
  "latest": {
    "composer": {
      "status": "failed",
      "total": 5,
      "critical": 1,
      "high": 2,
      "moderate": 1,
      "low": 1
    }
  }
}
```

If `critical`, `high`, etc. are all 0 but `total` is > 0, the issue persists.

## Understanding the Fix

### Before (Broken):
```python
# Old code - missed severities if field was missing
counts = {'critical': 0, ...}
for vuln in vulnerabilities:
    severity = vuln.get('severity', '').lower()  # Returns '' if missing
    if severity in counts:  # '' not in counts, so skipped!
        counts[severity] += 1
```

### After (Fixed):
```python
# New code - handles missing/different field names
for vuln in vulnerabilities:
    severity = None
    if 'severity' in vuln:
        severity = vuln['severity']
    elif 'Severity' in vuln:  # Try capitalized version
        severity = vuln['Severity']
    
    if severity:
        severity = str(severity).lower().strip()
        # Normalize variations
        if severity in ['critical', 'crit']:
            counts['critical'] += 1
        # ... etc
```

## Common Issues

### Issue 1: Still Empty After Fix

**Cause:** Browser cached old data

**Solution:**
```bash
# Hard refresh
# Chrome/Firefox: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)

# Or clear specific cache
rm /path/to/drupal/audit-dashboard/audit_data.json
python3 drupal_security_audit.py /path/to/drupal
```

### Issue 2: Some Severities Show, Others Don't

**Cause:** Severity values don't match expected format

**Solution:** Run diagnostic script to see actual severity values:
```bash
python3 diagnose_dashboard.py
```

Look at the "First vulnerability sample" section to see the exact field names and values.

### Issue 3: Database Shows Counts, Dashboard Doesn't

**Cause:** Dashboard JSON not regenerated

**Solution:**
```bash
# Delete old dashboard
rm -rf /path/to/drupal/audit-dashboard

# Run audit again
python3 drupal_security_audit.py /path/to/drupal
```

### Issue 4: "TypeError: 'NoneType' object is not iterable"

**Cause:** No vulnerabilities list in details

**Solution:** This is normal if no vulnerabilities found. The fix handles this gracefully.

## Verification Checklist

- [ ] Diagnostic script shows vulnerability count > 0
- [ ] Diagnostic script shows severity counts > 0
- [ ] Fresh audit shows "Dashboard Export - Composer Severity Counts"
- [ ] Database query shows non-zero counts
- [ ] Dashboard JSON has non-zero severity counts
- [ ] Browser hard-refreshed (Ctrl+Shift+R)
- [ ] Dashboard chart displays bars

## Still Not Working?

If charts are still empty after all fixes:

1. **Check browser console** (F12):
   ```
   Look for JavaScript errors
   Check if D3.js loaded successfully
   ```

2. **Verify data structure**:
   ```bash
   cat /path/to/drupal/audit-dashboard/audit_data.json | \
     python3 -c "import sys, json; d=json.load(sys.stdin); \
     print('Composer total:', d['latest']['composer']['total']); \
     print('Composer critical:', d['latest']['composer']['critical'])"
   ```

3. **Test with sample data**:
   Edit `audit_data.json` manually and set:
   ```json
   "composer": {
     "status": "failed",
     "total": 10,
     "critical": 2,
     "high": 3,
     "moderate": 3,
     "low": 2
   }
   ```
   
   Refresh dashboard. If it works now, the issue is in data generation.

4. **Share diagnostic output**:
   ```bash
   python3 diagnose_dashboard.py > diagnosis.txt
   ```
   
   Review `diagnosis.txt` for clues.

## Prevention

To prevent this issue in the future:

1. **Always use the updated script** with improved severity counting
2. **Run diagnostics periodically** to catch issues early
3. **Check dashboard after each audit** to verify data appears
4. **Keep database backups** before major changes

## Getting Help

If none of these solutions work, gather:

1. Output of `python3 diagnose_dashboard.py`
2. Output of database query showing composer_audits table
3. Content of `audit_data.json`
4. Browser console errors (F12)
5. Any error messages during audit run
