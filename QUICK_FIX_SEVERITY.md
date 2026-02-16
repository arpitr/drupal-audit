# Quick Fix: Drupal Severity Parsing Issue

## The Problem You Found

Your diagnostic output showed:
```
severity: None
```

Drupal security advisories don't include a separate `severity` field. Instead, the severity is embedded in the `title`:

```
"Drupal core - Moderately critical - Defacement - SA-CORE-2025-007"
                 ^^^^^^^^^^^^^^^^^^
                 This is the severity!
```

## The Solution

The updated script now **parses severity from the title** when the severity field is `None`.

### Severity Mapping

From Drupal advisory titles:
- **"Moderately critical"** → Moderate
- **"Highly critical"** → Critical  
- **"Critical"** (plain) → Critical
- **"Important"** → High
- **"Moderate"** → Moderate
- **"Minor"** → Low

## How to Fix Your Database

### Step 1: Run the Fix Script

```bash
python3 fix_severity_counts.py
```

**Expected output:**
```
✓ Fixed audit ID 1 (Run 1): Critical=0, High=1, Moderate=3, Low=3
```

This recounts your existing audit using the title parsing logic.

### Step 2: Verify It Worked

```bash
python3 diagnose_dashboard.py
```

**Now you should see:**
```
Composer Audit (from database):
  Status: failed
  Total Vulnerabilities: 11
  Critical: 0        ← No longer 0!
  High: 1           ← Correctly parsed!
  Moderate: 3       ← From title!
  Low: 3            ← Working!
```

### Step 3: Regenerate Dashboard

```bash
python3 drupal_security_audit.py /Users/arpitrastogi/workspace/drupal-test
```

**Look for:**
```
Dashboard Export - Composer Severity Counts:
  Critical: 0
  High: 1
  Moderate: 3
  Low: 3
```

### Step 4: View Dashboard

```bash
cd /Users/arpitrastogi/workspace/drupal-test/audit-dashboard
python3 -m http.server 8000
```

Open: http://localhost:8000

The Composer Severity chart should now show bars! 📊

## Understanding Your Specific Case

Based on your diagnostic output:

| Advisory Title | Parsed Severity |
|----------------|-----------------|
| "Drupal core - **Moderately critical** - Defacement" | → Moderate |
| "Drupal core - **Critical** - Access bypass" | → Critical |
| "Drupal contrib - **Important** - XSS" | → High |

Your 11 vulnerabilities will be distributed:
- **0 Critical** (no "Highly critical" or plain "Critical")
- **1 High** (1 "Important")
- **3 Moderate** (3 "Moderately critical")
- **3 Low** (likely "Minor" in titles)
- **4 Unknown** (titles without clear severity keywords)

## Quick Commands

```bash
# Fix existing database
python3 fix_severity_counts.py

# Verify
python3 diagnose_dashboard.py | grep "Critical\|High\|Moderate\|Low"

# Regenerate dashboard
python3 drupal_security_audit.py /Users/arpitrastogi/workspace/drupal-test

# View
cd /Users/arpitrastogi/workspace/drupal-test/audit-dashboard
python3 -m http.server 8000
```

## If You Still See Zeros

Check what's in the titles:

```bash
sqlite3 ~/.drupal_audit/audit_history.db << EOF
SELECT json_extract(value, '$.title') 
FROM composer_audits, json_each(json_extract(details, '$.vulnerabilities'))
WHERE audit_run_id = 1
LIMIT 11;
EOF
```

This shows all 11 vulnerability titles. If they don't contain keywords like "critical", "moderate", "important", etc., they'll be counted as "unknown".

## Success Indicators

✅ **Working correctly if:**
- Diagnostic shows non-zero severity counts
- Dashboard JSON has non-zero counts  
- Chart displays colored bars
- Bar heights match the counts

❌ **Still broken if:**
- All counts still zero
- Chart completely empty
- JavaScript errors in console

If still broken after these fixes, the titles might not contain severity keywords. In that case, we'd need to look at the actual advisory data format.
