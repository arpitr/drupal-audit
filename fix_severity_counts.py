#!/usr/bin/env python3
"""
Fix existing database records to properly count severity levels
Run this if you have existing audits with incorrect severity counts
"""

import sqlite3
import json
import os
from pathlib import Path

def count_severities(vulnerabilities):
    """Count vulnerabilities by severity"""
    counts = {'critical': 0, 'high': 0, 'moderate': 0, 'low': 0, 'info': 0, 'unknown': 0}
    
    if not vulnerabilities:
        return counts
    
    for vuln in vulnerabilities:
        severity = None
        
        # Try to get severity from direct field
        if 'severity' in vuln and vuln['severity'] is not None:
            severity = vuln['severity']
        elif 'Severity' in vuln and vuln['Severity'] is not None:
            severity = vuln['Severity']
        
        # If no severity field, try to extract from title
        # Drupal advisories format: "Drupal core - Moderately critical - ..."
        if not severity and 'title' in vuln:
            title = str(vuln['title']).lower()
            
            if 'critical' in title:
                if 'moderately critical' in title or 'moderately-critical' in title:
                    severity = 'moderate'
                elif 'highly critical' in title or 'highly-critical' in title:
                    severity = 'critical'
                else:
                    severity = 'critical'
            elif 'important' in title or 'high' in title:
                severity = 'high'
            elif 'moderate' in title or 'medium' in title:
                severity = 'moderate'
            elif 'minor' in title or 'low' in title:
                severity = 'low'
        
        # Normalize severity
        if severity:
            severity = str(severity).lower().strip()
            
            if severity in ['critical', 'crit', 'highly critical', 'highly-critical']:
                counts['critical'] += 1
            elif severity in ['high', 'important']:
                counts['high'] += 1
            elif severity in ['moderate', 'medium', 'mod', 'moderately critical', 'moderately-critical']:
                counts['moderate'] += 1
            elif severity in ['low', 'minor']:
                counts['low'] += 1
            elif severity in ['info', 'informational']:
                counts['info'] += 1
            else:
                counts['unknown'] += 1
        else:
            counts['unknown'] += 1
    
    return counts

# Database path
db_path = Path.home() / '.drupal_audit' / 'audit_history.db'

if not db_path.exists():
    print(f"❌ Database not found at: {db_path}")
    exit(1)

print(f"✓ Found database: {db_path}\n")
print("Fixing severity counts in existing audit records...\n")

# Connect to database
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Get all composer audits
cursor.execute('SELECT id, audit_run_id, details FROM composer_audits')
composer_audits = cursor.fetchall()

fixed_count = 0
skipped_count = 0

for audit_id, run_id, details_json in composer_audits:
    try:
        details = json.loads(details_json)
        vulnerabilities = details.get('vulnerabilities', [])
        
        if not vulnerabilities:
            skipped_count += 1
            continue
        
        # Count severities
        counts = count_severities(vulnerabilities)
        
        # Update the record
        cursor.execute('''
            UPDATE composer_audits
            SET critical_count = ?,
                high_count = ?,
                moderate_count = ?,
                low_count = ?
            WHERE id = ?
        ''', (
            counts['critical'],
            counts['high'],
            counts['moderate'],
            counts['low'],
            audit_id
        ))
        
        print(f"✓ Fixed audit ID {audit_id} (Run {run_id}): "
              f"Critical={counts['critical']}, High={counts['high']}, "
              f"Moderate={counts['moderate']}, Low={counts['low']}")
        
        fixed_count += 1
        
    except json.JSONDecodeError:
        print(f"⚠️  Skipped audit ID {audit_id}: Invalid JSON")
        skipped_count += 1
    except Exception as e:
        print(f"⚠️  Error fixing audit ID {audit_id}: {e}")
        skipped_count += 1

# Commit changes
conn.commit()
conn.close()

print(f"\n{'='*60}")
print(f"Summary:")
print(f"  Fixed: {fixed_count} records")
print(f"  Skipped: {skipped_count} records")
print(f"{'='*60}\n")

if fixed_count > 0:
    print("✓ Database updated successfully!")
    print("\nNext steps:")
    print("1. Run the audit again to regenerate the dashboard")
    print("2. Or manually check: sqlite3 ~/.drupal_audit/audit_history.db")
    print("   SELECT critical_count, high_count FROM composer_audits;")
else:
    print("ℹ️  No records needed fixing")
