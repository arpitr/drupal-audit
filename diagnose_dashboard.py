#!/usr/bin/env python3
"""
Diagnostic script to check Composer vulnerability data
"""

import sqlite3
import json
import os
from pathlib import Path

# Database path
db_path = Path.home() / '.drupal_audit' / 'audit_history.db'

if not db_path.exists():
    print(f"❌ Database not found at: {db_path}")
    print("Run an audit first to create the database.")
    exit(1)

print(f"✓ Found database: {db_path}\n")

# Connect to database
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Get latest audit run
cursor.execute('''
    SELECT id, timestamp, drupal_root 
    FROM audit_runs 
    ORDER BY created_at DESC 
    LIMIT 1
''')

latest = cursor.fetchone()

if not latest:
    print("❌ No audit runs found in database")
    exit(1)

audit_id, timestamp, drupal_root = latest
print(f"Latest Audit Run:")
print(f"  ID: {audit_id}")
print(f"  Timestamp: {timestamp}")
print(f"  Drupal Root: {drupal_root}\n")

# Get composer audit data
cursor.execute('''
    SELECT 
        status, 
        total_vulnerabilities, 
        critical_count, 
        high_count, 
        moderate_count, 
        low_count,
        details
    FROM composer_audits 
    WHERE audit_run_id = ?
''', (audit_id,))

composer = cursor.fetchone()

if composer:
    status, total, critical, high, moderate, low, details_json = composer
    
    print(f"Composer Audit (from database):")
    print(f"  Status: {status}")
    print(f"  Total Vulnerabilities: {total}")
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Moderate: {moderate}")
    print(f"  Low: {low}\n")
    
    # Parse details JSON
    try:
        details = json.loads(details_json)
        
        print(f"Raw Details Structure:")
        print(f"  Keys in details: {list(details.keys())}\n")
        
        if 'vulnerabilities' in details:
            vulns = details['vulnerabilities']
            print(f"  Number of vulnerabilities in details: {len(vulns)}")
            
            if len(vulns) > 0:
                print(f"\n  First vulnerability sample:")
                first = vulns[0]
                for key, value in first.items():
                    print(f"    {key}: {value}")
                
                # Count severities manually
                severity_counts = {}
                for vuln in vulns:
                    sev = vuln.get('severity', 'unknown')
                    if sev is None:
                        sev = 'None (will parse from title)'
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                print(f"\n  Severity breakdown from JSON:")
                for sev, count in sorted(severity_counts.items(), key=lambda x: (x[0] is None, x[0])):
                    print(f"    {sev}: {count}")
        
        if 'raw_advisories' in details:
            print(f"\n  Raw advisories present: Yes")
            advisories = details['raw_advisories']
            print(f"  Number of packages with advisories: {len(advisories)}")
    
    except json.JSONDecodeError as e:
        print(f"  ⚠️  Could not parse details JSON: {e}")
else:
    print("❌ No composer audit data found for this run")

# Check dashboard JSON file
dashboard_json = Path(drupal_root) / 'audit-dashboard' / 'audit_data.json'
if dashboard_json.exists():
    print(f"\n✓ Found dashboard JSON: {dashboard_json}")
    
    with open(dashboard_json, 'r') as f:
        dashboard_data = json.load(f)
    
    if 'latest' in dashboard_data and dashboard_data['latest']:
        latest_data = dashboard_data['latest']
        
        if 'composer' in latest_data and latest_data['composer']:
            comp = latest_data['composer']
            print(f"\nComposer data in dashboard JSON:")
            print(f"  Status: {comp.get('status')}")
            print(f"  Total: {comp.get('total')}")
            print(f"  Critical: {comp.get('critical')}")
            print(f"  High: {comp.get('high')}")
            print(f"  Moderate: {comp.get('moderate')}")
            print(f"  Low: {comp.get('low')}")
        else:
            print(f"\n⚠️  No composer data in dashboard JSON 'latest' section")
    else:
        print(f"\n⚠️  No 'latest' data in dashboard JSON")
else:
    print(f"\n⚠️  Dashboard JSON not found at: {dashboard_json}")

conn.close()

print("\n" + "="*60)
print("Diagnosis Complete")
print("="*60)
print("\nIf severity counts are 0 but vulnerabilities exist:")
print("1. The severity field might be missing or named differently")
print("2. Run the audit again with the updated script")
print("3. Check the 'First vulnerability sample' above for field names")
