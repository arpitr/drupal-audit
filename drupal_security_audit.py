#!/usr/bin/env python3
"""
Drupal 11 Security Audit Script
================================
This script performs comprehensive security auditing for Drupal 11 applications:
1. Composer audit for security vulnerabilities
2. PHPCS static code analysis
3. NPM package security audit for custom themes
4. Gitleaks scan for exposed secrets

Author: Security Audit Tool
License: MIT
"""

import subprocess
import sys
import os
import json
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class AuditDatabase:
    """Database manager for storing audit history"""
    
    def __init__(self, db_path: str = None):
        """Initialize database connection"""
        if db_path is None:
            db_path = os.path.expanduser('~/.drupal_audit/audit_history.db')
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Create database tables if they don't exist"""
        self.conn = sqlite3.connect(str(self.db_path))
        cursor = self.conn.cursor()
        
        # Main audit runs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                drupal_root TEXT NOT NULL,
                duration_seconds REAL,
                overall_status TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Composer audit results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS composer_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_run_id INTEGER NOT NULL,
                status TEXT,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                moderate_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                details TEXT,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
        ''')
        
        # PHPCS audit results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phpcs_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_run_id INTEGER NOT NULL,
                status TEXT,
                total_errors INTEGER DEFAULT 0,
                total_warnings INTEGER DEFAULT 0,
                files_scanned INTEGER DEFAULT 0,
                paths_scanned TEXT,
                details TEXT,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
        ''')
        
        # PHPStan audit results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phpstan_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_run_id INTEGER NOT NULL,
                status TEXT,
                total_errors INTEGER DEFAULT 0,
                total_file_errors INTEGER DEFAULT 0,
                files_with_errors INTEGER DEFAULT 0,
                files_analyzed INTEGER DEFAULT 0,
                paths_scanned TEXT,
                details TEXT,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
        ''')
        
        # NPM audit results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS npm_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_run_id INTEGER NOT NULL,
                status TEXT,
                themes_scanned INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                moderate_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                details TEXT,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
        ''')
        
        # Gitleaks audit results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gitleaks_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_run_id INTEGER NOT NULL,
                status TEXT,
                secrets_found INTEGER DEFAULT 0,
                details TEXT,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
        ''')
        
        self.conn.commit()
    
    def save_audit_run(self, results: Dict, duration: float) -> int:
        """Save an audit run to the database"""
        cursor = self.conn.cursor()
        
        # Determine overall status
        statuses = [
            results.get('composer_audit', {}).get('status'),
            results.get('phpcs_analysis', {}).get('status'),
            results.get('npm_security', {}).get('status'),
            results.get('gitleaks', {}).get('status')
        ]
        
        failed_count = sum(1 for s in statuses if s == 'failed')
        overall_status = 'failed' if failed_count > 0 else 'passed'
        
        # Insert main audit run
        cursor.execute('''
            INSERT INTO audit_runs (timestamp, drupal_root, duration_seconds, overall_status)
            VALUES (?, ?, ?, ?)
        ''', (
            results['timestamp'],
            results['drupal_root'],
            duration,
            overall_status
        ))
        
        audit_run_id = cursor.lastrowid
        
        # Save composer audit
        composer_data = results.get('composer_audit', {})
        if composer_data:
            vulnerabilities = composer_data.get('vulnerabilities', [])
            severity_counts = self._count_severities(vulnerabilities)
            
            cursor.execute('''
                INSERT INTO composer_audits 
                (audit_run_id, status, total_vulnerabilities, critical_count, 
                 high_count, moderate_count, low_count, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit_run_id,
                composer_data.get('status'),
                composer_data.get('vulnerabilities_count', 0),
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('moderate', 0),
                severity_counts.get('low', 0),
                json.dumps(composer_data)
            ))
        
        # Save PHPCS audit
        phpcs_data = results.get('phpcs_analysis', {})
        if phpcs_data:
            paths = phpcs_data.get('paths', {})
            total_errors = sum(p.get('errors', 0) for p in paths.values())
            total_warnings = sum(p.get('warnings', 0) for p in paths.values())
            
            cursor.execute('''
                INSERT INTO phpcs_audits 
                (audit_run_id, status, total_errors, total_warnings, 
                 files_scanned, paths_scanned, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit_run_id,
                phpcs_data.get('status'),
                total_errors,
                total_warnings,
                len(paths),
                json.dumps(list(paths.keys())),
                json.dumps(phpcs_data)
            ))
        
        # Save PHPStan audit
        phpstan_data = results.get('phpstan_analysis', {})
        if phpstan_data:
            cursor.execute('''
                INSERT INTO phpstan_audits 
                (audit_run_id, status, total_errors, total_file_errors,
                 files_with_errors, files_analyzed, paths_scanned, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit_run_id,
                phpstan_data.get('status'),
                phpstan_data.get('total_errors', 0),
                phpstan_data.get('total_file_errors', 0),
                phpstan_data.get('files_with_errors', 0),
                phpstan_data.get('files_analyzed', 0),
                json.dumps(phpstan_data.get('paths_scanned', [])),
                json.dumps(phpstan_data)
            ))
        
        # Save NPM audit
        npm_data = results.get('npm_security', {})
        if npm_data:
            themes = npm_data.get('themes', {})
            total_vulns = sum(t.get('vulnerabilities', 0) for t in themes.values())
            npm_severity_counts = self._count_npm_severities(themes)
            
            cursor.execute('''
                INSERT INTO npm_audits 
                (audit_run_id, status, themes_scanned, total_vulnerabilities,
                 critical_count, high_count, moderate_count, low_count, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit_run_id,
                npm_data.get('status'),
                npm_data.get('themes_scanned', 0),
                total_vulns,
                npm_severity_counts.get('critical', 0),
                npm_severity_counts.get('high', 0),
                npm_severity_counts.get('moderate', 0),
                npm_severity_counts.get('low', 0),
                json.dumps(npm_data)
            ))
        
        # Save Gitleaks audit
        gitleaks_data = results.get('gitleaks', {})
        if gitleaks_data:
            cursor.execute('''
                INSERT INTO gitleaks_audits 
                (audit_run_id, status, secrets_found, details)
                VALUES (?, ?, ?, ?)
            ''', (
                audit_run_id,
                gitleaks_data.get('status'),
                gitleaks_data.get('secrets_found', 0),
                json.dumps(gitleaks_data)
            ))
        
        self.conn.commit()
        return audit_run_id
    
    def _count_severities(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
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
            
            # Normalize severity to lowercase
            if severity:
                severity = str(severity).lower().strip()
                
                # Map common variations
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
    
    def _count_npm_severities(self, themes: Dict) -> Dict[str, int]:
        """Count NPM vulnerabilities by severity from theme details"""
        counts = {'critical': 0, 'high': 0, 'moderate': 0, 'low': 0}
        for theme_data in themes.values():
            details = theme_data.get('details', {})
            for pkg_name, pkg_data in details.items():
                if isinstance(pkg_data, dict):
                    severity = pkg_data.get('severity', '').lower()
                    if severity in counts:
                        counts[severity] += 1
        return counts
    
    def get_previous_run(self, drupal_root: str) -> Optional[Dict]:
        """Get the most recent previous audit run for this Drupal installation"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, overall_status, duration_seconds
            FROM audit_runs
            WHERE drupal_root = ?
            ORDER BY created_at DESC
            LIMIT 2
        ''', (drupal_root,))
        
        rows = cursor.fetchall()
        if len(rows) < 2:
            return None
        
        # Get the second most recent (previous run)
        prev_run = rows[1]
        audit_run_id = prev_run[0]
        
        # Fetch composer audit data
        # Schema: id, audit_run_id, status, total_vulnerabilities, critical_count, high_count, moderate_count, low_count, details
        cursor.execute('''
            SELECT status, total_vulnerabilities, critical_count, high_count, moderate_count, low_count
            FROM composer_audits WHERE audit_run_id = ?
        ''', (audit_run_id,))
        composer = cursor.fetchone()
        
        # Fetch phpcs audit data
        # Schema: id, audit_run_id, status, total_errors, total_warnings, files_scanned, paths_scanned, details
        cursor.execute('''
            SELECT status, total_errors, total_warnings
            FROM phpcs_audits WHERE audit_run_id = ?
        ''', (audit_run_id,))
        phpcs = cursor.fetchone()
        
        # Fetch phpstan audit data
        # Schema: id, audit_run_id, status, total_errors, total_file_errors, files_with_errors, files_analyzed, paths_scanned, details
        cursor.execute('''
            SELECT status, total_errors, total_file_errors, files_with_errors, files_analyzed
            FROM phpstan_audits WHERE audit_run_id = ?
        ''', (audit_run_id,))
        phpstan = cursor.fetchone()
        
        # Fetch npm audit data
        # Schema: id, audit_run_id, status, themes_scanned, total_vulnerabilities, critical_count, high_count, moderate_count, low_count, details
        cursor.execute('''
            SELECT status, themes_scanned, total_vulnerabilities, critical_count, high_count, moderate_count, low_count
            FROM npm_audits WHERE audit_run_id = ?
        ''', (audit_run_id,))
        npm = cursor.fetchone()
        
        # Fetch gitleaks audit data
        # Schema: id, audit_run_id, status, secrets_found, details
        cursor.execute('''
            SELECT status, secrets_found
            FROM gitleaks_audits WHERE audit_run_id = ?
        ''', (audit_run_id,))
        gitleaks = cursor.fetchone()
        
        return {
            'timestamp': prev_run[1],
            'overall_status': prev_run[2],
            'duration': prev_run[3],
            'composer': {
                'total_vulnerabilities': int(composer[1]) if composer and composer[1] is not None else 0,
                'critical': int(composer[2]) if composer and composer[2] is not None else 0,
                'high': int(composer[3]) if composer and composer[3] is not None else 0,
                'moderate': int(composer[4]) if composer and composer[4] is not None else 0,
                'low': int(composer[5]) if composer and composer[5] is not None else 0,
            } if composer else None,
            'phpcs': {
                'total_errors': int(phpcs[1]) if phpcs and phpcs[1] is not None else 0,
                'total_warnings': int(phpcs[2]) if phpcs and phpcs[2] is not None else 0,
            } if phpcs else None,
            'phpstan': {
                'total_errors': int(phpstan[1]) if phpstan and phpstan[1] is not None else 0,
                'total_file_errors': int(phpstan[2]) if phpstan and phpstan[2] is not None else 0,
                'files_with_errors': int(phpstan[3]) if phpstan and phpstan[3] is not None else 0,
                'files_analyzed': int(phpstan[4]) if phpstan and phpstan[4] is not None else 0,
            } if phpstan else None,
            'npm': {
                'total_vulnerabilities': int(npm[2]) if npm and npm[2] is not None else 0,
                'critical': int(npm[3]) if npm and npm[3] is not None else 0,
                'high': int(npm[4]) if npm and npm[4] is not None else 0,
                'moderate': int(npm[5]) if npm and npm[5] is not None else 0,
                'low': int(npm[6]) if npm and npm[6] is not None else 0,
            } if npm else None,
            'gitleaks': {
                'secrets_found': int(gitleaks[1]) if gitleaks and gitleaks[1] is not None else 0,
            } if gitleaks else None
        }
    
    def get_history(self, drupal_root: str, limit: int = 10) -> List[Dict]:
        """Get audit history for dashboard"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT ar.id, ar.timestamp, ar.overall_status, ar.duration_seconds,
                   ca.total_vulnerabilities as composer_vulns,
                   ca.critical_count + ca.high_count + ca.moderate_count + ca.low_count as composer_total,
                   pa.total_errors, pa.total_warnings,
                   psa.total_errors as phpstan_errors,
                   na.total_vulnerabilities as npm_vulns,
                   ga.secrets_found
            FROM audit_runs ar
            LEFT JOIN composer_audits ca ON ar.id = ca.audit_run_id
            LEFT JOIN phpcs_audits pa ON ar.id = pa.audit_run_id
            LEFT JOIN phpstan_audits psa ON ar.id = psa.audit_run_id
            LEFT JOIN npm_audits na ON ar.id = na.audit_run_id
            LEFT JOIN gitleaks_audits ga ON ar.id = ga.audit_run_id
            WHERE ar.drupal_root = ?
            ORDER BY ar.created_at DESC
            LIMIT ?
        ''', (drupal_root, limit))
        
        rows = cursor.fetchall()
        history = []
        
        for row in rows:
            history.append({
                'id': row[0],
                'timestamp': row[1],
                'overall_status': row[2],
                'duration': row[3],
                'composer_vulns': row[4] or 0,
                'phpcs_errors': row[6] or 0,
                'phpcs_warnings': row[7] or 0,
                'phpstan_errors': row[8] or 0,
                'npm_vulns': row[9] or 0,
                'secrets_found': row[10] or 0
            })
        
        return history
    
    def export_for_dashboard(self, drupal_root: str) -> str:
        """Export data as JSON for D3.js dashboard"""
        cursor = self.conn.cursor()
        
        # Get recent history
        history = self.get_history(drupal_root, limit=30)
        
        # Get latest run details
        cursor.execute('''
            SELECT ar.id FROM audit_runs ar
            WHERE ar.drupal_root = ?
            ORDER BY ar.created_at DESC LIMIT 1
        ''', (drupal_root,))
        
        latest_row = cursor.fetchone()
        if not latest_row:
            return json.dumps({'history': [], 'latest': None})
        
        latest_id = latest_row[0]
        
        # Get detailed breakdown for latest run
        cursor.execute('''
            SELECT status, total_vulnerabilities, critical_count, high_count, 
                   moderate_count, low_count, details
            FROM composer_audits WHERE audit_run_id = ?
        ''', (latest_id,))
        composer_latest = cursor.fetchone()
        
        cursor.execute('''
            SELECT status, total_errors, total_warnings
            FROM phpcs_audits WHERE audit_run_id = ?
        ''', (latest_id,))
        phpcs_latest = cursor.fetchone()
        
        cursor.execute('''
            SELECT status, total_errors, total_file_errors, files_with_errors, files_analyzed
            FROM phpstan_audits WHERE audit_run_id = ?
        ''', (latest_id,))
        phpstan_latest = cursor.fetchone()
        
        cursor.execute('''
            SELECT status, total_vulnerabilities, critical_count, high_count,
                   moderate_count, low_count
            FROM npm_audits WHERE audit_run_id = ?
        ''', (latest_id,))
        npm_latest = cursor.fetchone()
        
        cursor.execute('''
            SELECT status, secrets_found FROM gitleaks_audits WHERE audit_run_id = ?
        ''', (latest_id,))
        gitleaks_latest = cursor.fetchone()
        
        # Build latest details object
        latest_details = {
            'composer': {
                'status': composer_latest[0] if composer_latest else 'skipped',
                'total': composer_latest[1] if composer_latest else 0,
                'critical': composer_latest[2] if composer_latest else 0,
                'high': composer_latest[3] if composer_latest else 0,
                'moderate': composer_latest[4] if composer_latest else 0,
                'low': composer_latest[5] if composer_latest else 0,
            } if composer_latest else None,
            'phpcs': {
                'status': phpcs_latest[0] if phpcs_latest else 'skipped',
                'errors': phpcs_latest[1] if phpcs_latest else 0,
                'warnings': phpcs_latest[2] if phpcs_latest else 0,
            } if phpcs_latest else None,
            'phpstan': {
                'status': phpstan_latest[0] if phpstan_latest else 'skipped',
                'errors': phpstan_latest[1] if phpstan_latest else 0,
                'file_errors': phpstan_latest[2] if phpstan_latest else 0,
                'files_with_errors': phpstan_latest[3] if phpstan_latest else 0,
                'files_analyzed': phpstan_latest[4] if phpstan_latest else 0,
            } if phpstan_latest else None,
            'npm': {
                'status': npm_latest[0] if npm_latest else 'skipped',
                'total': npm_latest[1] if npm_latest else 0,
                'critical': npm_latest[2] if npm_latest else 0,
                'high': npm_latest[3] if npm_latest else 0,
                'moderate': npm_latest[4] if npm_latest else 0,
                'low': npm_latest[5] if npm_latest else 0,
            } if npm_latest else None,
            'gitleaks': {
                'status': gitleaks_latest[0] if gitleaks_latest else 'skipped',
                'secrets': gitleaks_latest[1] if gitleaks_latest else 0,
            } if gitleaks_latest else None
        }
        
        # Debug: Print severity counts
        if composer_latest:
            print(f"\n{Colors.OKBLUE}Dashboard Export - Composer Severity Counts:{Colors.ENDC}")
            print(f"  Critical: {composer_latest[2]}")
            print(f"  High: {composer_latest[3]}")
            print(f"  Moderate: {composer_latest[4]}")
            print(f"  Low: {composer_latest[5]}")
        
        return json.dumps({
            'history': history,
            'latest': latest_details,
            'drupal_root': drupal_root
        }, indent=2)
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class DrupalSecurityAuditor:
    """Main class for Drupal security auditing"""
    
    def __init__(self, drupal_root: str, phpcs_paths: List[str] = None, 
                 phpstan_paths: List[str] = None,
                 custom_themes_path: str = None, output_file: str = None,
                 db_path: str = None, enable_dashboard: bool = True):
        """
        Initialize the auditor
        
        Args:
            drupal_root: Path to Drupal root directory
            phpcs_paths: List of paths to run PHPCS on (relative to drupal_root)
            phpstan_paths: List of paths to run PHPStan on (relative to drupal_root)
            custom_themes_path: Path to custom themes directory
            output_file: Optional file to save the audit report
            db_path: Path to SQLite database (default: ~/.drupal_audit/audit_history.db)
            enable_dashboard: Whether to enable dashboard generation
        """
        self.drupal_root = Path(drupal_root).resolve()
        self.phpcs_paths = phpcs_paths or []
        self.phpstan_paths = phpstan_paths or []
        self.custom_themes_path = Path(custom_themes_path) if custom_themes_path else None
        self.output_file = output_file
        self.enable_dashboard = enable_dashboard
        self.start_time = datetime.now()
        self.db = AuditDatabase(db_path) if enable_dashboard else None
        self.results = {
            'timestamp': self.start_time.isoformat(),
            'drupal_root': str(self.drupal_root),
            'composer_audit': {},
            'phpcs_analysis': {},
            'phpstan_analysis': {},
            'npm_security': {},
            'gitleaks': {}
        }
        
    def print_section(self, title: str):
        """Print a formatted section header"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{title:^80}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
    
    def run_command(self, cmd: List[str], cwd: str = None) -> Tuple[int, str, str]:
        """
        Run a shell command and return the result
        
        Args:
            cmd: Command as list of strings
            cwd: Working directory
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.drupal_root,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out after 5 minutes"
        except Exception as e:
            return -1, "", str(e)
    
    def check_composer_installed(self) -> bool:
        """Check if composer is installed"""
        returncode, _, _ = self.run_command(['composer', '--version'])
        return returncode == 0
    
    def check_phpcs_installed(self) -> bool:
        """Check if PHPCS is installed via composer"""
        vendor_bin = self.drupal_root / 'vendor' / 'bin' / 'phpcs'
        return vendor_bin.exists()
    
    def check_npm_installed(self) -> bool:
        """Check if npm is installed"""
        returncode, _, _ = self.run_command(['npm', '--version'])
        return returncode == 0
    
    def check_gitleaks_installed(self) -> bool:
        """Check if gitleaks is installed"""
        returncode, _, _ = self.run_command(['gitleaks', 'version'])
        return returncode == 0
    
    def run_composer_audit(self) -> bool:
        """
        Run composer audit to check for security vulnerabilities
        
        Returns:
            True if no vulnerabilities found, False otherwise
        """
        self.print_section("COMPOSER SECURITY AUDIT")
        
        if not self.check_composer_installed():
            print(f"{Colors.FAIL}✗ Composer is not installed{Colors.ENDC}")
            self.results['composer_audit']['status'] = 'skipped'
            self.results['composer_audit']['reason'] = 'Composer not installed'
            return False
        
        print(f"{Colors.OKBLUE}Running composer audit...{Colors.ENDC}")
        returncode, stdout, stderr = self.run_command(['composer', 'audit', '--format=json'])
        
        if returncode == 0:
            print(f"{Colors.OKGREEN}✓ No security vulnerabilities found{Colors.ENDC}")
            self.results['composer_audit']['status'] = 'passed'
            self.results['composer_audit']['vulnerabilities'] = []
            return True
        else:
            try:
                audit_data = json.loads(stdout) if stdout else {}
                advisories = audit_data.get('advisories', {})
                
                print(f"{Colors.FAIL}✗ Found security vulnerabilities:{Colors.ENDC}\n")
                
                vuln_count = 0
                vuln_details = []
                
                for package, package_advisories in advisories.items():
                    # Check if package_advisories is a dict or list
                    if isinstance(package_advisories, dict):
                        # Newer format: advisories is dict with advisory IDs as keys
                        for advisory_id, advisory_data in package_advisories.items():
                            vuln_count += 1
                            
                            # Handle both string and dict advisory data
                            if isinstance(advisory_data, dict):
                                title = advisory_data.get('title', 'N/A')
                                severity = advisory_data.get('severity', 'N/A')
                                cve = advisory_data.get('cve', 'N/A')
                                link = advisory_data.get('link', advisory_data.get('url', 'N/A'))
                            else:
                                # If advisory_data is just a string (advisory ID)
                                title = str(advisory_data)
                                severity = 'Unknown'
                                cve = advisory_id
                                link = 'N/A'
                            
                            print(f"{Colors.WARNING}Package:{Colors.ENDC} {package}")
                            print(f"{Colors.WARNING}Advisory:{Colors.ENDC} {advisory_id}")
                            print(f"{Colors.WARNING}Title:{Colors.ENDC} {title}")
                            print(f"{Colors.WARNING}Severity:{Colors.ENDC} {severity}")
                            print(f"{Colors.WARNING}CVE:{Colors.ENDC} {cve}")
                            print(f"{Colors.WARNING}Link:{Colors.ENDC} {link}")
                            print("-" * 80)
                            
                            vuln_details.append({
                                'package': package,
                                'advisory_id': advisory_id,
                                'title': title,
                                'severity': severity,
                                'cve': cve,
                                'link': link
                            })
                    elif isinstance(package_advisories, list):
                        # Older format: advisories is a list
                        for advisory in package_advisories:
                            vuln_count += 1
                            
                            if isinstance(advisory, dict):
                                advisory_id = advisory.get('advisoryId', 'N/A')
                                title = advisory.get('title', 'N/A')
                                severity = advisory.get('severity', 'N/A')
                                cve = advisory.get('cve', 'N/A')
                                link = advisory.get('link', advisory.get('url', 'N/A'))
                            else:
                                advisory_id = str(advisory)
                                title = str(advisory)
                                severity = 'Unknown'
                                cve = 'N/A'
                                link = 'N/A'
                            
                            print(f"{Colors.WARNING}Package:{Colors.ENDC} {package}")
                            print(f"{Colors.WARNING}Advisory:{Colors.ENDC} {advisory_id}")
                            print(f"{Colors.WARNING}Title:{Colors.ENDC} {title}")
                            print(f"{Colors.WARNING}Severity:{Colors.ENDC} {severity}")
                            print(f"{Colors.WARNING}CVE:{Colors.ENDC} {cve}")
                            print(f"{Colors.WARNING}Link:{Colors.ENDC} {link}")
                            print("-" * 80)
                            
                            vuln_details.append({
                                'package': package,
                                'advisory_id': advisory_id,
                                'title': title,
                                'severity': severity,
                                'cve': cve,
                                'link': link
                            })
                
                self.results['composer_audit']['status'] = 'failed'
                self.results['composer_audit']['vulnerabilities_count'] = vuln_count
                self.results['composer_audit']['vulnerabilities'] = vuln_details
                self.results['composer_audit']['raw_advisories'] = advisories
                
                print(f"\n{Colors.FAIL}Total vulnerabilities found: {vuln_count}{Colors.ENDC}")
                return False
                
            except json.JSONDecodeError as e:
                print(f"{Colors.FAIL}✗ Error parsing composer audit JSON output{Colors.ENDC}")
                print(f"{Colors.WARNING}JSON Error:{Colors.ENDC} {str(e)}")
                print(f"\n{Colors.WARNING}Raw STDOUT (first 500 chars):{Colors.ENDC}")
                print(stdout[:500] if stdout else "No output")
                if stderr:
                    print(f"\n{Colors.WARNING}STDERR:{Colors.ENDC}")
                    print(stderr[:500])
                self.results['composer_audit']['status'] = 'error'
                self.results['composer_audit']['error'] = f'JSON parsing failed: {str(e)}'
                return False
            except Exception as e:
                print(f"{Colors.FAIL}✗ Unexpected error during composer audit{Colors.ENDC}")
                print(f"{Colors.WARNING}Error:{Colors.ENDC} {str(e)}")
                print(f"\n{Colors.WARNING}Raw output:{Colors.ENDC}")
                print(f"STDOUT: {stdout[:500] if stdout else 'None'}")
                print(f"STDERR: {stderr[:500] if stderr else 'None'}")
                self.results['composer_audit']['status'] = 'error'
                self.results['composer_audit']['error'] = str(e)
                return False
    
    def install_phpcs_standards(self) -> bool:
        """Install Drupal coding standards for PHPCS if not present"""
        print(f"{Colors.OKBLUE}Checking PHPCS Drupal standards...{Colors.ENDC}")
        
        # Check if Drupal standards are already installed
        returncode, stdout, _ = self.run_command([
            str(self.drupal_root / 'vendor' / 'bin' / 'phpcs'),
            '-i'
        ])
        
        if 'Drupal' in stdout and 'DrupalPractice' in stdout:
            print(f"{Colors.OKGREEN}✓ Drupal coding standards already installed{Colors.ENDC}")
            return True
        
        print(f"{Colors.WARNING}Installing Drupal coding standards...{Colors.ENDC}")
        
        # Install coder module
        returncode, stdout, stderr = self.run_command([
            'composer',
            'require',
            '--dev',
            'drupal/coder',
            '--no-interaction'
        ])
        
        if returncode != 0:
            print(f"{Colors.FAIL}✗ Failed to install drupal/coder{Colors.ENDC}")
            return False
        
        # Configure PHPCS to use Drupal standards
        returncode, _, _ = self.run_command([
            str(self.drupal_root / 'vendor' / 'bin' / 'phpcs'),
            '--config-set',
            'installed_paths',
            str(self.drupal_root / 'vendor' / 'drupal' / 'coder' / 'coder_sniffer')
        ])
        
        if returncode == 0:
            print(f"{Colors.OKGREEN}✓ Drupal coding standards installed successfully{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.FAIL}✗ Failed to configure Drupal standards{Colors.ENDC}")
            return False
    
    def run_phpcs(self) -> bool:
        """
        Run PHPCS static code analysis
        
        Returns:
            True if no issues found, False otherwise
        """
        self.print_section("PHPCS STATIC CODE ANALYSIS")
        
        if not self.check_phpcs_installed():
            print(f"{Colors.WARNING}PHPCS not found. Installing via composer...{Colors.ENDC}")
            returncode, _, stderr = self.run_command([
                'composer',
                'require',
                '--dev',
                'squizlabs/php_codesniffer',
                '--no-interaction'
            ])
            
            if returncode != 0:
                print(f"{Colors.FAIL}✗ Failed to install PHPCS: {stderr}{Colors.ENDC}")
                self.results['phpcs_analysis']['status'] = 'skipped'
                self.results['phpcs_analysis']['reason'] = 'PHPCS installation failed'
                return False
        
        # Install Drupal standards
        if not self.install_phpcs_standards():
            print(f"{Colors.WARNING}Warning: Could not install Drupal standards{Colors.ENDC}")
        
        if not self.phpcs_paths:
            print(f"{Colors.WARNING}No PHPCS paths specified. Skipping PHPCS analysis.{Colors.ENDC}")
            self.results['phpcs_analysis']['status'] = 'skipped'
            self.results['phpcs_analysis']['reason'] = 'No paths specified'
            return True
        
        phpcs_bin = self.drupal_root / 'vendor' / 'bin' / 'phpcs'
        all_passed = True
        path_results = {}
        
        for path in self.phpcs_paths:
            full_path = self.drupal_root / path
            
            if not full_path.exists():
                print(f"{Colors.WARNING}Warning: Path does not exist: {path}{Colors.ENDC}")
                continue
            
            print(f"\n{Colors.OKBLUE}Analyzing: {path}{Colors.ENDC}")
            
            returncode, stdout, stderr = self.run_command([
                str(phpcs_bin),
                '--standard=Drupal,DrupalPractice',
                '--extensions=php,module,inc,install,test,profile,theme',
                '--report=json',
                str(full_path)
            ])
            
            try:
                result = json.loads(stdout) if stdout else {}
                total_errors = result.get('totals', {}).get('errors', 0)
                total_warnings = result.get('totals', {}).get('warnings', 0)
                
                path_results[path] = {
                    'errors': total_errors,
                    'warnings': total_warnings,
                    'files': result.get('files', {})
                }
                
                if total_errors > 0 or total_warnings > 0:
                    print(f"{Colors.WARNING}Found {total_errors} errors and {total_warnings} warnings{Colors.ENDC}")
                    all_passed = False
                    
                    # Show top 10 issues
                    issue_count = 0
                    for file_path, file_data in result.get('files', {}).items():
                        for message in file_data.get('messages', []):
                            if issue_count < 10:
                                print(f"  {Colors.WARNING}Line {message['line']}:{Colors.ENDC} {message['message']} ({message['source']})")
                                issue_count += 1
                    
                    if sum(len(f.get('messages', [])) for f in result.get('files', {}).values()) > 10:
                        print(f"{Colors.WARNING}  ... and more issues{Colors.ENDC}")
                else:
                    print(f"{Colors.OKGREEN}✓ No issues found{Colors.ENDC}")
                    
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}✗ Error parsing PHPCS output{Colors.ENDC}")
                all_passed = False
        
        self.results['phpcs_analysis']['status'] = 'passed' if all_passed else 'failed'
        self.results['phpcs_analysis']['paths'] = path_results
        
        return all_passed
    
    def check_phpstan_installed(self) -> bool:
        """Check if PHPStan is installed via composer"""
        vendor_bin = self.drupal_root / 'vendor' / 'bin' / 'phpstan'
        return vendor_bin.exists()
    
    def install_phpstan(self) -> bool:
        """Install PHPStan with Drupal extensions"""
        print(f"{Colors.OKBLUE}Installing PHPStan with Drupal extensions...{Colors.ENDC}")
        
        packages = [
            'phpstan/phpstan',
            'mglaman/phpstan-drupal',
            'phpstan/phpstan-deprecation-rules'
        ]
        
        returncode, stdout, stderr = self.run_command([
            'composer',
            'require',
            '--dev',
            *packages,
            '--no-interaction'
        ])
        
        if returncode != 0:
            print(f"{Colors.FAIL}✗ Failed to install PHPStan: {stderr}{Colors.ENDC}")
            return False
        
        print(f"{Colors.OKGREEN}✓ PHPStan installed successfully{Colors.ENDC}")
        return True
    
    def create_phpstan_config(self) -> bool:
        """Create PHPStan configuration file if it doesn't exist"""
        config_file = self.drupal_root / 'phpstan.neon'
        
        if config_file.exists():
            print(f"{Colors.OKBLUE}Using existing phpstan.neon{Colors.ENDC}")
            return True
        
        print(f"{Colors.OKBLUE}Creating phpstan.neon configuration...{Colors.ENDC}")
        
        config_content = """includes:
    - vendor/mglaman/phpstan-drupal/extension.neon
    - vendor/phpstan/phpstan-deprecation-rules/rules.neon

parameters:
    level: 1
    drupal:
        drupal_root: web
    paths:
        - web/modules/custom
        - web/themes/custom
    excludePaths:
        - web/*/node_modules/*
        - web/*/vendor/*
        - */tests/*
        - */Tests/*
    ignoreErrors:
        # Ignore common Drupal core issues
        - '#Call to deprecated#'
"""
        
        try:
            with open(config_file, 'w') as f:
                f.write(config_content)
            print(f"{Colors.OKGREEN}✓ Created phpstan.neon{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.FAIL}✗ Failed to create config: {e}{Colors.ENDC}")
            return False
    
    def run_phpstan(self) -> bool:
        """
        Run PHPStan static analysis
        
        Returns:
            True if no issues found, False otherwise
        """
        self.print_section("PHPSTAN STATIC ANALYSIS")
        
        if not self.check_phpstan_installed():
            print(f"{Colors.WARNING}PHPStan not found. Installing...{Colors.ENDC}")
            if not self.install_phpstan():
                self.results['phpstan_analysis']['status'] = 'skipped'
                self.results['phpstan_analysis']['reason'] = 'Installation failed'
                return False
        
        # Create config if needed
        self.create_phpstan_config()
        
        if not self.phpstan_paths:
            print(f"{Colors.WARNING}No PHPStan paths specified. Skipping analysis.{Colors.ENDC}")
            self.results['phpstan_analysis']['status'] = 'skipped'
            self.results['phpstan_analysis']['reason'] = 'No paths specified'
            return True
        
        phpstan_bin = self.drupal_root / 'vendor' / 'bin' / 'phpstan'
        all_passed = True
        total_errors = 0
        total_file_errors = 0
        files_with_errors = 0
        files_analyzed = 0
        
        print(f"\n{Colors.OKBLUE}Running PHPStan analysis...{Colors.ENDC}")
        
        # Build paths argument
        paths_to_analyze = []
        for path in self.phpstan_paths:
            full_path = self.drupal_root / path
            if full_path.exists():
                paths_to_analyze.append(str(full_path))
            else:
                print(f"{Colors.WARNING}Warning: Path does not exist: {path}{Colors.ENDC}")
        
        if not paths_to_analyze:
            print(f"{Colors.WARNING}No valid paths to analyze{Colors.ENDC}")
            self.results['phpstan_analysis']['status'] = 'skipped'
            return True
        
        # Run PHPStan with JSON error format
        returncode, stdout, stderr = self.run_command([
            str(phpstan_bin),
            'analyse',
            '--error-format=json',
            '--no-progress',
            '--memory-limit=512M',
            *paths_to_analyze
        ])
        
        try:
            # PHPStan returns non-zero if errors found
            result = json.loads(stdout) if stdout else {}
            
            total_file_errors = result.get('totals', {}).get('file_errors', 0)
            total_errors = result.get('totals', {}).get('errors', 0)
            files = result.get('files', {})
            files_with_errors = len(files)
            
            # Count files analyzed (approximate from paths)
            for path in paths_to_analyze:
                if os.path.isfile(path):
                    files_analyzed += 1
                elif os.path.isdir(path):
                    for root, dirs, filenames in os.walk(path):
                        # Skip vendor and node_modules
                        dirs[:] = [d for d in dirs if d not in ['vendor', 'node_modules', 'tests', 'Tests']]
                        files_analyzed += len([f for f in filenames if f.endswith('.php')])
            
            self.results['phpstan_analysis']['total_errors'] = total_errors
            self.results['phpstan_analysis']['total_file_errors'] = total_file_errors
            self.results['phpstan_analysis']['files_with_errors'] = files_with_errors
            self.results['phpstan_analysis']['files_analyzed'] = files_analyzed
            self.results['phpstan_analysis']['paths_scanned'] = self.phpstan_paths
            
            if total_errors > 0 or total_file_errors > 0:
                print(f"{Colors.WARNING}Found {total_errors} error(s) in {files_with_errors} file(s){Colors.ENDC}\n")
                all_passed = False
                
                # Show top 10 errors
                error_count = 0
                for file_path, file_data in files.items():
                    for message in file_data.get('messages', []):
                        if error_count < 10:
                            relative_path = file_path.replace(str(self.drupal_root), '')
                            print(f"  {Colors.WARNING}{relative_path}:{message.get('line', '?')}{Colors.ENDC}")
                            print(f"    {message.get('message', 'Unknown error')}")
                            error_count += 1
                
                if total_errors > 10:
                    print(f"{Colors.WARNING}  ... and {total_errors - 10} more errors{Colors.ENDC}")
                
                self.results['phpstan_analysis']['details'] = result
            else:
                print(f"{Colors.OKGREEN}✓ No errors found{Colors.ENDC}")
                print(f"  Files analyzed: {files_analyzed}")
            
        except json.JSONDecodeError:
            print(f"{Colors.FAIL}✗ Error parsing PHPStan output{Colors.ENDC}")
            if stdout:
                print(f"Output: {stdout[:500]}")
            if stderr:
                print(f"Error: {stderr[:500]}")
            all_passed = False
        
        self.results['phpstan_analysis']['status'] = 'passed' if all_passed else 'failed'
        
        return all_passed
    
    def scan_npm_packages(self) -> bool:
        """
        Scan package.json files in custom themes for security vulnerabilities
        
        Returns:
            True if no vulnerabilities found, False otherwise
        """
        self.print_section("NPM PACKAGE SECURITY AUDIT")
        
        if not self.custom_themes_path:
            print(f"{Colors.WARNING}No custom themes path specified. Skipping NPM audit.{Colors.ENDC}")
            self.results['npm_security']['status'] = 'skipped'
            self.results['npm_security']['reason'] = 'No themes path specified'
            return True
        
        if not self.custom_themes_path.exists():
            print(f"{Colors.FAIL}✗ Custom themes path does not exist: {self.custom_themes_path}{Colors.ENDC}")
            self.results['npm_security']['status'] = 'skipped'
            self.results['npm_security']['reason'] = 'Path does not exist'
            return False
        
        if not self.check_npm_installed():
            print(f"{Colors.FAIL}✗ NPM is not installed{Colors.ENDC}")
            self.results['npm_security']['status'] = 'skipped'
            self.results['npm_security']['reason'] = 'NPM not installed'
            return False
        
        # Find all package.json files recursively
        package_files = list(self.custom_themes_path.rglob('package.json'))
        
        if not package_files:
            print(f"{Colors.WARNING}No package.json files found in {self.custom_themes_path}{Colors.ENDC}")
            self.results['npm_security']['status'] = 'passed'
            self.results['npm_security']['themes_scanned'] = 0
            return True
        
        print(f"{Colors.OKBLUE}Found {len(package_files)} package.json file(s){Colors.ENDC}\n")
        
        all_passed = True
        theme_results = {}
        
        for package_file in package_files:
            theme_dir = package_file.parent
            theme_name = theme_dir.name
            
            print(f"{Colors.OKBLUE}Scanning theme: {theme_name}{Colors.ENDC}")
            print(f"  Path: {package_file.relative_to(self.custom_themes_path)}")
            
            # Run npm audit
            returncode, stdout, stderr = self.run_command(
                ['npm', 'audit', '--json'],
                cwd=str(theme_dir)
            )
            
            try:
                audit_data = json.loads(stdout) if stdout else {}
                
                # npm audit returns non-zero if vulnerabilities found
                vulnerabilities = audit_data.get('vulnerabilities', {})
                metadata = audit_data.get('metadata', {})
                
                total_vulns = metadata.get('vulnerabilities', {}).get('total', 0)
                
                if total_vulns > 0:
                    print(f"{Colors.FAIL}  ✗ Found {total_vulns} vulnerabilities{Colors.ENDC}")
                    
                    severity_counts = metadata.get('vulnerabilities', {})
                    print(f"    Critical: {severity_counts.get('critical', 0)}")
                    print(f"    High: {severity_counts.get('high', 0)}")
                    print(f"    Moderate: {severity_counts.get('moderate', 0)}")
                    print(f"    Low: {severity_counts.get('low', 0)}")
                    
                    all_passed = False
                    theme_results[theme_name] = {
                        'status': 'failed',
                        'vulnerabilities': total_vulns,
                        'details': vulnerabilities
                    }
                else:
                    print(f"{Colors.OKGREEN}  ✓ No vulnerabilities found{Colors.ENDC}")
                    theme_results[theme_name] = {
                        'status': 'passed',
                        'vulnerabilities': 0
                    }
                
            except json.JSONDecodeError:
                print(f"{Colors.WARNING}  Warning: Could not parse npm audit output{Colors.ENDC}")
                theme_results[theme_name] = {
                    'status': 'error',
                    'error': 'Failed to parse audit output'
                }
            
            print()
        
        self.results['npm_security']['status'] = 'passed' if all_passed else 'failed'
        self.results['npm_security']['themes_scanned'] = len(package_files)
        self.results['npm_security']['themes'] = theme_results
        
        return all_passed
    
    def run_gitleaks(self) -> bool:
        """
        Run gitleaks to scan for secrets in the codebase
        
        Returns:
            True if no secrets found, False otherwise
        """
        self.print_section("GITLEAKS SECRET SCANNING")
        
        if not self.check_gitleaks_installed():
            print(f"{Colors.FAIL}✗ Gitleaks is not installed{Colors.ENDC}")
            print(f"{Colors.WARNING}Install from: https://github.com/gitleaks/gitleaks{Colors.ENDC}")
            self.results['gitleaks']['status'] = 'skipped'
            self.results['gitleaks']['reason'] = 'Gitleaks not installed'
            return False
        
        print(f"{Colors.OKBLUE}Scanning for secrets with gitleaks...{Colors.ENDC}")
        
        # Run gitleaks detect
        returncode, stdout, stderr = self.run_command([
            'gitleaks',
            'detect',
            '--source', '.',
            '--report-format', 'json',
            '--report-path', 'gitleaks-report.json',
            '--verbose'
        ])
        
        # Check if report was generated
        report_file = self.drupal_root / 'gitleaks-report.json'
        
        if report_file.exists():
            try:
                with open(report_file, 'r') as f:
                    findings = json.load(f)
                
                if findings:
                    print(f"{Colors.FAIL}✗ Found {len(findings)} potential secret(s):{Colors.ENDC}\n")
                    
                    for i, finding in enumerate(findings[:10], 1):  # Show first 10
                        print(f"{Colors.WARNING}Finding #{i}:{Colors.ENDC}")
                        print(f"  File: {finding.get('File', 'N/A')}")
                        print(f"  Rule: {finding.get('RuleID', 'N/A')}")
                        print(f"  Line: {finding.get('StartLine', 'N/A')}")
                        print(f"  Secret: {finding.get('Secret', 'N/A')[:50]}...")
                        print("-" * 80)
                    
                    if len(findings) > 10:
                        print(f"{Colors.WARNING}... and {len(findings) - 10} more findings{Colors.ENDC}")
                    
                    self.results['gitleaks']['status'] = 'failed'
                    self.results['gitleaks']['secrets_found'] = len(findings)
                    self.results['gitleaks']['report_path'] = str(report_file)
                    
                    print(f"\n{Colors.WARNING}Full report saved to: {report_file}{Colors.ENDC}")
                    return False
                else:
                    print(f"{Colors.OKGREEN}✓ No secrets found{Colors.ENDC}")
                    self.results['gitleaks']['status'] = 'passed'
                    self.results['gitleaks']['secrets_found'] = 0
                    
                    # Clean up empty report
                    report_file.unlink()
                    return True
                    
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}✗ Error parsing gitleaks report{Colors.ENDC}")
                self.results['gitleaks']['status'] = 'error'
                return False
        else:
            # No report means no secrets found (gitleaks exits with 0)
            if returncode == 0:
                print(f"{Colors.OKGREEN}✓ No secrets found{Colors.ENDC}")
                self.results['gitleaks']['status'] = 'passed'
                self.results['gitleaks']['secrets_found'] = 0
                return True
            else:
                print(f"{Colors.FAIL}✗ Gitleaks scan failed{Colors.ENDC}")
                print(f"Error: {stderr}")
                self.results['gitleaks']['status'] = 'error'
                self.results['gitleaks']['error'] = stderr
                return False
    
    def save_report(self):
        """Save the audit results to a JSON file"""
        if not self.output_file:
            return
        
        output_path = Path(self.output_file)
        
        try:
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            print(f"\n{Colors.OKGREEN}✓ Audit report saved to: {output_path}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}✗ Failed to save report: {e}{Colors.ENDC}")
    
    def print_summary(self):
        """Print a summary of all audit results"""
        self.print_section("AUDIT SUMMARY")
        
        # Get previous run for comparison
        previous_run = None
        if self.db:
            previous_run = self.db.get_previous_run(str(self.drupal_root))
        
        checks = [
            ('Composer Security Audit', self.results['composer_audit'].get('status')),
            ('PHPCS Code Analysis', self.results['phpcs_analysis'].get('status')),
            ('PHPStan Static Analysis', self.results['phpstan_analysis'].get('status')),
            ('NPM Security Audit', self.results['npm_security'].get('status')),
            ('Gitleaks Secret Scan', self.results['gitleaks'].get('status'))
        ]
        
        for check_name, status in checks:
            if status == 'passed':
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} {check_name}: {Colors.OKGREEN}PASSED{Colors.ENDC}")
            elif status == 'failed':
                print(f"{Colors.FAIL}✗{Colors.ENDC} {check_name}: {Colors.FAIL}FAILED{Colors.ENDC}")
            elif status == 'skipped':
                print(f"{Colors.WARNING}⊘{Colors.ENDC} {check_name}: {Colors.WARNING}SKIPPED{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}?{Colors.ENDC} {check_name}: {Colors.WARNING}ERROR{Colors.ENDC}")
        
        # Show comparison with previous run
        if previous_run:
            print(f"\n{Colors.BOLD}Comparison with Previous Run:{Colors.ENDC}")
            print(f"Previous run: {previous_run['timestamp']}")
            
            # Composer comparison
            if previous_run.get('composer'):
                curr_vulns = self.results['composer_audit'].get('vulnerabilities_count', 0)
                prev_vulns = previous_run['composer']['total_vulnerabilities']
                
                # Ensure both are integers
                curr_vulns = int(curr_vulns) if curr_vulns is not None else 0
                prev_vulns = int(prev_vulns) if prev_vulns is not None else 0
                
                diff = curr_vulns - prev_vulns
                
                if diff > 0:
                    print(f"  Composer: {Colors.FAIL}+{diff} vulnerabilities{Colors.ENDC} ({prev_vulns} → {curr_vulns})")
                elif diff < 0:
                    print(f"  Composer: {Colors.OKGREEN}{diff} vulnerabilities{Colors.ENDC} ({prev_vulns} → {curr_vulns})")
                else:
                    print(f"  Composer: No change ({curr_vulns} vulnerabilities)")
            
            # PHPCS comparison
            if previous_run.get('phpcs'):
                curr_errors = sum(p.get('errors', 0) for p in self.results['phpcs_analysis'].get('paths', {}).values())
                prev_errors = previous_run['phpcs']['total_errors']
                
                # Ensure both are integers
                curr_errors = int(curr_errors) if curr_errors is not None else 0
                prev_errors = int(prev_errors) if prev_errors is not None else 0
                
                diff = curr_errors - prev_errors
                
                if diff > 0:
                    print(f"  PHPCS: {Colors.FAIL}+{diff} errors{Colors.ENDC} ({prev_errors} → {curr_errors})")
                elif diff < 0:
                    print(f"  PHPCS: {Colors.OKGREEN}{diff} errors{Colors.ENDC} ({prev_errors} → {curr_errors})")
                else:
                    print(f"  PHPCS: No change ({curr_errors} errors)")
            
            # PHPStan comparison
            if previous_run.get('phpstan'):
                curr_phpstan_errors = self.results['phpstan_analysis'].get('total_errors', 0)
                prev_phpstan_errors = previous_run['phpstan']['total_errors']
                
                # Ensure both are integers
                curr_phpstan_errors = int(curr_phpstan_errors) if curr_phpstan_errors is not None else 0
                prev_phpstan_errors = int(prev_phpstan_errors) if prev_phpstan_errors is not None else 0
                
                diff = curr_phpstan_errors - prev_phpstan_errors
                
                if diff > 0:
                    print(f"  PHPStan: {Colors.FAIL}+{diff} errors{Colors.ENDC} ({prev_phpstan_errors} → {curr_phpstan_errors})")
                elif diff < 0:
                    print(f"  PHPStan: {Colors.OKGREEN}{diff} errors{Colors.ENDC} ({prev_phpstan_errors} → {curr_phpstan_errors})")
                else:
                    print(f"  PHPStan: No change ({curr_phpstan_errors} errors)")
            
            # NPM comparison
            if previous_run.get('npm'):
                curr_npm_vulns = sum(t.get('vulnerabilities', 0) for t in self.results['npm_security'].get('themes', {}).values())
                prev_npm_vulns = previous_run['npm']['total_vulnerabilities']
                
                # Ensure both are integers
                curr_npm_vulns = int(curr_npm_vulns) if curr_npm_vulns is not None else 0
                prev_npm_vulns = int(prev_npm_vulns) if prev_npm_vulns is not None else 0
                
                diff = curr_npm_vulns - prev_npm_vulns
                
                if diff > 0:
                    print(f"  NPM: {Colors.FAIL}+{diff} vulnerabilities{Colors.ENDC} ({prev_npm_vulns} → {curr_npm_vulns})")
                elif diff < 0:
                    print(f"  NPM: {Colors.OKGREEN}{diff} vulnerabilities{Colors.ENDC} ({prev_npm_vulns} → {curr_npm_vulns})")
                else:
                    print(f"  NPM: No change ({curr_npm_vulns} vulnerabilities)")
            
            # Gitleaks comparison
            if previous_run.get('gitleaks'):
                curr_secrets = self.results['gitleaks'].get('secrets_found', 0)
                prev_secrets = previous_run['gitleaks']['secrets_found']
                
                # Ensure both are integers
                curr_secrets = int(curr_secrets) if curr_secrets is not None else 0
                prev_secrets = int(prev_secrets) if prev_secrets is not None else 0
                
                diff = curr_secrets - prev_secrets
                
                if diff > 0:
                    print(f"  Gitleaks: {Colors.FAIL}+{diff} secrets{Colors.ENDC} ({prev_secrets} → {curr_secrets})")
                elif diff < 0:
                    print(f"  Gitleaks: {Colors.OKGREEN}{diff} secrets{Colors.ENDC} ({prev_secrets} → {curr_secrets})")
                else:
                    print(f"  Gitleaks: No change ({curr_secrets} secrets)")
        
        # Overall status
        failed_checks = sum(1 for _, status in checks if status == 'failed')
        
        print(f"\n{Colors.BOLD}Overall Status:{Colors.ENDC}", end=" ")
        if failed_checks == 0:
            print(f"{Colors.OKGREEN}✓ ALL CHECKS PASSED{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}✗ {failed_checks} CHECK(S) FAILED{Colors.ENDC}")
    
    def run_audit(self) -> bool:
        """
        Run all security audits
        
        Returns:
            True if all audits passed, False otherwise
        """
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}Drupal 11 Security Audit{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Drupal Root: {self.drupal_root}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        
        # Run all checks
        composer_passed = self.run_composer_audit()
        phpcs_passed = self.run_phpcs()
        phpstan_passed = self.run_phpstan()
        npm_passed = self.scan_npm_packages()
        gitleaks_passed = self.run_gitleaks()
        
        # Calculate duration
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Save to database
        if self.db:
            try:
                audit_run_id = self.db.save_audit_run(self.results, duration)
                print(f"\n{Colors.OKGREEN}✓ Audit results saved to database (Run ID: {audit_run_id}){Colors.ENDC}")
            except Exception as e:
                print(f"\n{Colors.WARNING}Warning: Failed to save to database: {e}{Colors.ENDC}")
        
        # Print summary
        self.print_summary()
        
        # Save report if requested
        if self.output_file:
            self.save_report()
        
        # Generate dashboard
        if self.enable_dashboard and self.db:
            self.generate_dashboard()
        
        # Clean up
        if self.db:
            self.db.close()
        
        # Return overall status
        return all([composer_passed, phpcs_passed, phpstan_passed, npm_passed, gitleaks_passed])
    
    def generate_dashboard(self):
        """Generate HTML dashboard with D3.js visualizations"""
        try:
            dashboard_data = self.db.export_for_dashboard(str(self.drupal_root))
            
            # Create dashboard HTML
            dashboard_dir = self.drupal_root / 'audit-dashboard'
            dashboard_dir.mkdir(exist_ok=True)
            
            dashboard_file = dashboard_dir / 'index.html'
            data_file = dashboard_dir / 'audit_data.json'
            
            # Save data file (for reference)
            with open(data_file, 'w') as f:
                f.write(dashboard_data)
            
            # Generate HTML with embedded data (avoids CORS issues)
            self._create_dashboard_html(dashboard_file, dashboard_data)
            
            print(f"\n{Colors.OKGREEN}✓ Dashboard generated: {dashboard_file}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  Open directly in browser: file://{dashboard_file}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  Or run: cd {dashboard_dir} && python3 -m http.server 8000{Colors.ENDC}")
            
        except Exception as e:
            print(f"\n{Colors.WARNING}Warning: Failed to generate dashboard: {e}{Colors.ENDC}")
    
    def _create_dashboard_html(self, output_path: Path, embedded_data: str = None):
        """Create the HTML dashboard file with optional embedded data"""
        # Look for dashboard template
        script_dir = Path(__file__).parent
        template_path = script_dir / 'dashboard_template.html'
        
        # If running from installed location, try alternative paths
        if not template_path.exists():
            # Try same directory as the script
            alt_paths = [
                Path.cwd() / 'dashboard_template.html',
                Path.home() / '.drupal_audit' / 'dashboard_template.html',
            ]
            
            for alt_path in alt_paths:
                if alt_path.exists():
                    template_path = alt_path
                    break
        
        if template_path.exists():
            # Read template
            with open(template_path, 'r') as f:
                html_content = f.read()
            
            # Embed data if provided
            if embedded_data:
                # Insert data as a JavaScript variable before the main script
                data_script = f"\n    <script>\n        const EMBEDDED_DATA = {embedded_data};\n    </script>\n"
                # Insert before the main script tag
                html_content = html_content.replace(
                    '<script>',
                    data_script + '    <script>',
                    1  # Only replace first occurrence
                )
            
            with open(output_path, 'w') as f:
                f.write(html_content)
        else:
            # Create embedded template if file not found
            with open(output_path, 'w') as f:
                f.write(self._get_embedded_dashboard_template(embedded_data))
    
    def _get_embedded_dashboard_template(self, data: str = None) -> str:
        """Return embedded dashboard HTML template"""
        # Return a minimal version
        return f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Drupal Audit Dashboard</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>body{{font-family:sans-serif;padding:20px;background:#f5f5f5;}}
.card{{background:white;padding:20px;margin:10px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}}
</style></head><body>
<div class="card"><h1>Dashboard Template Not Found</h1>
<p>Place dashboard_template.html in the same directory as the audit script.</p>
<p>Data is available in <code>audit_data.json</code></p>
<p>Run: <code>python3 -m http.server 8000</code> in the audit-dashboard directory</p>
</div>
</body></html>'''
        


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Drupal 11 Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit with composer and gitleaks only
  python drupal_security_audit.py /path/to/drupal

  # Full audit with PHPCS on custom modules
  python drupal_security_audit.py /path/to/drupal \\
    --phpcs-paths web/modules/custom web/themes/custom

  # Full audit with custom themes scanning
  python drupal_security_audit.py /path/to/drupal \\
    --phpcs-paths web/modules/custom \\
    --themes-path web/themes/custom

  # Complete audit with output report
  python drupal_security_audit.py /path/to/drupal \\
    --phpcs-paths web/modules/custom web/profiles/custom \\
    --themes-path web/themes/custom \\
    --output audit-report.json
        """
    )
    
    parser.add_argument(
        'drupal_root',
        help='Path to Drupal root directory'
    )
    
    parser.add_argument(
        '--phpcs-paths',
        nargs='+',
        help='Paths to run PHPCS on (relative to drupal_root). Example: web/modules/custom web/themes/custom'
    )
    
    parser.add_argument(
        '--phpstan-paths',
        nargs='+',
        help='Paths to run PHPStan on (relative to drupal_root). Example: web/modules/custom web/themes/custom'
    )
    
    parser.add_argument(
        '--themes-path',
        help='Path to custom themes directory for NPM security scanning'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for JSON audit report'
    )
    
    parser.add_argument(
        '--db-path',
        help='Path to SQLite database file (default: ~/.drupal_audit/audit_history.db)'
    )
    
    parser.add_argument(
        '--no-dashboard',
        action='store_true',
        help='Disable dashboard generation and database storage'
    )
    
    args = parser.parse_args()
    
    # Validate Drupal root
    drupal_root = Path(args.drupal_root)
    if not drupal_root.exists():
        print(f"{Colors.FAIL}Error: Drupal root directory does not exist: {drupal_root}{Colors.ENDC}")
        sys.exit(1)
    
    if not (drupal_root / 'composer.json').exists():
        print(f"{Colors.FAIL}Error: No composer.json found in {drupal_root}{Colors.ENDC}")
        print(f"{Colors.FAIL}Please ensure this is a valid Drupal root directory{Colors.ENDC}")
        sys.exit(1)
    
    # Create auditor and run
    auditor = DrupalSecurityAuditor(
        drupal_root=str(drupal_root),
        phpcs_paths=args.phpcs_paths,
        phpstan_paths=args.phpstan_paths,
        custom_themes_path=args.themes_path,
        output_file=args.output,
        db_path=args.db_path,
        enable_dashboard=not args.no_dashboard
    )
    
    success = auditor.run_audit()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
