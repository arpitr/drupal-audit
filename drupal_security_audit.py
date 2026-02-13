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
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple


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


class DrupalSecurityAuditor:
    """Main class for Drupal security auditing"""
    
    def __init__(self, drupal_root: str, phpcs_paths: List[str] = None, 
                 custom_themes_path: str = None, output_file: str = None):
        """
        Initialize the auditor
        
        Args:
            drupal_root: Path to Drupal root directory
            phpcs_paths: List of paths to run PHPCS on (relative to drupal_root)
            custom_themes_path: Path to custom themes directory
            output_file: Optional file to save the audit report
        """
        self.drupal_root = Path(drupal_root).resolve()
        self.phpcs_paths = phpcs_paths or []
        self.custom_themes_path = Path(custom_themes_path) if custom_themes_path else None
        self.output_file = output_file
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'drupal_root': str(self.drupal_root),
            'composer_audit': {},
            'phpcs_analysis': {},
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
        
        checks = [
            ('Composer Security Audit', self.results['composer_audit'].get('status')),
            ('PHPCS Code Analysis', self.results['phpcs_analysis'].get('status')),
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
        print(f"{Colors.OKCYAN}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        
        # Run all checks
        composer_passed = self.run_composer_audit()
        phpcs_passed = self.run_phpcs()
        npm_passed = self.scan_npm_packages()
        gitleaks_passed = self.run_gitleaks()
        
        # Print summary
        self.print_summary()
        
        # Save report if requested
        if self.output_file:
            self.save_report()
        
        # Return overall status
        return all([composer_passed, phpcs_passed, npm_passed, gitleaks_passed])


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
        '--themes-path',
        help='Path to custom themes directory for NPM security scanning'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for JSON audit report'
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
        custom_themes_path=args.themes_path,
        output_file=args.output
    )
    
    success = auditor.run_audit()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
