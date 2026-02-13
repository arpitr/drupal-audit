# Drupal 11 Security Audit Tool with Dashboard

A comprehensive Python-based security auditing tool for Drupal 11 applications with **historical tracking** and **interactive D3.js dashboard**.

## Quick Links

- [Installation](#installation)
- [Usage](#usage)
- [Dashboard Features](#dashboard-features)
- [Database Schema](#database-schema)

## What's New

- 📊 Interactive D3.js Dashboard with charts and graphs
- 💾 SQLite Database for audit history
- 📈 Trend Analysis over time
- 🔄 Automatic comparison with previous runs

## Usage

### Run with Dashboard (Default)
bash
python3 drupal_security_audit.py /path/to/drupal

After completion, open: `<drupal_root>/audit-dashboard/index.html`

### Full Command
bash
python3 drupal_security_audit.py /path/to/drupal \
  --phpcs-paths web/modules/custom \
  --themes-path web/themes/custom \
  --output report.json


See the original README.md for full documentation.
