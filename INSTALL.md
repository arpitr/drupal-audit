# Installation Guide for Drupal Security Audit Tool

## Complete Installation Instructions

### Step 1: Install System Prerequisites

#### On Ubuntu/Debian Linux

```bash
# Update package list
sudo apt update

# Install Python 3 (if not already installed)
sudo apt install -y python3 python3-pip

# Install Composer
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
sudo chmod +x /usr/local/bin/composer

# Install Gitleaks
GITLEAKS_VERSION="8.18.1"
wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
sudo mv gitleaks /usr/local/bin/
sudo chmod +x /usr/local/bin/gitleaks
rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

# Install Node.js and NPM (for theme scanning)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installations
python3 --version
composer --version
gitleaks version
npm --version
```

#### On macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install python3
brew install composer
brew install gitleaks
brew install node

# Verify installations
python3 --version
composer --version
gitleaks version
npm --version
```

#### On Windows (WSL2 recommended)

```powershell
# Enable WSL2
wsl --install

# Then follow Ubuntu/Debian instructions inside WSL2
```

### Step 2: Download the Audit Script

#### Option A: Using wget
```bash
cd /path/to/your/scripts
wget https://raw.githubusercontent.com/your-repo/drupal_security_audit.py
chmod +x drupal_security_audit.py
```

#### Option B: Using curl
```bash
cd /path/to/your/scripts
curl -O https://raw.githubusercontent.com/your-repo/drupal_security_audit.py
chmod +x drupal_security_audit.py
```

#### Option C: Manual download
1. Download `drupal_security_audit.py` from the repository
2. Save it to your preferred location
3. Make it executable:
```bash
chmod +x /path/to/drupal_security_audit.py
```

### Step 3: (Optional) Download Helper Files

```bash
# Download wrapper script
wget https://raw.githubusercontent.com/your-repo/run-audit.sh
chmod +x run-audit.sh

# Download example configuration files
wget https://raw.githubusercontent.com/your-repo/.gitleaksignore.example
wget https://raw.githubusercontent.com/your-repo/phpcs.xml.example

# Copy examples to your Drupal root
cp .gitleaksignore.example /path/to/drupal/.gitleaksignore
cp phpcs.xml.example /path/to/drupal/phpcs.xml
```

### Step 4: Verify Installation

```bash
# Test the script
python3 drupal_security_audit.py --help

# You should see the help message with usage instructions
```

## Post-Installation Setup

### Configure the Wrapper Script (Optional)

If you're using `run-audit.sh`, edit it to match your environment:

```bash
nano run-audit.sh
```

Update these variables:
```bash
DRUPAL_ROOT="/var/www/drupal"              # Your Drupal root path
PHPCS_PATHS="web/modules/custom web/themes/custom"  # Paths to scan
THEMES_PATH="web/themes/custom"            # Custom themes path
OUTPUT_DIR="./audit-reports"               # Where to save reports
```

### Set Up Your Drupal Project

1. **Navigate to your Drupal root:**
```bash
cd /var/www/drupal
```

2. **Ensure composer.json exists:**
```bash
ls -la composer.json
```

3. **Install Drupal dependencies (if not done):**
```bash
composer install
```

4. **(Optional) Copy configuration files:**
```bash
# Copy Gitleaks ignore file
cp /path/to/.gitleaksignore.example .gitleaksignore

# Copy PHPCS configuration
cp /path/to/phpcs.xml.example phpcs.xml
```

## Installation Verification Checklist

Run these commands to verify everything is set up correctly:

```bash
# Check Python
python3 --version
# Expected: Python 3.6.x or higher

# Check Composer
composer --version
# Expected: Composer version 2.x.x

# Check Gitleaks
gitleaks version
# Expected: gitleaks version x.x.x

# Check NPM (optional, for theme scanning)
npm --version
# Expected: 8.x.x or higher

# Check script is accessible
python3 /path/to/drupal_security_audit.py --help
# Expected: Help message displayed

# Check Drupal root has composer.json
ls -la /var/www/drupal/composer.json
# Expected: File exists
```

## Common Installation Issues

### Issue: Python not found
```bash
# On Ubuntu/Debian
sudo apt install python3

# On macOS
brew install python3
```

### Issue: Composer not in PATH
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$PATH:$HOME/.composer/vendor/bin"
source ~/.bashrc  # or source ~/.zshrc
```

### Issue: Gitleaks installation fails on Linux
```bash
# Try different architecture
# For ARM64:
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_arm64.tar.gz

# For 32-bit systems:
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x32.tar.gz
```

### Issue: Permission denied when running script
```bash
chmod +x drupal_security_audit.py
chmod +x run-audit.sh
```

## System-Wide Installation (Optional)

To make the script available system-wide:

```bash
# Copy script to /usr/local/bin
sudo cp drupal_security_audit.py /usr/local/bin/drupal-audit
sudo chmod +x /usr/local/bin/drupal-audit

# Now you can run from anywhere
drupal-audit /path/to/drupal
```

## Docker Installation (Alternative)

If you prefer to run in a container:

```dockerfile
# Create Dockerfile
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin --filename=composer

# Install Gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.1_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks_8.18.1_linux_x64.tar.gz

# Copy audit script
COPY drupal_security_audit.py /usr/local/bin/drupal-audit
RUN chmod +x /usr/local/bin/drupal-audit

WORKDIR /app

ENTRYPOINT ["drupal-audit"]
```

Build and use:
```bash
docker build -t drupal-audit .
docker run -v /path/to/drupal:/app drupal-audit /app --phpcs-paths web/modules/custom
```

## Next Steps

1. ✅ Verify all tools are installed
2. ✅ Download the audit script
3. ✅ Test the script with `--help`
4. 📖 Read the [QUICKSTART.md](QUICKSTART.md) for usage examples
5. 🚀 Run your first audit!

## Need Help?

- Check the [README.md](README.md) for detailed documentation
- Check the [QUICKSTART.md](QUICKSTART.md) for common usage scenarios
- Review troubleshooting section in README.md
- Open an issue in the repository

## Uninstallation

To remove the audit tool:

```bash
# Remove script
sudo rm /usr/local/bin/drupal-audit

# Remove wrapper script
rm /path/to/run-audit.sh

# Optionally remove dependencies
# (Only if not used by other applications)
# sudo apt remove gitleaks  # Linux
# brew uninstall gitleaks   # macOS
```

---

**Installation Complete!** 🎉

You're now ready to start auditing your Drupal applications.
