#!/bin/bash
#
# Drupal Security Audit Wrapper Script
# Makes it easier to run the audit with common configurations
#
# Usage: ./run-audit.sh [profile]
# Profiles: quick, full, ci, custom

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - Customize these paths for your project
DRUPAL_ROOT="/Users/arpitrastogi/workspace/drupal-test"
SCRIPT_PATH="$(dirname "$0")/drupal_security_audit.py"
PHPCS_PATHS="web/modules/custom web/themes/custom"
PHPSTAN_PATHS="web/modules/custom web/themes/custom"
THEMES_PATH="web/themes/custom"
OUTPUT_DIR="./audit-reports"

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if ! command -v composer &> /dev/null; then
        missing_tools+=("composer")
    fi
    
    if ! command -v gitleaks &> /dev/null; then
        missing_tools+=("gitleaks")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_error "Please install them before running the audit."
        exit 1
    fi
    
    print_info "All prerequisites satisfied ✓"
}

# Function to check if the script exists
check_script() {
    if [ ! -f "$SCRIPT_PATH" ]; then
        print_error "Audit script not found at: $SCRIPT_PATH"
        print_error "Please download drupal_security_audit.py first."
        exit 1
    fi
}

# Function to create output directory
prepare_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_info "Created output directory: $OUTPUT_DIR"
    fi
}

# Profile: Quick audit (Composer + Gitleaks only)
run_quick_audit() {
    print_info "Running QUICK audit (Composer + Gitleaks)..."
    print_info "This will take approximately 1-2 minutes"
    echo ""
    
    python3 "$SCRIPT_PATH" "$DRUPAL_ROOT"
    
    echo ""
    print_info "Quick audit completed!"
}

# Profile: Full audit (All checks)
run_full_audit() {
    print_info "Running FULL audit (All checks)..."
    print_info "This may take 5-10 minutes depending on codebase size"
    echo ""
    
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local output_file="$OUTPUT_DIR/full-audit-$timestamp.json"
    
    python3 "$SCRIPT_PATH" "$DRUPAL_ROOT" \
        --phpcs-paths $PHPCS_PATHS \
        --phpstan-paths $PHPSTAN_PATHS \
        --themes-path "$THEMES_PATH" \
        --output "$output_file"
    
    echo ""
    print_info "Full audit completed!"
    print_info "Report saved to: $output_file"
}

# Profile: CI/CD audit (Full audit with strict exit codes)
run_ci_audit() {
    print_info "Running CI/CD audit..."
    echo ""
    
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local output_file="$OUTPUT_DIR/ci-audit-$timestamp.json"
    
    # Run audit and capture exit code
    set +e
    python3 "$SCRIPT_PATH" "$DRUPAL_ROOT" \
        --phpcs-paths $PHPCS_PATHS \
        --phpstan-paths $PHPSTAN_PATHS \
        --themes-path "$THEMES_PATH" \
        --output "$output_file"
    
    local exit_code=$?
    set -e
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_info "✅ CI/CD audit PASSED - No issues found"
        print_info "Report saved to: $output_file"
        exit 0
    else
        print_error "❌ CI/CD audit FAILED - Issues found"
        print_error "Report saved to: $output_file"
        print_error "Review the report and fix issues before deployment"
        exit 1
    fi
}

# Profile: Custom audit (Interactive)
run_custom_audit() {
    print_info "Running CUSTOM audit..."
    echo ""
    
    # Ask user for customization
    read -p "Run PHPCS analysis? (y/n): " run_phpcs
    read -p "Run PHPStan analysis? (y/n): " run_phpstan
    read -p "Scan NPM packages in themes? (y/n): " run_npm
    read -p "Save JSON report? (y/n): " save_report
    
    echo ""
    
    local cmd="python3 $SCRIPT_PATH $DRUPAL_ROOT"
    
    if [[ "$run_phpcs" == "y" ]]; then
        read -p "Enter paths for PHPCS (space-separated, default: $PHPCS_PATHS): " custom_paths
        if [ -n "$custom_paths" ]; then
            cmd="$cmd --phpcs-paths $custom_paths"
        else
            cmd="$cmd --phpcs-paths $PHPCS_PATHS"
        fi
    fi
    
    if [[ "$run_phpstan" == "y" ]]; then
        read -p "Enter paths for PHPStan (space-separated, default: $PHPSTAN_PATHS): " custom_phpstan_paths
        if [ -n "$custom_phpstan_paths" ]; then
            cmd="$cmd --phpstan-paths $custom_phpstan_paths"
        else
            cmd="$cmd --phpstan-paths $PHPSTAN_PATHS"
        fi
    fi
    
    if [[ "$run_npm" == "y" ]]; then
        read -p "Enter themes path (default: $THEMES_PATH): " custom_themes
        if [ -n "$custom_themes" ]; then
            cmd="$cmd --themes-path $custom_themes"
        else
            cmd="$cmd --themes-path $THEMES_PATH"
        fi
    fi
    
    if [[ "$save_report" == "y" ]]; then
        local timestamp=$(date +%Y%m%d-%H%M%S)
        cmd="$cmd --output $OUTPUT_DIR/custom-audit-$timestamp.json"
    fi
    
    echo ""
    print_info "Running: $cmd"
    echo ""
    
    eval "$cmd"
    
    echo ""
    print_info "Custom audit completed!"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [PROFILE]

Profiles:
  quick     Quick audit (Composer + Gitleaks only) - ~1-2 min
  full      Full audit (all checks including PHPStan) - ~5-10 min  
  ci        CI/CD audit (full audit with strict exit codes)
  custom    Custom audit (interactive configuration)

Configuration (edit this script to customize):
  DRUPAL_ROOT   = $DRUPAL_ROOT
  PHPCS_PATHS   = $PHPCS_PATHS
  PHPSTAN_PATHS = $PHPSTAN_PATHS
  THEMES_PATH   = $THEMES_PATH
  OUTPUT_DIR    = $OUTPUT_DIR

Examples:
  $0 quick          # Fast security check
  $0 full           # Comprehensive audit with PHPCS, PHPStan, and report
  $0 ci             # For use in CI/CD pipelines
  $0 custom         # Interactive custom configuration

EOF
}

# Main execution
main() {
    # Check prerequisites first
    check_prerequisites
    check_script
    prepare_output_dir
    
    # Determine which profile to run
    PROFILE="${1:-}"
    
    case "$PROFILE" in
        quick)
            run_quick_audit
            ;;
        full)
            run_full_audit
            ;;
        ci)
            run_ci_audit
            ;;
        custom)
            run_custom_audit
            ;;
        -h|--help|help)
            show_usage
            exit 0
            ;;
        *)
            if [ -z "$PROFILE" ]; then
                print_warn "No profile specified. Showing usage..."
                echo ""
                show_usage
                exit 1
            else
                print_error "Unknown profile: $PROFILE"
                echo ""
                show_usage
                exit 1
            fi
            ;;
    esac
}

# Run main function
main "$@"