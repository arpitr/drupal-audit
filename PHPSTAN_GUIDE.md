# PHPStan Integration Guide

## What is PHPStan?

PHPStan is a static analysis tool that finds bugs in your PHP code without running it. The `mglaman/phpstan-drupal` extension adds Drupal-specific rules and understanding.

## New Features Added

### 1. Automatic Installation
The script now automatically installs PHPStan with Drupal extensions:
- `phpstan/phpstan` - Core PHPStan
- `mglaman/phpstan-drupal` - Drupal-specific rules
- `phpstan/phpstan-deprecation-rules` - Deprecation detection

### 2. Configuration File Generation
Auto-creates `phpstan.neon` with sensible Drupal defaults:
- Analysis level: 1 (good starting point)
- Excludes: tests, node_modules, vendor
- Drupal root: web
- Includes deprecation rules

### 3. Database Tracking
PHPStan results are stored in SQLite database:
- Total errors
- Files with errors
- Files analyzed
- Historical trends

### 4. Dashboard Integration
New PHPStan card and chart on dashboard showing:
- Total errors (with comparison to previous run)
- Files with errors
- Files analyzed
- Trend over time

## Usage

### Basic Usage

```bash
python3 drupal_security_audit.py /path/to/drupal \
  --phpstan-paths web/modules/custom web/themes/custom
```

### With PHPCS (Both Code Quality Tools)

```bash
python3 drupal_security_audit.py /path/to/drupal \
  --phpcs-paths web/modules/custom web/themes/custom \
  --phpstan-paths web/modules/custom web/themes/custom
```

### Full Audit

```bash
python3 drupal_security_audit.py /path/to/drupal \
  --phpcs-paths web/modules/custom web/themes/custom \
  --phpstan-paths web/modules/custom web/themes/custom \
  --themes-path web/themes/custom
```

## What PHPStan Checks

PHPStan finds:
- **Type errors**: Wrong types passed to functions
- **Undefined variables**: Using variables before they're defined
- **Dead code**: Code that can never be reached
- **Missing return types**: Functions without proper return type hints
- **Deprecated code**: Using deprecated Drupal APIs
- **Invalid method calls**: Calling methods that don't exist
- **Array access issues**: Accessing non-existent array keys
- **Drupal-specific issues**: Hook implementations, service injection, etc.

## Example Output

### Terminal Output

```
================================================================================
                        PHPSTAN STATIC ANALYSIS
================================================================================

Running PHPStan analysis...
Found 15 error(s) in 3 file(s)

  web/modules/custom/my_module/src/Controller/MyController.php:45
    Parameter #1 $nid of method Drupal\node\Entity\Node::load() expects int, string given.
  
  web/modules/custom/my_module/src/Plugin/Block/MyBlock.php:67
    Variable $result might not be defined.
  
  web/modules/custom/my_module/my_module.module:23
    Function my_module_preprocess_node() is deprecated. Use hook_theme_suggestions_HOOK() instead.
  
  ... and 12 more errors
```

### Dashboard Display

**PHPStan Card:**
```
Static Analysis (PHPStan)           [failed]

Total Errors              15    (+5 ↑)
Files with Errors          3
Files Analyzed            42
```

**PHPStan Chart:**
Bar chart showing:
- Errors: 15 (red bar)
- Files with Errors: 3 (orange bar)

## PHPStan Levels

The default level is 1 (basic checks). You can increase strictness:

Edit `phpstan.neon`:
```yaml
parameters:
    level: 5  # 0-9, higher = stricter
```

**Level Guidelines:**
- **Level 0-1**: Basic checks (recommended start)
- **Level 2-4**: Medium strictness (good for most projects)
- **Level 5-7**: Strict type checking
- **Level 8-9**: Maximum strictness (PHP 8.0+ features)

## Configuration

### Custom phpstan.neon

The script creates a default config, but you can customize:

```yaml
includes:
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
        # Ignore specific errors
        - '#Call to deprecated method#'
        - '#in file .*/legacy/.*#'
    
    # Increase memory limit if needed
    # Can also set via command line: --memory-limit=1G
```

### Analyzing Specific Modules

```bash
# Just one module
python3 drupal_security_audit.py /path/to/drupal \
  --phpstan-paths web/modules/custom/my_module

# Multiple specific modules
python3 drupal_security_audit.py /path/to/drupal \
  --phpstan-paths web/modules/custom/module1 web/modules/custom/module2

# Entire custom directory
python3 drupal_security_audit.py /path/to/drupal \
  --phpstan-paths web/modules/custom
```

## Comparison: PHPCS vs PHPStan

| Feature | PHPCS | PHPStan |
|---------|-------|---------|
| **Type** | Code style checker | Static analyzer |
| **Finds** | Formatting issues, style violations | Type errors, logic bugs |
| **Speed** | Fast | Slower |
| **Auto-fix** | Yes (phpcbf) | No |
| **Strictness** | Configurable | Levels 0-9 |
| **Best For** | Code consistency | Bug prevention |

**Recommendation:** Use both!
- PHPCS ensures consistent code style
- PHPStan catches potential bugs

## Troubleshooting

### "Out of memory" Error

Increase memory limit:
```bash
# Edit phpstan.neon or use command line flag
# The script passes --memory-limit=512M by default
```

### Too Many Errors

Start with level 0 or 1:
```yaml
parameters:
    level: 0  # Most permissive
```

Then gradually increase:
```bash
# After fixing level 0 errors
parameters:
    level: 1

# Keep increasing as you fix issues
```

### False Positives

Ignore specific errors in `phpstan.neon`:
```yaml
parameters:
    ignoreErrors:
        # Ignore specific message
        - '#Variable \$node might not be defined#'
        
        # Ignore in specific files
        - 
            message: '#Parameter \$form#'
            path: */legacy/*
```

### Drupal APIs Not Recognized

Make sure you're using the Drupal extension:
```yaml
includes:
    - vendor/mglaman/phpstan-drupal/extension.neon
```

## Integration with CI/CD

### GitHub Actions

```yaml
- name: Run PHPStan
  run: |
    python3 drupal_security_audit.py . \
      --phpstan-paths web/modules/custom \
      --no-dashboard \
      --output audit.json
    
    # Fail if PHPStan found errors
    if [ $? -ne 0 ]; then
      echo "PHPStan found errors!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run PHPStan on staged PHP files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.php$')

if [ -n "$STAGED_FILES" ]; then
    vendor/bin/phpstan analyse $STAGED_FILES --level 1
    if [ $? -ne 0 ]; then
        echo "PHPStan found errors. Fix them before committing."
        exit 1
    fi
fi
```

## Best Practices

1. **Start Low, Go Slow**
   - Begin with level 0 or 1
   - Fix all errors at that level
   - Increase level gradually

2. **Run Regularly**
   - Include in CI/CD pipeline
   - Run before deployments
   - Track trends in dashboard

3. **Focus on New Code**
   - Analyze new modules first
   - Add legacy code gradually
   - Use `excludePaths` for old code

4. **Combine with PHPCS**
   ```bash
   --phpcs-paths web/modules/custom \
   --phpstan-paths web/modules/custom
   ```

5. **Track Progress**
   - Use dashboard to see error trends
   - Set goals (e.g., reduce errors 10% per sprint)
   - Celebrate improvements

## Manual PHPStan Usage

You can also run PHPStan directly:

```bash
# Analyze specific path
vendor/bin/phpstan analyse web/modules/custom --level 1

# With memory limit
vendor/bin/phpstan analyse web/modules/custom --level 1 --memory-limit=1G

# Generate baseline (ignore existing errors)
vendor/bin/phpstan analyse --generate-baseline

# Check against baseline
vendor/bin/phpstan analyse --configuration phpstan.neon
```

## Resources

- [PHPStan Documentation](https://phpstan.org/user-guide/getting-started)
- [PHPStan Drupal Extension](https://github.com/mglaman/phpstan-drupal)
- [PHPStan Rule Levels](https://phpstan.org/user-guide/rule-levels)
- [Drupal PHPStan Guide](https://www.drupal.org/docs/develop/development-tools/phpstan)

## Summary

PHPStan integration adds powerful static analysis to your Drupal audits:

✅ **Automatic installation** - No manual setup needed
✅ **Finds real bugs** - Not just style issues  
✅ **Drupal-aware** - Understands Drupal APIs
✅ **Tracks trends** - See improvements over time
✅ **Dashboard integration** - Visual progress tracking

Use it alongside PHPCS for comprehensive code quality assurance! 🚀
