# Debugging Domain Validation Issues

If you're experiencing "domain_not_allowed" errors, follow these steps to debug:

## 1. Enable WordPress Debug Logging

Add these lines to your `wp-config.php`:

```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
```

## 2. Check Debug Scripts

Two debug scripts are included to help diagnose issues:

### A. Domain Validation Test (`test-domain-validation.php`)
Access: `https://yoursite.com/wp-content/plugins/admin-login-sso/test-domain-validation.php`

This script will:
- Show raw domain settings from database
- Test wp_parse_list() parsing
- Validate test email addresses
- Check PHP function availability

### B. Domain Settings Debug (`debug-domains.php`)
Access: `https://yoursite.com/wp-content/plugins/admin-login-sso/debug-domains.php`

This script will:
- Display all plugin settings
- Show byte-level analysis of domain strings
- Test live domain validation
- Display recent debug log entries
- Provide a form to update domains

## 3. Common Issues and Solutions

### Issue: Domains appear correct but validation fails

**Possible causes:**
1. **Hidden characters**: The domain string may contain invisible characters (spaces, tabs, etc.)
2. **Encoding issues**: UTF-8 vs ASCII encoding problems
3. **Line breaks**: Multiple domains on separate lines instead of comma-separated

**Solution:**
1. Re-type domains manually (don't copy-paste)
2. Use the debug script to see byte values
3. Ensure domains are comma-separated on a single line

### Issue: Wildcard domains not working

**Format requirements:**
- Wildcard domains must start with `*.`
- Example: `*.example.com` (correct)
- Example: `*example.com` (incorrect)

**What matches:**
- `*.example.com` matches:
  - `sub.example.com`
  - `deep.sub.example.com`
  - `example.com` (the base domain itself)
- Does NOT match:
  - `notexample.com`
  - `example.co.uk`

### Issue: Multiple domains not recognized

**Correct format:**
```
example.com, gmail.com, *.company.org
```

**Common mistakes:**
- Using semicolons instead of commas
- Adding quotes around domains
- Including protocols (http://)
- Including paths (/path)

## 4. Check Debug Log

After attempting login, check the debug log at:
`wp-content/debug.log`

Look for entries starting with `[Admin Login SSO]` for detailed validation steps.

## 5. Manual Database Check

If needed, check the database directly:

```sql
SELECT option_value 
FROM wp_options 
WHERE option_name = 'admin_login_sso_allowed_domains';
```

## 6. Test with Simple Domain First

1. Start with a single, simple domain (e.g., `gmail.com`)
2. Test login with that domain
3. Gradually add more complex domains

## 7. PHP Version Compatibility

Ensure PHP 8.0+ for full compatibility. The plugin includes polyfills but native support is preferred.

## Need Help?

If issues persist after following these steps:
1. Run both debug scripts
2. Copy the output
3. Check debug.log for recent entries
4. Report with this information