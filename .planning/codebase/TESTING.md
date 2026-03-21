# Testing Patterns

**Analysis Date:** 2026-03-21

## Test Framework & Infrastructure

**Current State:** No formal automated testing framework configured
- No PHPUnit configuration files found
- No Jest, Vitest, or other JavaScript test runners
- No Composer dependencies for testing
- Manual testing approach in place

**Manual Testing Tools Available:**
- Test scripts included in repository for manual verification
- Browser-based testing utilities for domain validation and debug

## Manual Testing Scripts

**Location:** Plugin root directory

**1. Domain Validation Tester**
- File: `test-domain-validation.php`
- Access: Must load WordPress and authenticate as admin
- Purpose: Verify domain validation logic works correctly
- Usage:
  ```
  /test-domain-validation.php (after uploading to plugin directory)
  ```
- What it tests:
  - Reads `admin_login_sso_allowed_domains` option from database
  - Parses domains using `wp_parse_list()`
  - Tests specific email addresses against domain rules
  - Supports exact match and wildcard matching (*.domain.com)
  - Shows results in HTML table format

**2. Domain Debug Tool**
- File: `debug-domains.php`
- Access: Requires admin user and WP_DEBUG enabled
- Purpose: Debug domain parsing and validation issues
- Shows:
  - Raw domain values from database
  - Parsed domain arrays
  - Character-by-character analysis of domain strings

**3. Emergency Bypass Tool**
- File: `emergency-bypass.php`
- Purpose: Temporarily disable SSO for recovery (5-hour bypass)
- Contains:
  - Settings inspection
  - Bypass activation/deactivation controls
  - Detailed debug output of current configuration

## Testing Approach

**Manual Testing Workflow:**

1. **Configuration Testing:**
   - Verify plugin activation creates default options
   - Check settings page renders correctly
   - Validate input sanitization in settings form

2. **Domain Validation Testing:**
   - Use `test-domain-validation.php` for domain logic verification
   - Test email domain extraction: `user@example.com` → `example.com`
   - Test exact domain matching: allowed domain `example.com` matches email `user@example.com`
   - Test wildcard matching: allowed domain `*.example.com` matches `user@sub.example.com`
   - Test negative cases: unauthorized domains are rejected

3. **OAuth Flow Testing:**
   - Use "Test Google Login" button in settings (appears when credentials configured)
   - Opens new window to Google OAuth consent screen
   - Verifies redirect back to `wp-login.php?action=admin_login_sso_callback`
   - Checks error handling if CSRF state parameter missing

4. **User Authentication Testing:**
   - Existing user login: User with matching email domain
   - New user creation: With auto-create enabled, new user should be created as admin
   - Permission checking: Non-admin users should receive "insufficient permissions" error
   - Logout: Token revocation via Google API

5. **Admin Access Restriction Testing:**
   - SSO enabled: Only Google-authenticated users access admin
   - SSO disabled: Standard WordPress login allowed
   - Emergency bypass: Can temporarily allow standard login
   - Super admin setup: Super admins can configure before enforcement

## Testing Best Practices (For Future Automated Tests)

**Pattern for Unit Testing Class Methods:**

When adding automated tests, follow this structure:

```php
// Test should focus on one method or behavior
// Use mock WordPress functions where needed
// Return type assertions with WP_Error checks

// Example pattern to follow:
$result = $user_handler->process_user($user_info);
if (is_wp_error($result)) {
    // Check error code
    $this->assertEquals('missing_email', $result->get_error_code());
} else {
    // Check returned WP_User object
    $this->assertInstanceOf('WP_User', $result);
}
```

**Testing Domain Validation Logic:**

The `validate_email_domain()` method should be tested with:
- Empty domain list (should fail)
- Exact domain matches
- Wildcard subdomain matches (*.example.com)
- Invalid email formats
- Case-insensitive comparison
- Whitespace handling

Location: `class-admin-login-sso-auth.php:386-450`

**Testing Sanitization Functions:**

The following sanitization methods should have test coverage:

1. `sanitize_domains()` - `class-admin-login-sso.php:183-240`
   - Tests: Invalid domain rejection, valid domain acceptance, comma-separated parsing

2. `sanitize_checkbox()` - `class-admin-login-sso.php:248-278`
   - Tests: Returns '1' for checked, '0' for unchecked, validation when enabling

3. `sanitize_client_id()` - `class-admin-login-sso.php:286-306`
   - Tests: Format validation (must end with .apps.googleusercontent.com)

4. `sanitize_client_secret()` - `class-admin-login-sso.php:314-333`
   - Tests: Length validation (minimum 10 characters)

## Testing Critical Paths

**OAuth Token Exchange (`get_token()` method):**
- File: `class-admin-login-sso-auth.php:304-344`
- Tests needed:
  - Valid authorization code → token response
  - Missing credentials → return false
  - Network error → log and return false
  - Invalid token response (missing access_token) → log and return false

**User Authentication (`process_user()` method):**
- File: `class-admin-login-sso-user.php:25-57`
- Tests needed:
  - Existing user with matching email → authenticate
  - Existing non-admin user → insufficient_permissions error
  - Non-existing user with auto-create disabled → user_not_found error
  - Non-existing user with auto-create enabled → create as administrator

**Access Restriction (`restrict_admin_access()` method):**
- File: `class-admin-login-sso-auth.php:492-590`
- Tests needed:
  - Non-authenticated user → redirect to login
  - Google-authenticated super admin during setup → allow access
  - Google-authenticated super admin after setup → normal restrictions apply
  - Emergency bypass active → allow standard login

## Coverage Gaps (Current)

**No test coverage for:**
- OAuth state parameter validation (CSRF protection)
- HTTP request error handling (wp_remote_post/wp_remote_get failures)
- Settings validation and error messages
- User metadata storage and retrieval
- Token revocation on logout
- REST API restriction logic
- Admin notice and message display
- CSS/JS asset enqueue functions
- Internationalization/translation strings

## Debug Logging

**Debug Log Output:**

When `WP_DEBUG_LOG` is enabled, the following are logged:

1. Domain validation steps:
   - Input email and extracted domain
   - Each domain check attempt
   - Wildcard matching logic
   - Final validation result

2. OAuth errors:
   - Token request failures
   - Invalid token responses
   - User info request failures
   - Invalid user data

3. Authentication errors:
   - Any WP_Error during user processing
   - Access restriction violations

Location: `class-admin-login-sso-auth.php:749-754` (log_error method)

**Enabling Debug Logging:**

In `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
// Logs go to: wp-content/debug.log
```

## Future Testing Recommendations

**Priority 1 - Add Unit Tests:**
1. PHPUnit setup for WordPress plugin testing
2. Mock WordPress functions using `Brain\Monkey` or `WP_Mock`
3. Test domain validation logic comprehensively
4. Test sanitization functions for all input types

**Priority 2 - Add Integration Tests:**
1. Test OAuth callback handling with mocked Google responses
2. Test user creation and authentication flow
3. Test settings persistence and validation
4. Test admin access restrictions

**Priority 3 - Manual Testing Checklist:**
Create documented test plan covering:
- Fresh plugin installation and configuration
- SSO enable/disable scenarios
- User login workflows (new, existing, non-admin)
- Error scenarios and recovery
- Domain configuration changes
- Emergency bypass usage

**Priority 4 - Add E2E Tests:**
Consider tools like Cypress or Playwright for:
- Full login flow testing
- Settings page interactions
- Admin page access verification

## Debugging Tools & Commands

**View Debug Log:**
```bash
# SSH into server and tail the debug.log
tail -f wp-content/debug.log | grep "Admin Login SSO"
```

**Test Domain Logic:**
1. Access: `yoursite.com/wp-content/plugins/admin-login-sso-main/test-domain-validation.php`
2. Requires: Admin login + WP_DEBUG enabled
3. Shows: Domain parsing and matching results

**Check Plugin Configuration:**
1. Access: `yoursite.com/wp-content/plugins/admin-login-sso-main/debug-domains.php`
2. Requires: Admin login + WP_DEBUG enabled
3. Shows: Current options and parsed values

**Emergency Recovery:**
1. Access: `yoursite.com/wp-content/plugins/admin-login-sso-main/emergency-bypass.php`
2. Requires: Admin login
3. Action: Disable SSO temporarily (5 hours)

## Manual Test Scenarios

**Scenario 1: Basic Configuration**
1. Activate plugin
2. Go to Settings → Admin Login SSO
3. Verify "Quick Setup Guide" displays
4. Copy redirect URI
5. Create Google OAuth credentials
6. Enter Client ID and Secret
7. Add allowed domains
8. Verify "Test Google Login" button appears
9. Save settings

**Scenario 2: SSO Login Flow**
1. Logout from WordPress
2. Go to wp-login.php
3. Click "Continue with Google"
4. Google login screen appears
5. Complete Google authentication
6. Redirect back to wp-login.php
7. User authenticated and redirected to admin dashboard

**Scenario 3: Domain Validation**
1. Configure allowed domains: `example.com, *.company.org`
2. Test valid logins:
   - user@example.com ✓
   - user@sub.company.org ✓
3. Test invalid logins:
   - user@notexample.com ✗
   - user@wrong.domain.com ✗

**Scenario 4: User Auto-Creation**
1. Enable "Auto-create admin users"
2. Google user with new email logs in
3. WordPress user created automatically as administrator
4. Next login authenticates without manual user creation

**Scenario 5: Emergency Bypass**
1. SSO enabled, locked out
2. Access `emergency-bypass.php`
3. Activate bypass (5 hours)
4. Login with WordPress credentials
5. Fix configuration issue
6. Disable bypass or wait 5 hours for auto-expiration

---

*Testing analysis: 2026-03-21*
