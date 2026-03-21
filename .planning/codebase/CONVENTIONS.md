# Coding Conventions

**Analysis Date:** 2026-03-21

## Language & Type Safety

**PHP Standard:**
- PHP 8.0+ required with strict types enabled
- All files start with `declare(strict_types=1);` at the top
- Type declarations used in function parameters and return types (e.g., `validate_email_domain(string $email): bool`)

**Verification:**
- `<?php` declaration with `declare(strict_types=1);` - See `includes/class-admin-login-sso-auth.php:1-2`
- Type-hinted method parameters throughout codebase

## Naming Patterns

**Files:**
- Class files use snake_case prefixed with `class-`: `class-admin-login-sso.php`, `class-admin-login-sso-auth.php`
- Location: Classes in `includes/` for core logic, `admin/` for admin-specific functionality
- Standalone test/utility scripts: kebab-case with prefix like `test-domain-validation.php`, `debug-domains.php`, `emergency-bypass.php`

**Classes:**
- PascalCase with underscores separating words: `Admin_Login_SSO`, `Admin_Login_SSO_Auth`, `Admin_Login_SSO_User`, `Admin_Login_SSO_Admin`
- Pattern: `Namespace_Class_SubFeature`

**Functions:**
- snake_case for global functions and hooks: `admin_login_sso_init()`, `admin_login_sso_activate()`, `admin_login_sso_plugin_action_links()`
- Private methods use underscore prefix convention: `private function get_token()`, `private function validate_email_domain()`
- Callback functions: `sanitize_checkbox()`, `enabled_callback()`, `client_id_callback()`

**Variables:**
- snake_case for all variables: `$client_id`, `$allowed_domains`, `$user_info`, `$email_domain`
- Transient keys use snake_case with plugin prefix: `admin_login_sso_error`, `admin_login_sso_state_{state}`, `admin_login_sso_authenticated`
- User metadata keys use snake_case: `admin_login_sso_google_id`, `admin_login_sso_picture`, `admin_login_sso_authenticated`

**Constants:**
- SCREAMING_SNAKE_CASE for plugin constants: `ADMIN_LOGIN_SSO_VERSION`, `ADMIN_LOGIN_SSO_PLUGIN_DIR`, `ADMIN_LOGIN_SSO_USER_AGENT`
- Class constants for URLs: `const GOOGLE_AUTHORIZE_URL = 'https://...'`, `const STATE_EXPIRATION = 300`

## Code Style

**Formatting:**
- PSR-12 style conventions followed
- 4-space indentation (no tabs)
- Opening braces on same line: `public function init() {`
- Closing braces on own line at same indentation as opening statement

**Array Formatting:**
```php
$auth_params = array(
    'client_id' => $client_id,
    'redirect_uri' => esc_url_raw($this->get_redirect_uri()),
    'response_type' => 'code',
);
```

**Spacing:**
- Spaces around operators: `if (!$this->is_enabled())`, `!empty($input)`
- No space after function name in calls: `get_option('admin_login_sso_client_id')`
- Space after control structures: `if (...)`, `foreach (...)`

## Documentation & Comments

**File Headers:**
All class files include docblock at top with `@package` tag:
```php
/**
 * Authentication handler class
 *
 * @package Admin_Login_SSO
 */
```

**Method Documentation:**
- All public and protected methods documented with PHPDoc format
- Includes `@param` tags with type and description
- Includes `@return` tags with type and description
- See example: `class-admin-login-sso-auth.php:75-80` (display_login_messages method)

**Inline Comments:**
- Used for non-obvious logic: `// Generate and store a state parameter to prevent CSRF`
- Explanation comments above code blocks explain the "why"
- Debug comments with context: `// Allow wildcards in domains, e.g., *.example.com`

**DocBlock Pattern:**
```php
/**
 * Exchange authorization code for access token
 *
 * @param string $code Authorization code
 * @return array|false Token data or false on failure
 */
private function get_token($code)
```

## Security & Escaping Patterns

**Input Sanitization:**
- All `$_GET` parameters sanitized with appropriate functions before use
- Email inputs: `is_email()` validation applied - See `class-admin-login-sso-user.php:32`
- Text fields: `sanitize_text_field()` - See `class-admin-login-sso-auth.php:237-238`
- Textarea: `sanitize_textarea_field()` - See `class-admin-login-sso.php:184`
- Keys/IDs: `sanitize_key()` - See `class-admin-login-sso-auth.php:244`
- User input: `sanitize_user()` - See `class-admin-login-sso-user.php:153`

**Output Escaping:**
- HTML context: `esc_html()` for plain text, `esc_attr()` for HTML attributes
- URLs: `esc_url()` or `esc_url_raw()` depending on context
- POST/JavaScript: `esc_js()` - See `class-admin-login-sso-admin.php:202`
- Textarea output: `esc_textarea()` - See `class-admin-login-sso-admin.php:151`
- Rich HTML from wp_kses: `wp_kses_post()` - See `class-admin-login-sso-auth.php:113`

**Pattern Example:**
```php
$error_code = sanitize_text_field($_GET['error']);
set_transient('admin_login_sso_error', array(
    'code' => $code,
    'message' => $message
), 60);
echo '<p>' . wp_kses_post($error['message']) . '</p>';
```

## Error Handling

**Strategy:**
- Return `WP_Error` objects for errors from functions that process critical operations
- Error messages stored in transients for display on login page
- Log errors to `debug.log` when `WP_DEBUG_LOG` enabled

**Pattern:**
```php
if (empty($user_info['email'])) {
    return new WP_Error('missing_email', __('Error message', 'admin-login-sso'));
}

// Check for errors
if (is_wp_error($user)) {
    $this->handle_error('login_failed', $user->get_error_message());
    return;
}
```

**Validation with Feedback:**
- `add_settings_error()` used to show validation errors in settings page
- Domain validation example: `class-admin-login-sso.php:216-226`
- Returns sanitized value on success or empty string on validation failure

## PHP 8.0 Compatibility

**Polyfills provided:**
Plugin includes polyfills for `str_starts_with()` and `str_ends_with()` since they were added in PHP 8.0.0
- See `class-admin-login-sso-auth.php:14-31`
- Checked with `if (!function_exists(...))` before defining

**Modern PHP Features Used:**
- Type declarations: `(string $email): bool`
- Match expressions: Not used (preferring if/else for compatibility)
- Named arguments: Not used
- Union types: Not used

## Import Organization

**Include Pattern:**
- Direct `require_once` with full paths
- Path uses plugin constants: `require_once ADMIN_LOGIN_SSO_PLUGIN_DIR . 'includes/class-admin-login-sso.php'`
- See main plugin file: `admin-login-sso.php:31`

**No use of namespaces** - Traditional WordPress plugin structure maintained

## WordPress Conventions

**Action & Filter Hooks:**
- Snake_case hook names: `'plugins_loaded'`, `'admin_init'`, `'login_form'`
- Custom hooks follow pattern: `'admin_login_sso_' . $feature`
- Parameters passed as array to callbacks: `add_action('admin_init', array($this, 'register_settings'))`

**Settings & Options:**
- Option keys use plugin prefix: `admin_login_sso_client_id`, `admin_login_sso_enabled`
- User metadata keys use prefix: `admin_login_sso_authenticated`
- All stored/retrieved via `get_option()`, `update_option()`, `get_user_meta()`, `update_user_meta()`

**Transients:**
- Used for temporary data like OAuth state and error messages
- Key pattern: `admin_login_sso_` + feature + optional suffix
- Expiration set explicitly: `set_transient('admin_login_sso_error', $data, 60);`

**Internationalization:**
- All user-facing strings wrapped in `__()` or `_e()`
- Text domain: `'admin-login-sso'`
- Example: `__('Enable Google-Only Admin Login', 'admin-login-sso')`

## Class Design

**Constructor Pattern:**
Classes initialize dependencies in constructor and register hooks in `init()` method
```php
public function __construct() {
    $this->load_dependencies();
}

public function init() {
    add_action('admin_init', array($this, 'register_settings'));
}
```

**Singleton Pattern (Optional):**
Main class uses optional singleton: `get_instance()` method available but not enforced
- See `class-admin-login-sso.php:340-345`

**Callback Methods:**
Settings field callbacks follow naming convention: `{field}_callback()`
- `enabled_callback()`, `client_id_callback()`, `allowed_domains_callback()`
- See `class-admin-login-sso-admin.php`

## Control Flow

**Conditions:**
- Early returns to reduce nesting: `if (!condition) { return; }`
- Explicit string comparisons: `if ('1' === $value)` instead of truthy checks
- Boolean casts for clarity: `(bool) get_user_meta(...)`

**Loops:**
- `foreach` preferred over `for` when iterating collections
- Array functions like `explode()`, `array_map()`, `implode()` used appropriately
- Example: `class-admin-login-sso-user.php:69-71` (map roles to display names)

## Performance Considerations

**HTTP Requests:**
- `wp_remote_post()` and `wp_remote_get()` used with timeout: 10 seconds
- See `class-admin-login-sso-auth.php:313-329`

**Database:**
- Options fetched with `get_option()` - uses WordPress cache internally
- User meta accessed directly via `get_user_meta()` / `update_user_meta()`

**Transients:**
- Short expiration for temporary data (60 seconds for errors/messages, 300 for OAuth state)
- Cleaned up explicitly after use when possible

---

*Convention analysis: 2026-03-21*
