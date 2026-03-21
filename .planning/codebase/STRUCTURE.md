# Codebase Structure

**Analysis Date:** 2026-03-21

## Directory Layout

```
admin-login-sso-main/
├── admin/                          # Admin interface components
│   └── class-admin-login-sso-admin.php
├── includes/                       # Core functionality classes
│   ├── class-admin-login-sso.php
│   ├── class-admin-login-sso-auth.php
│   └── class-admin-login-sso-user.php
├── assets/                         # Static assets
│   └── css/
│       ├── admin.css
│       └── login.css
├── admin-login-sso.php            # Main plugin entry point
├── emergency-bypass.php            # Emergency access recovery script
├── debug-domains.php               # Domain validation debugging utility
├── test-domain-validation.php      # Domain validation test script
├── DEBUGGING.md                    # Debugging guide
├── README.md                       # Plugin documentation
├── readme.txt                      # WordPress.org readme
└── .planning/                      # Documentation (generated)
    └── codebase/
        ├── ARCHITECTURE.md
        └── STRUCTURE.md
```

## Directory Purposes

**admin/:**
- Purpose: Admin dashboard and settings UI rendering
- Contains: Settings form callbacks, field renderers, activation notices, admin asset enqueuing
- Key files: `class-admin-login-sso-admin.php`
- Instantiated by: `class-admin-login-sso.php` during `init()`

**includes/:**
- Purpose: Core business logic for authentication, user management, and plugin coordination
- Contains: Main plugin orchestrator, OAuth2 handler, user provisioning, dependency loading
- Key files:
  - `class-admin-login-sso.php` - Singleton coordinator
  - `class-admin-login-sso-auth.php` - OAuth2 and access control
  - `class-admin-login-sso-user.php` - User lookup and creation
- Loaded by: Main plugin file during `plugins_loaded` action

**assets/css/:**
- Purpose: Styling for login page and admin interface
- Contains: Google button styling, message boxes, animations, responsive layouts
- Key files:
  - `login.css` - Login form customization (85 lines)
  - `admin.css` - Settings page styling (30 lines)
- Enqueued by: `enqueue_login_assets()` and `enqueue_admin_styles()` in auth and admin classes

**Root level:**
- `admin-login-sso.php` - Plugin entry point (116 lines) with header, constants, hooks
- `emergency-bypass.php` - Standalone utility to disable SSO via direct file access
- `debug-domains.php` - Domain validation tester (displays parsed domains list)
- `test-domain-validation.php` - Unit test script for domain matching logic

## Key File Locations

**Entry Points:**

- `admin-login-sso.php` - Plugin initialization via `plugins_loaded` action hook. Registers activation/deactivation hooks, adds action links to plugins page.
- `wp-login.php?action=admin_login_sso_callback` - OAuth callback endpoint handled by `Admin_Login_SSO_Auth::handle_oauth_callback()`

**Configuration:**

- `wp-admin/options-general.php?page=admin-login-sso` - Settings page rendered by `Admin_Login_SSO_Admin::render_settings_page()`
- WordPress options table keys: `admin_login_sso_client_id`, `admin_login_sso_client_secret`, `admin_login_sso_allowed_domains`, `admin_login_sso_enabled`, `admin_login_sso_auto_create_users`, `admin_login_sso_show_classic_login`

**Core Logic:**

- `includes/class-admin-login-sso.php` - Plugin singleton with settings registration and dependency loading
- `includes/class-admin-login-sso-auth.php` - OAuth2 flow, domain validation, access control (755 lines)
- `includes/class-admin-login-sso-user.php` - User provisioning and authentication (230 lines)

**Testing/Debugging:**

- `emergency-bypass.php` - Sets transient to disable SSO for recovery
- `debug-domains.php` - Outputs parsed allowed domains for debugging
- `test-domain-validation.php` - Test script for domain matching logic

## Naming Conventions

**Files:**
- Class files: `class-{plugin-prefix}-{component}.php`
  - Example: `class-admin-login-sso-auth.php`, `class-admin-login-sso-user.php`
- Utilities: `{function}-{purpose}.php`
  - Example: `emergency-bypass.php`, `debug-domains.php`, `test-domain-validation.php`
- Plugin entry: `{plugin-slug}.php`
  - Example: `admin-login-sso.php`

**Directories:**
- Functional grouping: `admin/`, `includes/`, `assets/`
- Asset subdirectories: `assets/css/`, `assets/js/` (js not used currently)

**Classes:**
- Format: `Admin_Login_SSO` with components `Admin_Login_SSO_Auth`, `Admin_Login_SSO_User`, `Admin_Login_SSO_Admin`
- Prefix: `Admin_Login_SSO` for all classes (matches plugin slug capitalized)

**Methods:**
- camelCase throughout all methods
- Descriptive names indicating purpose: `get_auth_url()`, `validate_email_domain()`, `process_user_login()`, `handle_oauth_callback()`
- Private methods prefixed with context: `get_token()`, `get_user_info()` (both private)
- Callback methods use `{action}_callback()` pattern: `enabled_callback()`, `client_id_callback()`, `allowed_domains_callback()`

**Functions:**
- Global functions use `admin_login_sso_{purpose}()` format
  - Examples: `admin_login_sso_init()`, `admin_login_sso_activate()`, `admin_login_sso_deactivate()`, `admin_login_sso_plugin_action_links()`, `admin_login_sso_plugin_row_meta()`

**Constants:**
- Uppercase with plugin prefix: `ADMIN_LOGIN_SSO_VERSION`, `ADMIN_LOGIN_SSO_PLUGIN_DIR`, `ADMIN_LOGIN_SSO_PLUGIN_URL`, `ADMIN_LOGIN_SSO_USER_AGENT`
- OAuth endpoints as class constants in `Admin_Login_SSO_Auth`: `GOOGLE_AUTHORIZE_URL`, `GOOGLE_TOKEN_URL`, `GOOGLE_USER_INFO_URL`, `GOOGLE_REVOKE_URL`, `STATE_EXPIRATION`

**Options (Settings):**
- Format: `admin_login_sso_{setting_name}`
  - `admin_login_sso_client_id` - Google OAuth2 client ID
  - `admin_login_sso_client_secret` - Google OAuth2 secret
  - `admin_login_sso_allowed_domains` - Comma-separated email domains
  - `admin_login_sso_enabled` - Boolean flag (stored as '0' or '1')
  - `admin_login_sso_auto_create_users` - Boolean flag
  - `admin_login_sso_show_classic_login` - Boolean flag
  - `admin_login_sso_emergency_bypass` - Unix timestamp for temporary disable

**User Metadata:**
- Format: `admin_login_sso_{data_type}`
  - `admin_login_sso_authenticated` - Authentication flag ('1' or empty)
  - `admin_login_sso_google_id` - Google user ID (sub claim)
  - `admin_login_sso_picture` - Google profile picture URL
  - `admin_login_sso_access_token` - OAuth access token (for logout/revocation)
  - `admin_login_sso_last_login` - Unix timestamp of last login
  - `admin_login_sso_restriction_notice` - First-time setup notice flag

**Hooks & Actions:**
- Custom actions: None defined
- Custom filters: None defined
- WordPress hooks used: `plugins_loaded`, `admin_init`, `admin_menu`, `admin_enqueue_scripts`, `admin_notices`, `login_form`, `login_enqueue_scripts`, `login_message`, `init`, `wp_logout`, `wp_login`, `rest_authentication_errors`, `plugin_action_links_*`, `plugin_row_meta`

## Where to Add New Code

**New Feature (OAuth/Auth-related):**
- Primary code: `includes/class-admin-login-sso-auth.php`
  - Follows existing pattern of public methods for hooks, private methods for implementation
  - Example: New provider would need new constants and token exchange method
- Tests: Use `test-domain-validation.php` as template for new test scripts

**New User Handling Feature:**
- Implementation: `includes/class-admin-login-sso-user.php`
  - Update `update_user_meta()` to store additional data
  - Update `user_can_access_admin()` for new permission logic
- Example: Storing additional Google profile data like department/organization

**New Admin Setting:**
- Settings registration: `includes/class-admin-login-sso.php` in `register_settings()` method
- Settings sanitization: Add method in `class-admin-login-sso.php` following `sanitize_*()` pattern
- Settings field: `admin/class-admin-login-sso-admin.php` in `register_settings_sections()` and add callback method
- Field callback: Add method in `admin/class-admin-login-sso-admin.php` following `{field_name}_callback()` pattern

**New Asset/Style:**
- Login page styles: `assets/css/login.css` (enqueued by `enqueue_login_assets()`)
- Admin page styles: `assets/css/admin.css` (enqueued by `enqueue_admin_styles()`)
- JavaScript: Create `assets/js/{purpose}.js` and enqueue in appropriate callback method

**New Utility/Helper:**
- Emergency/debug utilities: Root level `{verb}-{noun}.php` (see `emergency-bypass.php`, `debug-domains.php` pattern)
- Shared utilities: Consider adding to `includes/` as new class if reused across components

## Special Directories

**assets/:**
- Purpose: Static resources for styling
- Generated: No
- Committed: Yes, all files are source-controlled
- CSS organization: Separate files for login page vs admin interface

**.planning/codebase/:**
- Purpose: Generated architecture documentation
- Generated: Yes (by GSD mapper)
- Committed: Yes (documentation for reference)
- Contents: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md (quality focus), TESTING.md (quality focus)

**.git/:**
- Purpose: Version control repository
- Generated: Yes
- Committed: N/A (git internal)

**.claude/:**
- Purpose: Claude-specific configuration
- Generated: Yes
- Committed: Partial (settings.local.json may contain local settings)
- Contains: settings.local.json for local development configuration

