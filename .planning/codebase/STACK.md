# Technology Stack

**Analysis Date:** 2026-03-21

## Languages

**Primary:**
- PHP 8.0+ - Core plugin language. Uses strict type declarations throughout codebase (`declare(strict_types=1)` in all class files)
- CSS 3 - Styling for login form and admin interface

**Secondary:**
- HTML 5 - Template markup in admin pages and login form customizations

## Runtime

**Environment:**
- WordPress 6.4+ - Required CMS framework
- PHP 8.0 - Minimum required version per plugin header in `admin-login-sso.php`

**Package Manager:**
- WordPress Core - No external dependency manager (composer/npm)
- Lockfile: Not applicable (no composer.json or package.json)

## Frameworks

**Core:**
- WordPress Hooks API - Used throughout for plugin initialization and customization
  - Action hooks: `plugins_loaded`, `admin_init`, `admin_menu`, `login_form`, `login_enqueue_scripts`, `login_message`, `init`, `wp_logout`, `admin_notices`, `wp_login`
  - Filter hooks: `plugin_action_links`, `plugin_row_meta`, `rest_authentication_errors`
- WordPress Settings API - Configuration storage via `register_setting()` and options management

**Testing:**
- Not detected - No test framework, test files, or test configuration present

**Build/Dev:**
- Not detected - No build tools, bundlers, or development pipelines configured

## Key Dependencies

**Critical:**
- WordPress Core - All functionality depends on WordPress APIs for authentication, user management, and admin interface
  - User functions: `get_user_by()`, `wp_set_auth_cookie()`, `wp_insert_user()`
  - Options functions: `get_option()`, `update_option()`, `add_option()`
  - HTTP functions: `wp_remote_post()`, `wp_remote_get()`, `wp_remote_retrieve_body()`

**Infrastructure:**
- None - Plugin uses only WordPress built-in functions. No third-party PHP packages or SDKs.
- HTTP requests to external APIs handled via WordPress HTTP API (`wp_remote_*` functions)

## Configuration

**Environment:**
- WordPress Options Table - Plugin settings stored in WordPress database via options API
  - `admin_login_sso_client_id` - Google OAuth2 Client ID
  - `admin_login_sso_client_secret` - Google OAuth2 Client Secret
  - `admin_login_sso_allowed_domains` - Comma-separated list of allowed email domains
  - `admin_login_sso_enabled` - Boolean flag to enable/disable SSO
  - `admin_login_sso_auto_create_users` - Boolean flag to auto-create admin users
  - `admin_login_sso_show_classic_login` - Boolean flag to show classic login form as fallback
  - `admin_login_sso_emergency_bypass` - Temporary bypass timestamp for emergency access

- User Meta - Per-user authentication data stored in WordPress user meta:
  - `admin_login_sso_google_id` - Google user ID
  - `admin_login_sso_picture` - Google profile picture URL
  - `admin_login_sso_authenticated` - Flag indicating Google authentication
  - `admin_login_sso_access_token` - OAuth access token
  - `admin_login_sso_last_login` - Timestamp of last successful login

**Build:**
- No build configuration - Plugin is pure PHP, no compilation or bundling step
- Constants defined in `admin-login-sso.php`:
  - `ADMIN_LOGIN_SSO_VERSION` - Plugin version
  - `ADMIN_LOGIN_SSO_PLUGIN_DIR` - Plugin directory path
  - `ADMIN_LOGIN_SSO_PLUGIN_URL` - Plugin URL
  - `ADMIN_LOGIN_SSO_PLUGIN_BASENAME` - Plugin basename
  - `ADMIN_LOGIN_SSO_USER_AGENT` - User-Agent string for HTTP requests

## Platform Requirements

**Development:**
- WordPress 6.4+ installation with database
- PHP 8.0+ CLI for running code
- Text editor for modifying PHP files
- Google Cloud Console account for OAuth credential creation

**Production:**
- WordPress 6.4+ hosted environment
- PHP 8.0+ support on hosting provider
- PHP extension: `json` (for JSON parsing/encoding)
- PHP extension: `curl` or equivalent (for `wp_remote_*` HTTP functions)
- MySQL/MariaDB for WordPress database
- HTTPS endpoint required by Google OAuth2 (redirect_uri must use https)

## Asset Files

**Location:** `assets/css/`
- `login.css` - Styling for login page modifications including Google sign-in button
- `admin.css` - Styling for plugin settings page in WordPress admin

**Enqueue Points:**
- Login assets: Enqueued in `Admin_Login_SSO_Auth::enqueue_login_assets()` (line 177 in `class-admin-login-sso-auth.php`)
- Admin assets: Enqueued in `Admin_Login_SSO_Admin::enqueue_admin_styles()` (line 49 in `class-admin-login-sso-admin.php`)

## Version & Compatibility

**Current Version:** 1.0.0 (defined in `admin-login-sso.php` line 24)

**Backward Compatibility:**
- Plugin includes PHP 8.0 polyfills in `class-admin-login-sso-auth.php` (lines 15-31):
  - `str_starts_with()` - For string checking
  - `str_ends_with()` - For string ending validation
  - These functions are only used if not already defined (native in PHP 8.0+)

---

*Stack analysis: 2026-03-21*
