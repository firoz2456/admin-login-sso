# Architecture

**Analysis Date:** 2026-03-21

## Pattern Overview

**Overall:** Plugin-based authentication middleware with OAuth2 integration

**Key Characteristics:**
- WordPress plugin architecture using hooks and actions
- OAuth2 flow integration with Google as identity provider
- Domain-based access control for admin login
- User provisioning with role validation
- Emergency bypass mechanism for lockout recovery

## Layers

**Plugin Entry Point:**
- Purpose: Initialize plugin lifecycle and register hooks
- Location: `admin-login-sso.php`
- Contains: Plugin header, constants, activation/deactivation handlers, plugin action links
- Depends on: WordPress core hooks, `class-admin-login-sso.php`
- Used by: WordPress plugin loader

**Core Plugin Manager:**
- Purpose: Orchestrate plugin initialization and dependency loading
- Location: `includes/class-admin-login-sso.php`
- Contains: Singleton instance, settings registration, text domain loading, dependency injection
- Depends on: `class-admin-login-sso-auth.php`, `class-admin-login-sso-admin.php`, `class-admin-login-sso-user.php`
- Used by: Plugin entry point via `admin_login_sso_init()`

**Authentication Layer:**
- Purpose: Handle OAuth2 flow, login form modification, access control enforcement
- Location: `includes/class-admin-login-sso-auth.php`
- Contains: Google OAuth endpoints, CSRF state management, token exchange, user info retrieval, domain validation, redirect logic
- Depends on: WordPress HTTP API (`wp_remote_*`), Google OAuth2 API
- Used by: WordPress hooks system (`login_form`, `login_enqueue_scripts`, `admin_init`, `wp_logout`)

**User Handler Layer:**
- Purpose: Process user login/creation and meta management
- Location: `includes/class-admin-login-sso-user.php`
- Contains: User lookup, permission checking, user creation, username generation, metadata storage
- Depends on: WordPress user functions (`get_user_by`, `wp_insert_user`, `get_user_meta`)
- Used by: `class-admin-login-sso-auth.php` during callback processing

**Admin Settings Layer:**
- Purpose: Render settings UI and handle field callbacks
- Location: `admin/class-admin-login-sso-admin.php`
- Contains: Settings form, field renderers, activation notices, asset enqueuing
- Depends on: WordPress settings API, `class-admin-login-sso-auth.php` (for test login button)
- Used by: `class-admin-login-sso.php` during admin initialization

**Presentation Layer:**
- Purpose: Style login form and admin interface
- Location: `assets/css/login.css`, `assets/css/admin.css`
- Contains: Google button styling, message boxes, responsive layouts, animation effects
- Used by: Login page and admin settings page via `wp_enqueue_style()`

## Data Flow

**OAuth2 Authentication Flow:**

1. User navigates to `/wp-login.php` (admin-targeted)
2. `modify_login_form()` hook renders Google button (if enabled)
3. User clicks "Continue with Google"
4. `get_auth_url()` generates authorization URL with state parameter
5. State stored in transient (5 min expiration) for CSRF protection
6. User redirected to Google OAuth2 consent screen
7. Google redirects to `wp-login.php?action=admin_login_sso_callback` with code + state
8. `handle_oauth_callback()` verifies state and code
9. `get_token()` exchanges code for access token via Google API
10. `get_user_info()` retrieves email, name, profile via access token
11. `validate_email_domain()` checks email domain against allowed list
12. `process_user_login()` finds user by email or creates new user
13. User metadata updated with Google ID, picture, auth flag
14. Auth cookies set via `wp_set_auth_cookie()`
15. User redirected to admin dashboard

**Admin Access Restriction Flow:**

1. User attempts to access admin page
2. `restrict_admin_access()` hook checks SSO enabled state
3. If emergency bypass active, allow access
4. Check if user marked as Google authenticated via `admin_login_sso_authenticated` meta
5. If not authenticated, clear cookies and redirect to login
6. Display reauth message in transient

**REST API Protection Flow:**

1. Request to `/wp-json/wp/v2/*` endpoint
2. `restrict_rest_api()` checks if user has edit capability
3. If user has edit capability but not Google authenticated, return 403 Forbidden
4. Otherwise, allow normal authentication flow

**State Management:**

- **Transient-based:** OAuth state, error messages, reauth messages (60-300 sec expiration)
- **User metadata:** Google ID, profile picture, authentication flag, access token, last login timestamp
- **WordPress options:** Client ID, Client Secret, allowed domains, enable flag, auto-create flag, show classic login flag

## Key Abstractions

**OAuth2 Client:**
- Purpose: Encapsulate Google OAuth2 protocol details
- Location: `includes/class-admin-login-sso-auth.php` (constants + methods)
- Pattern: Static constants for endpoints, instance methods for flow
- Methods: `get_auth_url()`, `get_token()`, `get_user_info()`, `handle_oauth_callback()`

**Domain Validator:**
- Purpose: Match email domains against whitelist with wildcard support
- Location: `includes/class-admin-login-sso-auth.php` (`validate_email_domain()` method)
- Pattern: Parses comma-separated domain list, supports exact and wildcard matching (`*.example.com`)
- Returns: Boolean with logging for debugging

**User Manager:**
- Purpose: Provision and authenticate WordPress users from OAuth profile
- Location: `includes/class-admin-login-sso-user.php`
- Pattern: Separate concerns for user lookup, creation, and permission checking
- Capabilities checked: `manage_options`, `edit_posts`, `publish_posts`, `edit_published_posts`, `edit_others_posts`

**Settings Manager:**
- Purpose: Centralize credential and policy storage
- Location: WordPress options table (prefixed `admin_login_sso_*`)
- Keys: `client_id`, `client_secret`, `allowed_domains`, `enabled`, `auto_create_users`, `show_classic_login`
- Sanitization: Custom callbacks in `class-admin-login-sso.php` with validation rules

## Entry Points

**Plugin Activation:**
- Location: `admin-login-sso.php` (`register_activation_hook`)
- Triggers: When plugin installed
- Responsibilities: Initialize options table, set default values, flush rewrite rules, show activation transient

**Plugin Deactivation:**
- Location: `admin-login-sso.php` (`register_deactivation_hook`)
- Triggers: When plugin disabled
- Responsibilities: Clean up rewrite rules

**Login Page (OAuth Initiation):**
- Location: `includes/class-admin-login-sso-auth.php` (`modify_login_form` hook)
- Triggers: User navigates to admin login
- Responsibilities: Render Google button, enqueue styles, check emergency bypass

**OAuth Callback:**
- Location: `includes/class-admin-login-sso-auth.php` (`handle_oauth_callback` method)
- Triggers: Google redirects to `wp-login.php?action=admin_login_sso_callback`
- Responsibilities: Verify state, exchange code for token, fetch user info, validate domain, login/create user

**Admin Initialization:**
- Location: `admin-login-sso.php` (`plugins_loaded` hook)
- Triggers: WordPress plugins_loaded action
- Responsibilities: Load dependencies, create plugin instance, call `init()`

**Admin Settings Page:**
- Location: `admin/class-admin-login-sso-admin.php` (`render_settings_page` method)
- Triggers: User navigates to Settings > Admin Login SSO
- Responsibilities: Display form, show setup instructions, connection status, test button

**Admin Access Control:**
- Location: `includes/class-admin-login-sso-auth.php` (`restrict_admin_access` hook)
- Triggers: `admin_init` WordPress action
- Responsibilities: Check authentication status, enforce re-login, show notices for first-time setup

## Error Handling

**Strategy:** Transient-based error storage with display on login page

**Patterns:**

- **OAuth errors:** Stored in transient `admin_login_sso_error` (60 sec), displayed above login form
- **Validation errors:** Settings errors added via `add_settings_error()`, display in settings page
- **User creation failures:** `WP_Error` returned with descriptive messages (insufficient permissions, missing email, etc.)
- **Token exchange failures:** Logged to `debug.log` if `WP_DEBUG_LOG` enabled, generic error shown to user
- **Domain validation failures:** Logged with specific domain values for troubleshooting

**Error codes returned:**
- `invalid_state`: CSRF token mismatch
- `missing_code`: Authorization code not received
- `token_error`: Token exchange failed
- `userinfo_error`: User info retrieval failed
- `domain_not_allowed`: Email domain not whitelisted
- `login_failed`: User creation/auth failed
- `user_not_found`: User doesn't exist and auto-create disabled
- `insufficient_permissions`: User exists but lacks admin capabilities
- `missing_email`: Google account missing email
- `invalid_email`: Email format invalid

## Cross-Cutting Concerns

**Logging:** Error logging to `debug.log` when `WP_DEBUG_LOG` constant defined. All OAuth and domain validation errors logged with context.

**Validation:**
- Email format validation via `is_email()`
- Domain format validation in settings via regex (`/^(\*\.)?([\w-]+\.)+[\w-]{2,}$/`)
- Client ID format validation in settings via Google domain suffix check
- Client secret length validation (minimum 10 chars)

**Authentication:**
- CSRF protection via state parameter (stored in transient, 5 min expiration)
- User permission checking via capability list (administrator role or specific capabilities)
- Session management via `wp_set_auth_cookie()` and `wp_clear_auth_cookie()`
- Google token revocation on logout via `handle_logout()` hook

**Security:**
- Emergency bypass mechanism: `admin_login_sso_emergency_bypass` option stores Unix timestamp
- Super admin bypass during initial setup for configuration access
- REST API restriction for users with edit capabilities
- Nonce and sanitization for all user inputs via WordPress functions

