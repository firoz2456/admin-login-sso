# External Integrations

**Analysis Date:** 2026-03-21

## APIs & External Services

**Google OAuth2:**
- **Service:** Google Cloud OAuth2 API
- **What it's used for:** Admin login authentication, user identity verification
- **Endpoints (defined in `includes/class-admin-login-sso-auth.php`):**
  - Authorization endpoint: `https://accounts.google.com/o/oauth2/v2/auth` (line 42)
  - Token endpoint: `https://oauth2.googleapis.com/token` (line 43)
  - User info endpoint: `https://www.googleapis.com/oauth2/v3/userinfo` (line 44)
  - Revoke endpoint: `https://accounts.google.com/o/oauth2/revoke` (line 45)
- **SDK/Client:** Built-in via WordPress HTTP API (`wp_remote_post()`, `wp_remote_get()`)
- **Auth:** Stored in WordPress options:
  - `admin_login_sso_client_id` - OAuth2 Client ID from Google Cloud Console
  - `admin_login_sso_client_secret` - OAuth2 Client Secret from Google Cloud Console
- **Configuration Location:** Settings page at `/wp-admin/options-general.php?page=admin-login-sso`

## Data Storage

**Databases:**
- **Type:** WordPress Options Table (wp_options)
- **Connection:** Via WordPress database connection (defined in wp-config.php)
- **Client:** WordPress Query API (`get_option()`, `update_option()`, `add_option()`)
- **Data Stored:**
  - Plugin configuration (client_id, client_secret, allowed_domains, enable flag)
  - Emergency bypass timestamp
  - Domain configuration

- **Type:** WordPress User Meta (wp_usermeta)
- **Connection:** Via WordPress database connection
- **Client:** WordPress User Meta API (`get_user_meta()`, `update_user_meta()`)
- **Data Stored (per authenticated user):**
  - `admin_login_sso_google_id` - Google user's unique identifier (sub claim)
  - `admin_login_sso_picture` - Google profile picture URL
  - `admin_login_sso_authenticated` - Flag that user authenticated via Google
  - `admin_login_sso_access_token` - OAuth access token for potential future use
  - `admin_login_sso_last_login` - Timestamp of last successful Google login

**File Storage:**
- Local filesystem only - No external file storage service used

**Caching:**
- WordPress Transients API for temporary data:
  - `admin_login_sso_state_[random]` - CSRF prevention state token (5 minute expiration, line 201 in `class-admin-login-sso-auth.php`)
  - `admin_login_sso_error` - Error messages for login page display (60 second expiration)
  - `admin_login_sso_reauth_required` - Re-authentication required message (60 second expiration)
  - `admin_login_sso_activated` - Activation notice flag (60 second expiration)

## Authentication & Identity

**Primary Auth Provider:**
- **Service:** Google OAuth2
- **Implementation:** OAuth2 Authorization Code flow
  - User clicks "Continue with Google" button
  - Redirected to Google authorization endpoint with scopes: `openid email profile`
  - Google redirects back to `wp-login.php?action=admin_login_sso_callback` (line 223)
  - Plugin exchanges authorization code for access token (method `get_token()` at line 304)
  - Plugin retrieves user info using access token (method `get_user_info()` at line 352)

**Email Domain Validation:**
- Implementation: `validate_email_domain()` method in `class-admin-login-sso-auth.php` (line 386)
- Supports exact matches and wildcard subdomain matches (e.g., `*.example.com`)
- Domains stored in `admin_login_sso_allowed_domains` option

**User Provisioning:**
- **Matching:** By email address using `get_user_by('email', $user_info['email'])` (line 37 in `class-admin-login-sso-user.php`)
- **Auto-creation:** Controlled by `admin_login_sso_auto_create_users` option
  - If enabled: Creates new admin user with generated username from email
  - If disabled: Returns error requiring existing WordPress account (line 49-56)

## Session & Token Management

**OAuth Tokens:**
- Access tokens stored in user meta: `admin_login_sso_access_token`
- Tokens are revoked on logout via Google revoke endpoint (line 473-482 in `class-admin-login-sso-auth.php`)
- CSRF protection via state parameter with 5-minute expiration

**WordPress Session:**
- Standard WordPress authentication cookies set via `wp_set_auth_cookie()` (line 85 in `class-admin-login-sso-user.php`)
- Google authentication flag stored in user meta: `admin_login_sso_authenticated`
- RE-authentication enforced if user meta flag missing (line 578 in `class-admin-login-sso-auth.php`)

## Monitoring & Observability

**Error Tracking:**
- Custom error handling via `handle_error()` method (line 679 in `class-admin-login-sso-auth.php`)
- Errors stored in transients for display on login page
- No external error tracking service configured

**Logs:**
- WordPress debug.log if `WP_DEBUG_LOG` is enabled
- Logging method: `log_error()` (line 749 in `class-admin-login-sso-auth.php`)
- Errors logged with prefix: `[Admin Login SSO]`
- Extensive logging throughout authentication flow (domain validation, token exchange, etc.)

## CI/CD & Deployment

**Hosting:**
- WordPress hosting (shared, managed, or self-hosted)
- No specific deployment service required

**CI Pipeline:**
- Not detected - No CI/CD configuration present

**Deployment Configuration:**
- None - Manual WordPress plugin upload/activation

## Environment Configuration

**Required env vars:**
- None - All configuration done through WordPress Settings page (database stored)

**Secrets location:**
- WordPress Options Table:
  - `admin_login_sso_client_id` - Stored as plain text (should be treated as secret)
  - `admin_login_sso_client_secret` - Stored as plain text (should be treated as secret)
- No `.env` file support
- No external secrets management

**Security Considerations:**
- Secrets stored in WordPress database - Use database-level encryption if available
- Redirect URI must be HTTPS (Google OAuth2 requirement)
- Callback handler at `wp-login.php?action=admin_login_sso_callback`

## Webhooks & Callbacks

**Incoming:**
- OAuth2 callback handler: `wp-login.php?action=admin_login_sso_callback`
  - Triggered by Google OAuth2 after user authorization
  - Parameters: `code` (authorization code), `state` (CSRF token)
  - Handler method: `handle_oauth_callback()` (line 229 in `class-admin-login-sso-auth.php`)

**Outgoing:**
- Token revoke request to Google: `https://accounts.google.com/o/oauth2/revoke`
  - Called on user logout (line 473-482)
  - Revokes the access token stored in user meta
- No other webhook deliveries

## REST API Integration

**WordPress REST API Restrictions:**
- Filters REST API access for authenticated users (line 599 in `class-admin-login-sso-auth.php`)
- Only restricts `/wp-json/wp/v2/` endpoints (line 612)
- Requires Google authentication for users with edit capabilities
- Returns 403 Forbidden if user not Google authenticated (line 624)

## Admin Access Control

**Access Restriction Flow:**
1. Plugin checks if SSO is enabled at every admin page load (method `restrict_admin_access()` at line 492)
2. Skips restriction for:
   - AJAX requests (line 506)
   - Plugin activation/deactivation (line 511)
   - Plugin settings page (line 518)
   - Specific admin pages: admin-ajax.php, plugins.php, options-general.php (line 523-533)
3. Requires Google authentication flag (`admin_login_sso_authenticated`) in user meta (line 578)
4. Enforces Google authentication on logout (line 586)

## Emergency Bypass

**Mechanism:**
- Stored in option: `admin_login_sso_emergency_bypass` (timestamp)
- Temporarily disables SSO when active (checked at line 137 in `class-admin-login-sso-auth.php`)
- Used in login form modification (line 142)
- Can be activated via `emergency-bypass.php` script (for recovery scenarios)

---

*Integration audit: 2026-03-21*
