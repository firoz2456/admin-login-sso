# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## WordPress Admin Login via Google Plugin

This plugin enables WordPress administrators to replace the traditional wp-admin login with Google OAuth2 authentication, restricting access to specific email domains.

### Development Commands

```bash
# Run PHP code linting
php -l file.php

# WordPress coding standards check (if installed)
phpcs --standard=WordPress file.php

# Debug mode (writes to wp-content/debug.log)
# Add to wp-config.php:
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

### Architecture Overview

1. **Core Components**:
   - `admin-login-sso.php`: Main plugin file with initialization hooks
   - `includes/`: Core functionality classes
     - Authentication handler for Google OAuth2
     - Domain validation logic
     - User matching and provisioning
   - `admin/`: Admin settings page and UI customizations
   - `assets/`: CSS, JS, and images

2. **Key Workflows**:
   - **Authentication Flow**:
     1. Intercept wp-login.php
     2. Redirect to Google OAuth consent screen
     3. Process OAuth callback
     4. Validate email domain against allowed list
     5. Match or provision WordPress user
     6. Create authenticated session

   - **Settings Management**:
     - Google Client credentials storage (Client ID, Client Secret)
     - Allowed domains configuration (supports wildcards)
     - Toggle for Google-only admin login
     - Auto-create admin users option

3. **Security Considerations**:
   - Token handling follows OAuth2 best practices
   - Domain validation is strictly enforced
   - Proper nonce verification for all admin actions
   - No capability elevation during user provisioning

### Data Storage

- Plugin settings stored in wp_options table with autoload=no
- No custom database tables
- Transient storage for temporary OAuth states

### Integration Points

- Hooks into WordPress authentication system
- Modifies wp-login.php UI when enabled
- Filters REST API and WP-CLI access for admin functions
- Compatible with WordPress 6.4+, PHP 8.0+