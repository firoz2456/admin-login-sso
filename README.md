# Admin Login SSO

A WordPress plugin that replaces the traditional admin login with Google OAuth2 authentication, restricting access to specific email domains.

## Features

- **Google OAuth2 Integration**: Add a "Sign in with Google" flow on your admin login page.
- **Domain-Based Access Control**: Validate email addresses (with wildcard subdomain support) and allow login only when the email's domain matches an entry in your allowed domains list. Requires Google to have marked the email as verified.
- **User Matching & Provisioning**: Match existing WordPress users by email or optionally auto-create new administrator accounts.
- **WAF-Safe Secret Save**: The Client Secret saves via a dedicated AJAX channel with a base64-encoded, neutrally-named payload — Cloudflare / Sucuri / Wordfence don't see a `GOCSPX-` value crossing `wp-admin/options.php`.
- **External Secret Management**: Define `ADMIN_LOGIN_SSO_CLIENT_SECRET` as an env var or PHP constant to keep the secret out of the database entirely. The settings UI detects this and switches to a read-only "Managed externally" notice.
- **Secure Token Handling**: AES-256-CBC encryption of stored access tokens, derived from `AUTH_KEY`. Fails closed (refuses to persist) if OpenSSL or `AUTH_KEY` is unavailable.
- **Easy Setup**: Quick setup guide card, in-page "Test Google sign-in" button, contextual Help tab, and a parsed-domains chip preview for sanity-checking the allowed list.

## Requirements

- WordPress 6.4+
- PHP 8.0+
- Google Cloud Console project with OAuth credentials

## Installation

1. Upload the `admin-login-sso` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Settings > Admin Login SSO' to configure the plugin
4. Set up Google OAuth credentials in the Google Cloud Console
5. Enter your Client ID, Client Secret, and allowed domains
6. Enable the plugin and test the login

## Setup Instructions

### Google Cloud Console Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project or select an existing one
3. Configure the OAuth consent screen (External or Internal)
4. Create OAuth 2.0 Client ID credentials (Web application type)
5. Add the Redirect URI shown in the plugin settings to the authorized redirect URIs
6. Copy the Client ID and Client Secret to the plugin settings

### Plugin Configuration

1. Navigate to Settings → Admin Login SSO in your WordPress admin
2. Enter the Google Client ID and Client Secret from your Google Cloud Console
3. Add the allowed email domains (e.g., example.com, *.example.org)
4. Enable the "Google-Only Admin Login" option
5. Optionally enable "Auto-create admin users"
6. Save settings

## Usage

Once enabled, your WordPress admin login screen will show a "Continue with Google" button instead of the traditional username/password form. Users will need to authenticate with Google, and their email domain will be checked against your allowed domains list.

## License

This plugin is licensed under the GPL v2 or later.

## Author

Created by Firoz Sabaliya