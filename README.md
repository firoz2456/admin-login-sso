# Admin Login SSO

A WordPress plugin that replaces the traditional admin login with Google OAuth2 authentication, restricting access to specific email domains.

## Features

- **Google OAuth2 Integration**: Add a "Sign in with Google" flow on your admin login page.
- **Domain-Based Access Control**: Validate email addresses and allow login only when the email's domain matches an entry in your allowed domains list.
- **User Matching & Provisioning**: Match existing WordPress users by email or optionally create new admin users.
- **Secure Token Handling**: Properly manage OAuth tokens and revoke them on logout.
- **Easy Setup**: Simple configuration through the WordPress admin interface.

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