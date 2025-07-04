=== Admin Login SSO ===
Contributors: adminloginsso
Tags: google, login, sso, oauth, security, admin
Requires at least: 6.4
Tested up to: 6.4
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Replace WordPress admin login with Google OAuth2 authentication, restricting access to specific email domains.

== Description ==

Admin Login SSO provides a secure and convenient way to replace the traditional WordPress admin login with Google OAuth2 authentication. This plugin is perfect for organizations that want to enforce Google account login for admin access and restrict access to specific email domains.

= Key Features =

* **Google OAuth2 Integration**: Add a "Sign in with Google" flow on your admin login page.
* **Domain-Based Access Control**: Validate email addresses and allow login only when the email's domain matches an entry in your allowed domains list.
* **User Matching & Provisioning**: Match existing WordPress users by email or optionally create new admin users.
* **Secure Token Handling**: Properly manage OAuth tokens and revoke them on logout.
* **Easy Setup**: Simple configuration through the WordPress admin interface.

= Use Cases =

* **Corporate Websites**: Ensure only users with company email addresses can access the admin area.
* **Educational Institutions**: Restrict admin access to users with .edu domain emails.
* **Agency Client Sites**: Allow only your agency team members to access client admin areas.

== Installation ==

1. Upload the `admin-login-sso` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Settings > Google Admin Login' to configure the plugin
4. Set up Google OAuth credentials in the Google Cloud Console
5. Enter your Client ID, Client Secret, and allowed domains
6. Enable the plugin and test the login

== Frequently Asked Questions ==

= How do I set up Google OAuth credentials? =

1. Go to the Google Cloud Console: https://console.cloud.google.com/apis/credentials
2. Create a new project or select an existing one
3. Configure the OAuth consent screen (External or Internal)
4. Create OAuth 2.0 Client ID credentials (Web application type)
5. Add the Redirect URI shown in the plugin settings to the authorized redirect URIs
6. Copy the Client ID and Client Secret to the plugin settings

= Can I use wildcards for domains? =

Yes, you can use wildcards for subdomains. For example, *.example.com would match any subdomain of example.com.

= What happens if a user doesn't have a WordPress account? =

If a user doesn't have a WordPress account, there are two possibilities:
1. If "Auto-create admin users" is enabled, a new administrator account will be created for them.
2. If not enabled, they will see an error message indicating they need to contact the administrator.

= Does this affect front-end login? =

No, this plugin only affects admin login (/wp-admin). Front-end login and other roles continue via native or existing SSO methods.

= What if Google authentication fails? =

If the classic login form is enabled in the settings, users can sign in using the standard WordPress login form as a fallback.

== Screenshots ==

1. Admin login page with Google sign-in button
2. Plugin settings page
3. Domain restriction error message

== Changelog ==

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.0 =
Initial release