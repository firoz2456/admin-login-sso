<?php
declare(strict_types=1);
/**
 * Authentication handler class
 *
 * @package Admin_Login_SSO
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// PHP 8.0 polyfills for better compatibility
if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle)
    {
        return strpos($haystack, $needle) === 0;
    }
}

if (!function_exists('str_ends_with')) {
    function str_ends_with($haystack, $needle)
    {
        if ($needle === '') {
            return true;
        }
        $length = strlen($needle);
        return substr($haystack, -$length) === $needle;
    }
}

/**
 * Authentication handler class
 */
class Admin_Login_SSO_Auth
{

    /**
     * Google OAuth2 endpoints
     */
    const GOOGLE_AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
    const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
    const GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';
    const GOOGLE_REVOKE_URL = 'https://accounts.google.com/o/oauth2/revoke';

    /**
     * OAuth state transient expiration (5 minutes)
     */
    const STATE_EXPIRATION = 300;

    /**
     * Initialize the authentication functionality
     */
    public function init()
    {
        // Handle login form modification
        add_action('login_form', array($this, 'modify_login_form'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));

        // Display error messages above the login form
        add_action('login_message', array($this, 'display_login_messages'));

        // Handle OAuth callback
        add_action('init', array($this, 'handle_oauth_callback'));

        // Handle admin-only restriction
        add_action('admin_init', array($this, 'restrict_admin_access'));
        add_filter('rest_authentication_errors', array($this, 'restrict_rest_api'), 10, 1);

        // Handle logout
        add_action('wp_logout', array($this, 'handle_logout'));
    }

    /**
     * Display login messages above the form
     *
     * @param string $message Existing login message
     * @return string Modified login message
     */
    public function display_login_messages($message)
    {
        // Only show messages if it's an admin login and the feature is enabled
        if (!$this->is_admin_login() || !$this->is_enabled()) {
            return $message;
        }

        $output = '';

        // Check for emergency bypass
        $bypass_time = get_option('admin_login_sso_emergency_bypass');
        if ($bypass_time && $bypass_time > time()) {
            $output .= '<div class="admin-login-sso-message info">';
            $output .= '<p>' . __('SSO is temporarily disabled. You can use standard WordPress login.', 'admin-login-sso') . '</p>';
            $output .= '</div>';
        }

        // Check for re-authentication message
        $reauth_message = get_transient('admin_login_sso_reauth_required');
        if ($reauth_message) {
            $output .= '<div class="admin-login-sso-message info">';
            $output .= '<p>' . esc_html($reauth_message['message']) . '</p>';
            $output .= '</div>';
            delete_transient('admin_login_sso_reauth_required');
        }

        // Check for errors
        $login_status = isset($_GET['login']) ? sanitize_text_field($_GET['login']) : '';
        if ('failed' === $login_status) {
            $error = get_transient('admin_login_sso_error');
            if ($error) {
                $output .= '<div class="admin-login-sso-message error">';
                $output .= '<p>' . wp_kses_post($error['message']) . '</p>';
                $output .= '</div>';
                delete_transient('admin_login_sso_error');
            } else {
                $output .= '<div class="admin-login-sso-message error">';
                $output .= '<p>' . __('Authentication failed. Please try again.', 'admin-login-sso') . '</p>';
                $output .= '</div>';
            }
        }

        return $output . $message;
    }

    /**
     * Modify the login form to show Google sign-in
     */
    public function modify_login_form()
    {
        // Only modify if it's an admin login and the feature is enabled
        if (!$this->is_admin_login() || !$this->is_enabled()) {
            return;
        }

        // Check for emergency bypass
        $bypass_time = get_option('admin_login_sso_emergency_bypass');
        if ($bypass_time && $bypass_time > time()) {
            return;
        }

        $show_classic = get_option('admin_login_sso_show_classic_login', '1');

        if ($show_classic !== '1' && $show_classic !== true) {
            // Hide the default login form when classic login is disabled
            echo '<style type="text/css">
                #loginform p:not(.google-login-button-container),
                #loginform .user-pass-wrap,
                #loginform .forgetmenot,
                #loginform .submit {
                    display: none;
                }
            </style>';
        }

        // Add Google login button
        echo '<div class="google-login-button-container">';
        echo '<a href="' . esc_url($this->get_auth_url()) . '" class="google-login-button">';
        echo '<div class="google-logo"></div>';
        echo '<span class="google-button-text">' . esc_html__('Continue with Google', 'admin-login-sso') . '</span>';
        echo '</a>';
        echo '</div>';

        // Classic login is shown automatically based on the admin setting,
        // so no toggle link is required.
    }

    /**
     * Enqueue login assets
     */
    public function enqueue_login_assets()
    {
        if (!$this->is_admin_login() || !$this->is_enabled()) {
            return;
        }

        wp_enqueue_style(
            'admin-login-sso-login',
            ADMIN_LOGIN_SSO_PLUGIN_URL . 'assets/css/login.css',
            array('login'),
            ADMIN_LOGIN_SSO_VERSION
        );

        wp_enqueue_style('dashicons');
    }

    /**
     * Get Google authorization URL
     *
     * @return string Authorization URL
     */
    public function get_auth_url()
    {
        $client_id = get_option('admin_login_sso_client_id');
        if (empty($client_id)) {
            return '#';
        }

        // Generate and store a state parameter to prevent CSRF
        $state = wp_generate_password(40, false);
        set_transient('admin_login_sso_state_' . $state, 1, self::STATE_EXPIRATION);

        $auth_params = array(
            'client_id' => $client_id,
            'redirect_uri' => esc_url_raw($this->get_redirect_uri()),
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'prompt' => 'select_account',
            'access_type' => 'online'
        );

        return self::GOOGLE_AUTHORIZE_URL . '?' . http_build_query($auth_params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Get redirect URI
     *
     * @return string Redirect URI
     */
    private function get_redirect_uri()
    {
        return site_url('wp-login.php?action=admin_login_sso_callback');
    }

    /**
     * Handle OAuth callback
     */
    public function handle_oauth_callback()
    {
        if (!isset($_GET['action']) || 'admin_login_sso_callback' !== $_GET['action']) {
            return;
        }

        // Check for errors
        if (isset($_GET['error'])) {
            $error_code = sanitize_text_field($_GET['error']);
            $error_desc = isset($_GET['error_description']) ? sanitize_text_field($_GET['error_description']) : '';
            $this->handle_error($error_code, $error_desc);
            return;
        }

        // Verify state parameter to prevent CSRF
        $state = isset($_GET['state']) ? sanitize_key($_GET['state']) : '';
        if (empty($state) || !get_transient('admin_login_sso_state_' . $state)) {
            $this->handle_error('invalid_state', __('Invalid state parameter. Please try again.', 'admin-login-sso'));
            return;
        }

        // Delete the transient since we've verified it
        delete_transient('admin_login_sso_state_' . $state);

        // Check for authorization code
        if (!isset($_GET['code'])) {
            $this->handle_error('missing_code', __('Authorization code is missing. Please try again.', 'admin-login-sso'));
            return;
        }

        $code = sanitize_text_field($_GET['code']);

        // Exchange authorization code for access token
        $token_data = $this->get_token($code);
        if (!$token_data || isset($token_data['error'])) {
            $error_message = isset($token_data['error_description']) ? $token_data['error_description'] : __('Failed to get access token. Please try again.', 'admin-login-sso');
            $this->handle_error('token_error', $error_message);
            return;
        }

        // Get user info using the access token
        $user_info = $this->get_user_info($token_data['access_token']);
        if (!$user_info || isset($user_info['error'])) {
            $error_message = isset($user_info['error_description']) ? $user_info['error_description'] : __('Failed to get user information. Please try again.', 'admin-login-sso');
            $this->handle_error('userinfo_error', $error_message);
            return;
        }

        // Validate email domain
        if (!$this->validate_email_domain($user_info['email'])) {
            $this->handle_error(
                'domain_not_allowed',
                __('Access Denied: Please contact the site admin.', 'admin-login-sso')
            );
            return;
        }

        // Process user login or creation
        $user = $this->process_user_login($user_info);
        if (is_wp_error($user)) {
            $this->handle_error('login_failed', $user->get_error_message());
            return;
        }

        // Redirect to admin dashboard
        wp_safe_redirect(admin_url());
        exit;
    }

    /**
     * Exchange authorization code for access token
     *
     * @param string $code Authorization code
     * @return array|false Token data or false on failure
     */
    private function get_token($code)
    {
        $client_id = get_option('admin_login_sso_client_id');
        $client_secret = get_option('admin_login_sso_client_secret');

        if (empty($client_id) || empty($client_secret)) {
            return false;
        }

        $token_request = wp_remote_post(
            self::GOOGLE_TOKEN_URL,
            array(
                'timeout' => 10,
                'headers' => array(
                    'Accept' => 'application/json',
                    'User-Agent' => ADMIN_LOGIN_SSO_USER_AGENT,
                ),
                'body' => array(
                    'code' => $code,
                    'client_id' => $client_id,
                    'client_secret' => $client_secret,
                    'redirect_uri' => esc_url_raw($this->get_redirect_uri()),
                    'grant_type' => 'authorization_code',
                ),
            )
        );

        if (is_wp_error($token_request)) {
            $this->log_error('Token request failed: ' . $token_request->get_error_message());
            return false;
        }

        $token_response = json_decode(wp_remote_retrieve_body($token_request), true);

        if (!isset($token_response['access_token'])) {
            $this->log_error('Invalid token response: ' . wp_json_encode($token_response));
            return false;
        }

        return $token_response;
    }

    /**
     * Get user info using the access token
     *
     * @param string $access_token Access token
     * @return array|false User info or false on failure
     */
    private function get_user_info($access_token)
    {
        $user_info_request = wp_remote_get(
            self::GOOGLE_USER_INFO_URL,
            array(
                'timeout' => 10,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $access_token,
                    'User-Agent' => ADMIN_LOGIN_SSO_USER_AGENT,
                ),
            )
        );

        if (is_wp_error($user_info_request)) {
            $this->log_error('User info request failed: ' . $user_info_request->get_error_message());
            return false;
        }

        $user_info = json_decode(wp_remote_retrieve_body($user_info_request), true);

        if (!isset($user_info['email'])) {
            $this->log_error('Invalid user info response: ' . wp_json_encode($user_info));
            return false;
        }

        return $user_info;
    }

    /**
     * Validate email domain against allowed domains
     *
     * @param string $email User email
     * @return bool True if domain is allowed, false otherwise
     */
    private function validate_email_domain(string $email): bool
    {
        $allowed_domains = get_option('admin_login_sso_allowed_domains');

        if (empty($allowed_domains)) {
            $this->log_error('Domain validation failed: No allowed domains configured');
            return false;
        }

        // Use wp_parse_list to properly handle comma-separated values
        // This function handles various separators and trims whitespace
        $domains = wp_parse_list($allowed_domains);

        // Extract email domain more reliably
        $email = strtolower(trim($email));
        $email_parts = explode('@', $email);
        if (count($email_parts) !== 2) {
            $this->log_error('Domain validation failed: Invalid email format - ' . $email);
            return false;
        }

        $email_domain = trim($email_parts[1]);

        $this->log_error('Validating email: ' . $email . ' with domain: ' . $email_domain);
        $this->log_error('Raw allowed_domains option: "' . $allowed_domains . '"');
        $this->log_error('Parsed domains: [' . implode('], [', $domains) . ']');

        foreach ($domains as $domain) {
            // Normalize domain: lowercase and trim all whitespace
            $domain = strtolower(trim($domain));

            // Skip empty domains
            if (empty($domain)) {
                continue;
            }

            $this->log_error('Checking against domain: "' . $domain . '" (length: ' . strlen($domain) . ')');

            // Exact match
            if ($domain === $email_domain) {
                $this->log_error('Domain validation passed: Exact match for "' . $domain . '"');
                return true;
            }

            // Wildcard subdomain match
            if (str_starts_with($domain, '*.')) {
                // Get the base domain (everything after *.)
                $base_domain = substr($domain, 2);
                $this->log_error('Checking wildcard domain: "' . $domain . '" with base domain: "' . $base_domain . '"');

                // Check if email domain ends with the base domain
                if (str_ends_with($email_domain, $base_domain)) {
                    // Also ensure it's a proper subdomain match (not just suffix)
                    // e.g., *.example.com should match sub.example.com but not notexample.com
                    if ($email_domain === $base_domain || str_ends_with($email_domain, '.' . $base_domain)) {
                        $this->log_error('Domain validation passed: Wildcard match for "' . $domain . '"');
                        return true;
                    }
                }
            }
        }

        $this->log_error('Domain validation failed: No matching domain found for "' . $email_domain . '"');
        return false;
    }

    /**
     * Process user login or creation
     *
     * @param array $user_info User info from Google
     * @return WP_User|WP_Error WP_User on success, WP_Error on failure
     */
    private function process_user_login($user_info)
    {
        $user_handler = new Admin_Login_SSO_User();
        return $user_handler->process_user($user_info);
    }

    /**
     * Handle logout by revoking Google token
     */
    public function handle_logout()
    {
        $token = get_user_meta(get_current_user_id(), 'admin_login_sso_access_token', true);

        if (!empty($token)) {
            // Revoke token
            wp_remote_get(
                self::GOOGLE_REVOKE_URL . '?token=' . rawurlencode($token),
                array(
                    'timeout' => 10,
                    'sslverify' => true,
                    'headers' => array(
                        'User-Agent' => ADMIN_LOGIN_SSO_USER_AGENT,
                    ),
                )
            );

            // Delete user meta
            delete_user_meta(get_current_user_id(), 'admin_login_sso_access_token');
        }
    }

    /**
     * Restrict admin access to Google-authenticated users
     */
    public function restrict_admin_access()
    {
        // Only apply restrictions if enabled
        if (!$this->is_enabled()) {
            return;
        }

        // Check for emergency bypass
        $bypass_time = get_option('admin_login_sso_emergency_bypass');
        if ($bypass_time && $bypass_time > time()) {
            return; // Bypass is active
        }

        // Skip restriction for AJAX requests
        if (wp_doing_ajax()) {
            return;
        }

        // Skip restriction during plugin activation/deactivation
        $action = isset($_GET['action']) ? sanitize_key($_GET['action']) : '';
        if (in_array($action, array('activate', 'deactivate'), true)) {
            return;
        }

        // Skip restriction for plugin settings page
        $page = isset($_GET['page']) ? sanitize_key($_GET['page']) : '';
        if ('admin-login-sso' === $page) {
            return;
        }

        // Skip restriction for specific admin pages
        $allowed_pages = array(
            'admin-ajax.php',
            'plugins.php', // Allow access to plugins page
            'options-general.php', // Allow access to settings
        );

        foreach ($allowed_pages as $page) {
            if (false !== strpos($_SERVER['SCRIPT_NAME'], $page)) {
                return;
            }
        }

        // Check if user is logged in
        if (!is_user_logged_in()) {
            // Not logged in at all, let WordPress handle the redirect
            return;
        }

        // Get current user
        $current_user = wp_get_current_user();
        if (!$current_user || !$current_user->exists()) {
            return;
        }

        // Allow super admins to bypass during initial setup
        if (is_super_admin($current_user->ID)) {
            // Check if plugin is properly configured
            $client_id = get_option('admin_login_sso_client_id');
            $client_secret = get_option('admin_login_sso_client_secret');
            $allowed_domains = get_option('admin_login_sso_allowed_domains');

            // If not configured, allow super admin access to configure it
            if (empty($client_id) || empty($client_secret) || empty($allowed_domains)) {
                return;
            }

            // Check if this is the first time restriction is being applied
            $restriction_notice_shown = get_user_meta($current_user->ID, 'admin_login_sso_restriction_notice', true);
            if (!$restriction_notice_shown) {
                // Set a flag that we've shown the notice
                update_user_meta($current_user->ID, 'admin_login_sso_restriction_notice', '1');

                // Add an admin notice instead of immediate redirect
                add_action('admin_notices', function () {
                    echo '<div class="notice notice-warning is-dismissible">';
                    echo '<p><strong>' . __('Admin Login SSO Active', 'admin-login-sso') . '</strong></p>';
                    echo '<p>' . __('Google SSO is now active. You will need to log in with Google on your next login. Make sure your email domain is in the allowed list.', 'admin-login-sso') . '</p>';
                    echo '<p><a href="' . esc_url(admin_url('options-general.php?page=admin-login-sso')) . '" class="button button-primary">' . __('Configure Settings', 'admin-login-sso') . '</a></p>';
                    echo '</div>';
                });
                return;
            }
        }

        // If user doesn't have the Google authentication flag, redirect to login
        if (!$this->is_user_google_authenticated()) {
            // Clear auth cookies to force re-authentication
            wp_clear_auth_cookie();

            // Set a message for the login page
            set_transient('admin_login_sso_reauth_required', array(
                'message' => __('Please log in with your Google account to access the admin area.', 'admin-login-sso')
            ), 60);

            wp_safe_redirect(wp_login_url(admin_url()));
            exit;
        }
    }

    /**
     * Restrict REST API access
     *
     * @param WP_Error|null|bool $errors WP_Error if authentication error, null if authentication
     *                                    method wasn't used, true if authentication succeeded.
     * @return WP_Error|null|bool
     */
    public function restrict_rest_api($errors)
    {
        // If there's already an error, return it
        if (is_wp_error($errors)) {
            return $errors;
        }

        // Only apply restrictions if enabled
        if (!$this->is_enabled()) {
            return $errors;
        }

        // Only restrict access to WP REST API endpoints that require edit capability
        if (0 !== strpos($_SERVER['REQUEST_URI'], '/wp-json/wp/v2/')) {
            return $errors;
        }

        // Get current user
        $current_user = wp_get_current_user();
        if (!$current_user || !$current_user->exists()) {
            return $errors;
        }

        // Check if the user has edit capability and is Google authenticated
        if ($this->user_has_edit_capability($current_user) && !$this->is_user_google_authenticated()) {
            return new WP_Error(
                'rest_forbidden',
                __('Access to this resource requires Google authentication.', 'admin-login-sso'),
                array('status' => 403)
            );
        }

        return $errors;
    }

    /**
     * Check if user has edit capability
     *
     * @param WP_User $user WordPress user object
     * @return bool True if user has edit capability
     */
    private function user_has_edit_capability($user)
    {
        if (!$user || !$user->exists()) {
            return false;
        }

        $post_types = get_post_types(array('show_in_rest' => true), 'objects');

        foreach ($post_types as $post_type) {
            if (current_user_can($post_type->cap->edit_posts)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if current user is Google authenticated
     *
     * @return bool True if user is Google authenticated
     */
    private function is_user_google_authenticated()
    {
        $current_user_id = get_current_user_id();

        if (!$current_user_id) {
            return false;
        }

        return (bool) get_user_meta($current_user_id, 'admin_login_sso_authenticated', true);
    }

    /**
     * Handle authentication errors
     *
     * @param string $code Error code
     * @param string $message Error message
     */
    private function handle_error($code, $message)
    {
        $this->log_error("Authentication error: [$code] $message");

        // Store error in a transient to display it on the login page
        set_transient('admin_login_sso_error', array(
            'code' => $code,
            'message' => $message
        ), 60); // Expires after 60 seconds

        wp_safe_redirect(
            add_query_arg(
                array(
                    'login' => 'failed',
                    'error' => $code,
                ),
                wp_login_url()
            )
        );
        exit;
    }

    /**
     * Check if SSO is enabled
     *
     * @return bool True if enabled
     */
    private function is_enabled()
    {
        // First check if SSO is enabled
        if ('1' !== get_option('admin_login_sso_enabled', '0')) {
            return false;
        }

        // Then check if credentials are configured
        $client_id = get_option('admin_login_sso_client_id', '');
        $client_secret = get_option('admin_login_sso_client_secret', '');

        return !empty($client_id) && !empty($client_secret);
    }

    /**
     * Check if it's an admin login
     *
     * @return bool True if it's an admin login
     */
    private function is_admin_login()
    {
        $is_admin = false;

        // Check for admin query param
        if (isset($_GET['redirect_to'])) {
            $redirect_to = sanitize_text_field(wp_unslash($_GET['redirect_to']));
            $is_admin = false !== strpos($redirect_to, admin_url());
        }

        // Always consider it admin login if admin-login-sso is enabled
        if ($this->is_enabled()) {
            $is_admin = true;
        }

        return $is_admin;
    }


    /**
     * Log error to debug.log if WP_DEBUG_LOG is enabled
     *
     * @param string $message Error message
     */
    private function log_error($message)
    {
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log('[Admin Login SSO] ' . $message);
        }
    }
}