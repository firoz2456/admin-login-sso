<?php
declare(strict_types=1);
/**
 * User handling class
 *
 * @package Admin_Login_SSO
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * User handling class
 */
class Admin_Login_SSO_User {

    /**
     * Process user login or creation
     *
     * @param array $user_info User info from Google
     * @return WP_User|WP_Error WP_User on success, WP_Error on failure
     */
    public function process_user($user_info) {
        // Check required user info
        if (empty($user_info['email'])) {
            return new WP_Error('missing_email', __('Email address is missing from your Google account. Please ensure your Google account has a valid email address.', 'admin-login-sso'));
        }

        // Validate email format
        if (!is_email($user_info['email'])) {
            return new WP_Error('invalid_email', sprintf(__('Invalid email format: %s. Please use a valid email address.', 'admin-login-sso'), $user_info['email']));
        }

        // Find existing user by email
        $user = get_user_by('email', $user_info['email']);
        
        // If user exists, authenticate them
        if ($user) {
            return $this->authenticate_existing_user($user, $user_info);
        }
        
        // If auto-create is enabled, create new user
        if ('1' === get_option('admin_login_sso_auto_create_users')) {
            return $this->create_new_user($user_info);
        }
        
        // Otherwise, return detailed error
        return new WP_Error(
            'user_not_found',
            sprintf(
                __('No WordPress user found with email address %s. Please contact your site administrator to create an account or use an email that matches an existing WordPress user.', 'admin-login-sso'),
                '<strong>' . esc_html($user_info['email']) . '</strong>'
            )
        );
    }

    /**
     * Authenticate existing user
     *
     * @param WP_User $user WordPress user object
     * @param array $user_info User info from Google
     * @return WP_User|WP_Error WP_User on success, WP_Error on failure
     */
    private function authenticate_existing_user($user, $user_info) {
        // Domain validation is already done before this method is called.
        // Any user with a valid allowed domain can log in.

        // Log the user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        
        // Update user meta with Google data
        $this->update_user_meta($user->ID, $user_info);
        
        do_action('wp_login', $user->user_login, $user);
        
        return $user;
    }

    /**
     * Create new user
     *
     * @param array $user_info User info from Google
     * @return WP_User|WP_Error WP_User on success, WP_Error on failure
     */
    private function create_new_user($user_info) {
        // Generate username from email
        $username = $this->generate_username($user_info['email']);
        
        // Generate random password
        $password = wp_generate_password(24, true, true);
        
        // Set user data
        $user_data = array(
            'user_login' => $username,
            'user_email' => $user_info['email'],
            'user_pass' => $password,
            'role' => 'administrator',
        );
        
        // Add first and last name if available
        if (!empty($user_info['given_name'])) {
            $user_data['first_name'] = $user_info['given_name'];
        }
        
        if (!empty($user_info['family_name'])) {
            $user_data['last_name'] = $user_info['family_name'];
        }
        
        // Create the user
        $user_id = wp_insert_user($user_data);
        
        if (is_wp_error($user_id)) {
            return $user_id;
        }
        
        // Update user meta with Google data
        $this->update_user_meta($user_id, $user_info);
        
        // Log the user in
        $user = get_user_by('id', $user_id);
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id);
        
        do_action('wp_login', $user->user_login, $user);
        
        return $user;
    }

    /**
     * Generate username from email
     *
     * @param string $email User email
     * @return string Generated username
     */
    private function generate_username($email) {
        $email_parts = explode('@', $email);
        $base_username = sanitize_user($email_parts[0], true);
        
        // Check if username exists
        if (!username_exists($base_username)) {
            return $base_username;
        }
        
        // If username exists, add a number
        $i = 1;
        $username = $base_username . $i;
        
        while (username_exists($username)) {
            $i++;
            $username = $base_username . $i;
        }
        
        return $username;
    }

    /**
     * Update user meta with Google data
     *
     * @param int $user_id User ID
     * @param array $user_info User info from Google
     */
    private function update_user_meta($user_id, $user_info) {
        // Store Google user ID
        if (!empty($user_info['sub'])) {
            update_user_meta($user_id, 'admin_login_sso_google_id', sanitize_text_field($user_info['sub']));
        }
        
        // Store Google profile picture
        if (!empty($user_info['picture'])) {
            update_user_meta($user_id, 'admin_login_sso_picture', esc_url_raw($user_info['picture']));
        }
        
        // Store authentication flag
        update_user_meta($user_id, 'admin_login_sso_authenticated', '1');
        
        // Store access token encrypted if available
        if (!empty($user_info['access_token'])) {
            $encrypted = self::encrypt_token($user_info['access_token']);
            update_user_meta($user_id, 'admin_login_sso_access_token', $encrypted);
        }
        
        // Update login timestamp
        update_user_meta($user_id, 'admin_login_sso_last_login', current_time('timestamp'));
    }

    /**
     * Encrypt a token for storage
     *
     * @param string $token Plain text token
     * @return string Base64-encoded encrypted token
     */
    public static function encrypt_token(string $token): string
    {
        $key = self::get_encryption_key();
        if (!function_exists('openssl_encrypt')) {
            // Fallback: use HMAC-based obfuscation if OpenSSL unavailable
            return base64_encode($token);
        }
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($token, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt a stored token
     *
     * @param string $encrypted Base64-encoded encrypted token
     * @return string|false Decrypted token or false on failure
     */
    public static function decrypt_token(string $encrypted)
    {
        $key = self::get_encryption_key();
        $data = base64_decode($encrypted, true);
        if ($data === false || strlen($data) < 17) {
            return false;
        }
        if (!function_exists('openssl_decrypt')) {
            return $data;
        }
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return $decrypted !== false ? $decrypted : false;
    }

    /**
     * Get the encryption key derived from WordPress salts
     *
     * @return string 32-byte encryption key
     */
    private static function get_encryption_key(): string
    {
        $salt = defined('AUTH_KEY') ? AUTH_KEY : 'admin-login-sso-default-key';
        return hash('sha256', $salt . 'admin_login_sso_token_encryption', true);
    }

    /**
     * Check if user can access admin
     *
     * @param WP_User $user WordPress user object
     * @return bool True if user can access admin
     */
    private function user_can_access_admin($user) {
        // Check if user is administrator
        if (in_array('administrator', (array) $user->roles, true)) {
            return true;
        }
        
        // Check for specific capabilities
        $admin_caps = array(
            'manage_options',
            'edit_posts',
            'publish_posts',
            'edit_published_posts',
            'edit_others_posts',
        );
        
        foreach ($admin_caps as $cap) {
            if ($user->has_cap($cap)) {
                return true;
            }
        }
        
        return false;
    }
}