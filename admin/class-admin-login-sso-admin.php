<?php
/**
 * Admin settings class
 *
 * @package Admin_Login_SSO
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Admin settings class
 */
class Admin_Login_SSO_Admin {

    /**
     * Initialize the admin functionality
     */
    public function __construct() {
        // Add settings link to plugins page
        add_filter('plugin_action_links_' . ADMIN_LOGIN_SSO_PLUGIN_BASENAME, array($this, 'add_settings_link'));
        
        // Add settings sections and fields
        add_action('admin_init', array($this, 'register_settings_sections'));
    }
    
    /**
     * Initialize the admin class
     */
    public function init() {
        // Add admin styles
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
    }
    
    /**
     * Enqueue admin styles
     *
     * @param string $hook Current admin page
     */
    public function enqueue_admin_styles($hook) {
        // Only load on plugin settings page
        if ('settings_page_admin-login-sso' !== $hook) {
            return;
        }
        
        wp_enqueue_style(
            'admin-login-sso-admin',
            ADMIN_LOGIN_SSO_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            ADMIN_LOGIN_SSO_VERSION
        );
    }

    /**
     * Add settings link to plugins page
     *
     * @param array $links Plugin action links
     * @return array Modified plugin action links
     */
    public function add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=admin-login-sso') . '">' . __('Settings', 'admin-login-sso') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Register settings sections and fields
     */
    public function register_settings_sections() {
        // Add settings section
        add_settings_section(
            'admin_login_sso_settings_section',
            __('Google Admin Login Settings', 'admin-login-sso'),
            array($this, 'settings_section_callback'),
            'admin_login_sso_settings'
        );
        
        // Add settings fields
        add_settings_field(
            'admin_login_sso_client_id',
            __('Google Client ID', 'admin-login-sso'),
            array($this, 'client_id_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
        
        add_settings_field(
            'admin_login_sso_client_secret',
            __('Google Client Secret', 'admin-login-sso'),
            array($this, 'client_secret_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
        
        add_settings_field(
            'admin_login_sso_allowed_domains',
            __('Allowed Domains', 'admin-login-sso'),
            array($this, 'allowed_domains_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
        
        add_settings_field(
            'admin_login_sso_enabled',
            __('Enable Google-Only Admin Login', 'admin-login-sso'),
            array($this, 'enabled_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
        
        add_settings_field(
            'admin_login_sso_auto_create_users',
            __('Auto-create admin users', 'admin-login-sso'),
            array($this, 'auto_create_users_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
    }

    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        echo '<p>' . esc_html__('Configure your Google OAuth2 credentials and domain restrictions.', 'admin-login-sso') . '</p>';
        
        // Show the redirect URI
        echo '<p><strong>' . esc_html__('Redirect URI:', 'admin-login-sso') . '</strong> ';
        echo '<code>' . esc_html(site_url('wp-login.php?action=admin_login_sso_callback')) . '</code>';
        echo ' <button type="button" class="button" onclick="navigator.clipboard.writeText(\'' . esc_js(site_url('wp-login.php?action=admin_login_sso_callback')) . '\');">' . esc_html__('Copy', 'admin-login-sso') . '</button></p>';
        
        // Show instructions
        echo '<div class="admin-login-sso-instructions">';
        echo '<h3>' . esc_html__('Setup Instructions', 'admin-login-sso') . '</h3>';
        echo '<ol>';
        echo '<li>' . esc_html__('Go to the Google Cloud Console:', 'admin-login-sso') . ' <a href="https://console.cloud.google.com/apis/credentials" target="_blank">https://console.cloud.google.com/apis/credentials</a></li>';
        echo '<li>' . esc_html__('Create a new project or select an existing one', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Configure the OAuth consent screen (External or Internal)', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Create OAuth 2.0 Client ID credentials (Web application type)', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Add the Redirect URI shown above to the authorized redirect URIs', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Copy the Client ID and Client Secret to the fields below', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Enter the allowed email domains (e.g., example.com, *.example.org)', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Save settings and enable the plugin', 'admin-login-sso') . '</li>';
        echo '</ol>';
        echo '</div>';
    }

    /**
     * Client ID field callback
     */
    public function client_id_callback() {
        $client_id = get_option('admin_login_sso_client_id');
        echo '<input type="text" id="admin_login_sso_client_id" name="admin_login_sso_client_id" value="' . esc_attr($client_id) . '" class="regular-text" />';
        echo '<p class="description">' . esc_html__('Enter your Google OAuth2 Client ID', 'admin-login-sso') . '</p>';
    }

    /**
     * Client Secret field callback
     */
    public function client_secret_callback() {
        $client_secret = get_option('admin_login_sso_client_secret');
        echo '<input type="password" id="admin_login_sso_client_secret" name="admin_login_sso_client_secret" value="' . esc_attr($client_secret) . '" class="regular-text" />';
        echo '<p class="description">' . esc_html__('Enter your Google OAuth2 Client Secret', 'admin-login-sso') . '</p>';
    }

    /**
     * Allowed Domains field callback
     */
    public function allowed_domains_callback() {
        $allowed_domains = get_option('admin_login_sso_allowed_domains');
        echo '<textarea id="admin_login_sso_allowed_domains" name="admin_login_sso_allowed_domains" rows="5" cols="50" class="large-text code">' . esc_textarea($allowed_domains) . '</textarea>';
        echo '<p class="description">' . esc_html__('Enter comma-separated list of allowed email domains (e.g., example.com, *.example.org)', 'admin-login-sso') . '</p>';
    }

    /**
     * Enabled field callback
     */
    public function enabled_callback() {
        $enabled = get_option('admin_login_sso_enabled');
        echo '<label for="admin_login_sso_enabled">';
        echo '<input type="checkbox" id="admin_login_sso_enabled" name="admin_login_sso_enabled" value="1" ' . checked('1', $enabled, false) . ' />';
        echo esc_html__('Enable Google-Only Admin Login', 'admin-login-sso');
        echo '</label>';
        echo '<p class="description">' . esc_html__('When enabled, admin login is restricted to Google authentication only.', 'admin-login-sso') . '</p>';
    }

    /**
     * Auto-create users field callback
     */
    public function auto_create_users_callback() {
        $auto_create_users = get_option('admin_login_sso_auto_create_users');
        echo '<label for="admin_login_sso_auto_create_users">';
        echo '<input type="checkbox" id="admin_login_sso_auto_create_users" name="admin_login_sso_auto_create_users" value="1" ' . checked('1', $auto_create_users, false) . ' />';
        echo esc_html__('Auto-create admin users', 'admin-login-sso');
        echo '</label>';
        echo '<p class="description">' . esc_html__('When enabled, users with allowed email domains will be automatically created as administrators if they don\'t exist.', 'admin-login-sso') . '</p>';
    }

    /**
     * Render settings page
     */
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Check if settings were updated
        if (isset($_GET['settings-updated'])) {
            add_settings_error(
                'admin_login_sso_messages',
                'admin_login_sso_message',
                __('Settings saved.', 'admin-login-sso'),
                'updated'
            );
        }
        
        // Output settings form
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <?php settings_errors('admin_login_sso_messages'); ?>
            <form action="options.php" method="post">
                <?php
                settings_fields('admin_login_sso_settings');
                do_settings_sections('admin_login_sso_settings');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
}