<?php
declare(strict_types=1);
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
        // Add settings sections and fields
        add_action('admin_init', array($this, 'register_settings_sections'));
    }
    
    /**
     * Initialize the admin class
     */
    public function init() {
        // Add admin styles
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
        
        // Show activation notice
        add_action('admin_notices', array($this, 'show_activation_notice'));
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
        
        // Add enable/disable field FIRST
        add_settings_field(
            'admin_login_sso_enabled',
            __('Enable Google-Only Admin Login', 'admin-login-sso'),
            array($this, 'enabled_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
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
            'admin_login_sso_auto_create_users',
            __('Auto-create admin users', 'admin-login-sso'),
            array($this, 'auto_create_users_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
        
        add_settings_field(
            'admin_login_sso_show_classic_login',
            __('Show classic login form', 'admin-login-sso'),
            array($this, 'show_classic_login_callback'),
            'admin_login_sso_settings',
            'admin_login_sso_settings_section'
        );
    }

    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        // Nothing here - we'll show instructions after the enable checkbox
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
        $client_id = get_option('admin_login_sso_client_id');
        $client_secret = get_option('admin_login_sso_client_secret');
        $allowed_domains = get_option('admin_login_sso_allowed_domains');
        
        // Main enable/disable checkbox with prominent styling
        echo '<div style="margin-bottom: 20px; padding: 20px; background: #f8f9fa; border: 2px solid ' . ($enabled ? '#28a745' : '#dee2e6') . '; border-radius: 5px;">';
        
        echo '<label for="admin_login_sso_enabled" style="display: flex; align-items: center; cursor: pointer;">';
        echo '<input type="checkbox" id="admin_login_sso_enabled" name="admin_login_sso_enabled" value="1" ' . checked('1', $enabled, false) . ' style="margin-right: 10px; transform: scale(1.5);" />';
        echo '<span style="font-size: 18px; font-weight: bold;">' . esc_html__('Enable Google-Only Admin Login', 'admin-login-sso') . '</span>';
        echo '</label>';
        
        // Status message
        if ($enabled) {
            echo '<div style="margin-top: 10px; padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 3px; color: #155724;">';
            echo '<strong>✓ ' . esc_html__('SSO is ACTIVE', 'admin-login-sso') . '</strong> - ' . esc_html__('All admin logins require Google authentication.', 'admin-login-sso');
            echo '</div>';
        } else {
            echo '<div style="margin-top: 10px; padding: 10px; background: #fff3cd; border: 1px solid #ffeeba; border-radius: 3px; color: #856404;">';
            echo '<strong>✗ ' . esc_html__('SSO is INACTIVE', 'admin-login-sso') . '</strong> - ' . esc_html__('Standard WordPress login is being used.', 'admin-login-sso');
            echo '</div>';
        }
        
        // Configuration status
        if (empty($client_id) || empty($client_secret) || empty($allowed_domains)) {
            echo '<div style="margin-top: 10px; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 3px; color: #721c24;">';
            echo '<strong>' . esc_html__('⚠️ Configuration Required:', 'admin-login-sso') . '</strong><br>';
            if (empty($client_id)) echo '• ' . esc_html__('Google Client ID is missing', 'admin-login-sso') . '<br>';
            if (empty($client_secret)) echo '• ' . esc_html__('Google Client Secret is missing', 'admin-login-sso') . '<br>';
            if (empty($allowed_domains)) echo '• ' . esc_html__('No allowed domains configured', 'admin-login-sso') . '<br>';
            echo '</div>';
        }
        
        echo '</div>';
        
        // Setup instructions
        echo '<div style="margin-bottom: 30px; padding: 20px; background: #e7f3ff; border: 1px solid #b3d9ff; border-radius: 5px;">';
        echo '<h3 style="margin-top: 0;">' . esc_html__('Quick Setup Guide', 'admin-login-sso') . '</h3>';
        
        // Show the redirect URI
        echo '<p><strong>' . esc_html__('Your Redirect URI:', 'admin-login-sso') . '</strong><br>';
        echo '<code style="background: #fff; padding: 5px; border: 1px solid #ddd;">' . esc_html(site_url('wp-login.php?action=admin_login_sso_callback')) . '</code>';
        echo ' <button type="button" class="button button-small" onclick="navigator.clipboard.writeText(\'' . esc_js(site_url('wp-login.php?action=admin_login_sso_callback')) . '\');">' . esc_html__('Copy', 'admin-login-sso') . '</button></p>';
        
        echo '<ol style="margin-left: 20px;">';
        echo '<li>' . esc_html__('Go to', 'admin-login-sso') . ' <a href="https://console.cloud.google.com/apis/credentials" target="_blank">' . esc_html__('Google Cloud Console', 'admin-login-sso') . '</a></li>';
        echo '<li>' . esc_html__('Create OAuth 2.0 Client ID (Web application type)', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Add the Redirect URI above to authorized redirect URIs', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Copy Client ID and Secret to fields below', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Configure allowed email domains', 'admin-login-sso') . '</li>';
        echo '<li>' . esc_html__('Save settings and test login before enabling SSO', 'admin-login-sso') . '</li>';
        echo '</ol>';
        
        // Add test login button if credentials are configured
        if (!empty($client_id) && !empty($client_secret)) {
            $auth = new Admin_Login_SSO_Auth();
            $test_url = $auth->get_auth_url();
            echo '<p style="margin-top: 15px;">';
            echo '<a href="' . esc_url($test_url) . '" class="button button-secondary" target="_blank">' . esc_html__('Test Google Login', 'admin-login-sso') . '</a>';
            echo ' <span class="description">' . esc_html__('Opens in new window. You should see Google login and return to wp-login.php', 'admin-login-sso') . '</span>';
            echo '</p>';
        }
        
        echo '</div>';
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
     * Show classic login field callback
     */
    public function show_classic_login_callback() {
        $show_classic = get_option('admin_login_sso_show_classic_login', '1');
        echo '<label for="admin_login_sso_show_classic_login">';
        echo '<input type="checkbox" id="admin_login_sso_show_classic_login" name="admin_login_sso_show_classic_login" value="1" ' . checked('1', $show_classic, false) . ' />';
        echo esc_html__('Show classic login form on the login page', 'admin-login-sso');
        echo '</label>';
        echo '<p class="description">' . esc_html__('When enabled, the traditional WordPress login form will be visible in addition to the Google login button.', 'admin-login-sso') . '</p>';
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
        
        // Get current settings
        $enabled = get_option('admin_login_sso_enabled');
        $client_id = get_option('admin_login_sso_client_id');
        $client_secret = get_option('admin_login_sso_client_secret');
        
        // Output settings form
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <?php
            // Show SSO status notice
            if (!$enabled) {
                echo '<div class="notice notice-warning" style="border-left-color: #ffc107;">';
                echo '<p style="font-size: 16px;"><strong>' . esc_html__('🟡 SSO Status: DISABLED', 'admin-login-sso') . '</strong></p>';
                echo '<p>' . esc_html__('The plugin is active but SSO is disabled. Standard WordPress login is being used.', 'admin-login-sso') . '</p>';
                if (empty($client_id) || empty($client_secret)) {
                    echo '<p>' . esc_html__('To enable SSO, please configure your Google API credentials below.', 'admin-login-sso') . '</p>';
                }
                echo '</div>';
            }
            ?>
            
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
    
    /**
     * Show activation notice
     */
    public function show_activation_notice() {
        // Check if plugin was just activated
        if (!get_transient('admin_login_sso_activated')) {
            return;
        }
        
        // Delete the transient
        delete_transient('admin_login_sso_activated');
        
        // Check if plugin is configured
        $client_id = get_option('admin_login_sso_client_id');
        $client_secret = get_option('admin_login_sso_client_secret');
        $allowed_domains = get_option('admin_login_sso_allowed_domains');
        $enabled = get_option('admin_login_sso_enabled');
        
        ?>
        <div class="notice notice-info is-dismissible">
            <p><strong><?php _e('Admin Login SSO has been activated!', 'admin-login-sso'); ?></strong></p>
            
            <?php if (empty($client_id) || empty($client_secret) || empty($allowed_domains)) : ?>
                <p><?php _e('To get started, you need to configure the plugin with your Google OAuth2 credentials.', 'admin-login-sso'); ?></p>
                <p>
                    <a href="<?php echo esc_url(admin_url('options-general.php?page=admin-login-sso')); ?>" class="button button-primary">
                        <?php _e('Configure Plugin Settings', 'admin-login-sso'); ?>
                    </a>
                </p>
            <?php elseif (!$enabled) : ?>
                <p><?php _e('The plugin is configured but SSO is not enabled yet.', 'admin-login-sso'); ?></p>
                <p>
                    <a href="<?php echo esc_url(admin_url('options-general.php?page=admin-login-sso')); ?>" class="button button-primary">
                        <?php _e('Enable SSO', 'admin-login-sso'); ?>
                    </a>
                </p>
            <?php else : ?>
                <p><?php _e('SSO is enabled and ready to use. Make sure your email domain is in the allowed list before logging out.', 'admin-login-sso'); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }
}