<?php
declare(strict_types=1);
/**
 * Main plugin class
 *
 * @package Admin_Login_SSO
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main plugin class
 */
class Admin_Login_SSO {

    /**
     * Instance of the class
     *
     * @var Admin_Login_SSO
     */
    private static $instance = null;

    /**
     * Constructor
     */
    public function __construct() {
        // Load dependencies
        $this->load_dependencies();
    }

    /**
     * Initialize the plugin
     */
    public function init() {
        // Load plugin text domain
        add_action('init', array($this, 'load_textdomain'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add settings page
        add_action('admin_menu', array($this, 'add_settings_page'));
        
        // Initialize admin functionality
        $admin = new Admin_Login_SSO_Admin();
        $admin->init();
        
        // Initialize authentication
        $this->init_authentication();
    }

    /**
     * Load required dependencies
     */
    private function load_dependencies() {
        // Admin-related functionality
        require_once ADMIN_LOGIN_SSO_PLUGIN_DIR . 'admin/class-admin-login-sso-admin.php';
        
        // Authentication functionality
        require_once ADMIN_LOGIN_SSO_PLUGIN_DIR . 'includes/class-admin-login-sso-auth.php';
        
        // User provisioning
        require_once ADMIN_LOGIN_SSO_PLUGIN_DIR . 'includes/class-admin-login-sso-user.php';
    }

    /**
     * Load plugin text domain
     */
    public function load_textdomain() {
        load_plugin_textdomain('admin-login-sso', false, dirname(ADMIN_LOGIN_SSO_PLUGIN_BASENAME) . '/languages');
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        // Register settings
        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_client_id',
            array(
                'type' => 'string',
                'description' => __('Google Client ID', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_client_id'),
                'default' => '',
            )
        );

        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_client_secret',
            array(
                'type' => 'string',
                'description' => __('Google Client Secret', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_client_secret'),
                'default' => '',
            )
        );

        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_allowed_domains',
            array(
                'type' => 'string',
                'description' => __('Allowed Domains', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_domains'),
                'default' => '',
            )
        );

        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_enabled',
            array(
                'type' => 'boolean',
                'description' => __('Enable Google-Only Admin Login', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_checkbox'),
                'default' => false,
            )
        );

        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_auto_create_users',
            array(
                'type' => 'boolean',
                'description' => __('Auto-create admin users', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_checkbox'),
                'default' => false,
            )
        );
        
        register_setting(
            'admin_login_sso_settings',
            'admin_login_sso_show_classic_login',
            array(
                'type' => 'boolean',
                'description' => __('Show classic login form', 'admin-login-sso'),
                'sanitize_callback' => array($this, 'sanitize_checkbox'),
                'default' => true,
            )
        );
    }

    /**
     * Add settings page
     */
    public function add_settings_page() {
        add_options_page(
            __('Google Admin Login', 'admin-login-sso'),
            __('Google Admin Login', 'admin-login-sso'),
            'manage_options',
            'admin-login-sso',
            array($this, 'render_settings_page')
        );
    }

    /**
     * Render settings page
     */
    public function render_settings_page() {
        $admin = new Admin_Login_SSO_Admin();
        $admin->render_settings_page();
    }

    /**
     * Initialize authentication
     */
    private function init_authentication() {
        $auth = new Admin_Login_SSO_Auth();
        $auth->init();
    }

    /**
     * Sanitize domains input
     *
     * @param string $input Input from settings
     * @return string Sanitized domains
     */
    public function sanitize_domains($input) {
        if (empty($input)) {
            add_settings_error(
                'admin_login_sso_allowed_domains',
                'empty_domains',
                __('Warning: No domains were specified. This will prevent all Google logins until domains are added.', 'admin-login-sso'),
                'warning'
            );
            return '';
        }

        // Split by commas
        $domains = explode(',', $input);
        $sanitized_domains = array();
        $invalid_domains = array();

        foreach ($domains as $domain) {
            $domain = trim($domain);
            
            if (empty($domain)) {
                continue;
            }
            
            // Allow wildcards in domains, e.g., *.example.com
            if (preg_match('/^(\*\.)?([\w-]+\.)+[\w-]{2,}$/', $domain) || filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
                $sanitized_domains[] = $domain;
            } else {
                $invalid_domains[] = $domain;
            }
        }
        
        // Show error for invalid domains
        if (!empty($invalid_domains)) {
            add_settings_error(
                'admin_login_sso_allowed_domains',
                'invalid_domains',
                sprintf(
                    __('These domains were removed because they are invalid: %s', 'admin-login-sso'),
                    '<code>' . esc_html(implode(', ', $invalid_domains)) . '</code>'
                ),
                'error'
            );
        }
        
        // Show warning if no valid domains provided
        if (empty($sanitized_domains)) {
            add_settings_error(
                'admin_login_sso_allowed_domains',
                'no_valid_domains',
                __('No valid domains were provided. Google login will not function until you add at least one valid domain.', 'admin-login-sso'),
                'error'
            );
            return '';
        }

        return implode(',', $sanitized_domains);
    }

    /**
     * Sanitize checkbox input
     *
     * @param mixed $input Input from settings
     * @return string '1' if true, '0' if false
     */
    public function sanitize_checkbox($input) {
        // Special handling for the enabled checkbox
        if (current_filter() === 'sanitize_option_admin_login_sso_enabled' && !empty($input)) {
            // Check if credentials are configured
            $client_id = get_option('admin_login_sso_client_id');
            $client_secret = get_option('admin_login_sso_client_secret');
            $allowed_domains = get_option('admin_login_sso_allowed_domains');
            
            if (empty($client_id) || empty($client_secret)) {
                add_settings_error(
                    'admin_login_sso_enabled',
                    'missing_credentials',
                    __('Cannot enable SSO: Please configure Google Client ID and Client Secret first.', 'admin-login-sso'),
                    'error'
                );
                return '0';
            }
            
            if (empty($allowed_domains)) {
                add_settings_error(
                    'admin_login_sso_enabled',
                    'missing_domains',
                    __('Cannot enable SSO: Please configure at least one allowed email domain.', 'admin-login-sso'),
                    'error'
                );
                return '0';
            }
        }
        
        return !empty($input) ? '1' : '0';
    }
    
    /**
     * Sanitize and validate Google Client ID
     *
     * @param string $input Input from settings
     * @return string Sanitized client ID
     */
    public function sanitize_client_id($input) {
        $input = sanitize_text_field($input);
        
        if (empty($input)) {
            // Allow empty value for disabling
            return '';
        }
        
        // Very basic validation - Google Client IDs are typically in format: 
        // XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com
        if (!preg_match('/^[\w-]+\.apps\.googleusercontent\.com$/', $input)) {
            add_settings_error(
                'admin_login_sso_client_id',
                'invalid_client_id',
                __('Warning: The Google Client ID doesn\'t appear to be in the correct format. Google Client IDs typically end with .apps.googleusercontent.com', 'admin-login-sso'),
                'warning'
            );
        }
        
        return $input;
    }
    
    /**
     * Sanitize and validate Google Client Secret
     *
     * @param string $input Input from settings
     * @return string Sanitized client secret
     */
    public function sanitize_client_secret($input) {
        $input = sanitize_text_field($input);
        
        if (empty($input)) {
            // Allow empty value for disabling
            return '';
        }
        
        // Basic validation - Google Client Secrets are typically around 24 characters
        if (strlen($input) < 10) {
            add_settings_error(
                'admin_login_sso_client_secret',
                'invalid_client_secret',
                __('Warning: The Google Client Secret seems too short. Please verify you\'ve entered it correctly.', 'admin-login-sso'),
                'warning'
            );
        }
        
        return $input;
    }

    /**
     * Get instance of the class
     *
     * @return Admin_Login_SSO Instance of the class
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
}