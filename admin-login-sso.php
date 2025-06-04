<?php
declare(strict_types=1);
/**
 * Plugin Name: Admin Login SSO
 * Plugin URI: https://wordpress.org/plugins/admin-login-sso/
 * Description: Replace WordPress admin login with Google OAuth2 authentication, restricting access to specific email domains.
 * Version: 1.0.0
 * Author: Firoz
 * Author URI: https://wordpress.org/plugins/admin-login-sso/
 * Text Domain: admin-login-sso
 * Domain Path: /languages
 * Requires at least: 6.4
 * Requires PHP: 8.0
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('ADMIN_LOGIN_SSO_VERSION', '1.0.0');
define('ADMIN_LOGIN_SSO_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ADMIN_LOGIN_SSO_PLUGIN_URL', plugin_dir_url(__FILE__));
define('ADMIN_LOGIN_SSO_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Include required files
require_once ADMIN_LOGIN_SSO_PLUGIN_DIR . 'includes/class-admin-login-sso.php';

// Initialize the plugin
function admin_login_sso_init() {
    $plugin = new Admin_Login_SSO();
    $plugin->init();
}
add_action('plugins_loaded', 'admin_login_sso_init');

// Plugin activation hook
register_activation_hook(__FILE__, 'admin_login_sso_activate');
function admin_login_sso_activate() {
    // Set default options if not already set
    if (!get_option('admin_login_sso_client_id')) {
        add_option('admin_login_sso_client_id', '', '', 'no');
    }
    
    if (!get_option('admin_login_sso_client_secret')) {
        add_option('admin_login_sso_client_secret', '', '', 'no');
    }
    
    if (!get_option('admin_login_sso_allowed_domains')) {
        add_option('admin_login_sso_allowed_domains', '', '', 'no');
    }
    
    if (!get_option('admin_login_sso_enabled')) {
        add_option('admin_login_sso_enabled', '0', '', 'no');
    }
    
    if (!get_option('admin_login_sso_auto_create_users')) {
        add_option('admin_login_sso_auto_create_users', '0', '', 'no');
    }
    
    // Add rewrite rules if needed
    flush_rewrite_rules();
}

// Plugin deactivation hook
register_deactivation_hook(__FILE__, 'admin_login_sso_deactivate');
function admin_login_sso_deactivate() {
    // Clean up if needed
    flush_rewrite_rules();
}

// Add settings link on the plugins page
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'admin_login_sso_plugin_action_links');
function admin_login_sso_plugin_action_links($links) {
    $settings_link = '<a href="' . admin_url('options-general.php?page=admin-login-sso') . '">' . __('Settings', 'admin-login-sso') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
}