<?php
/**
 * Emergency bypass script for Admin Login SSO
 * 
 * Usage: Navigate to /wp-content/plugins/admin-login-sso/emergency-bypass.php?action=check_credentials
 */

// Load WordPress
$wp_load_path = dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
if (!file_exists($wp_load_path)) {
    die('Could not find wp-load.php');
}
require_once $wp_load_path;

// Check if user is logged in as admin via standard WordPress auth
if (!current_user_can('manage_options')) {
    die('You must be logged in as an administrator to use this tool.');
}

$action = isset($_GET['action']) ? $_GET['action'] : '';

?>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login SSO - Emergency Bypass</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 10px 0; }
        .success { background: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 10px 0; }
        .error { background: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 10px 0; }
        .warning { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .button { display: inline-block; padding: 10px 20px; background: #0073aa; color: white; text-decoration: none; margin: 5px; }
        .button:hover { background: #005a87; }
    </style>
</head>
<body>
    <h1>Admin Login SSO - Emergency Bypass Tool</h1>
    
    <?php if (empty($action)): ?>
        <div class="info">
            <h3>Available Actions:</h3>
            <p><a href="?action=check_credentials" class="button">Check Google API Credentials</a></p>
            <p><a href="?action=disable_plugin" class="button">Temporarily Disable SSO</a></p>
            <p><a href="?action=clear_auth_meta" class="button">Clear Authentication Meta</a></p>
            <p><a href="?action=view_settings" class="button">View Current Settings</a></p>
        </div>
    <?php endif; ?>

    <?php
    switch ($action) {
        case 'check_credentials':
            echo '<h2>Checking Google API Credentials</h2>';
            
            $client_id = get_option('admin_login_sso_client_id');
            $client_secret = get_option('admin_login_sso_client_secret');
            $allowed_domains = get_option('admin_login_sso_allowed_domains');
            
            if (empty($client_id) || empty($client_secret)) {
                echo '<div class="error">Google API credentials are not configured!</div>';
            } else {
                echo '<div class="info">';
                echo '<strong>Client ID:</strong> ' . esc_html($client_id) . '<br>';
                echo '<strong>Client Secret:</strong> ' . (strlen($client_secret) > 0 ? '***' . substr($client_secret, -4) : 'Not set') . '<br>';
                echo '<strong>Allowed Domains:</strong> ' . esc_html($allowed_domains ?: 'None configured') . '<br>';
                echo '</div>';
                
                // Validate format
                if (!preg_match('/\.apps\.googleusercontent\.com$/', $client_id)) {
                    echo '<div class="warning">Client ID format appears invalid. Should end with .apps.googleusercontent.com</div>';
                }
                
                if (strlen($client_secret) < 10) {
                    echo '<div class="warning">Client Secret appears too short.</div>';
                }
                
                // Test OAuth URL generation
                $redirect_uri = wp_login_url() . '?action=admin_login_sso_callback';
                $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
                    'client_id' => $client_id,
                    'redirect_uri' => $redirect_uri,
                    'response_type' => 'code',
                    'scope' => 'email profile',
                    'access_type' => 'online',
                    'prompt' => 'select_account'
                ]);
                
                echo '<div class="info">';
                echo '<strong>Redirect URI (add this to Google Console):</strong><br>';
                echo '<pre>' . esc_html($redirect_uri) . '</pre>';
                echo '</div>';
                
                echo '<div class="info">';
                echo '<strong>Test OAuth URL:</strong><br>';
                echo '<a href="' . esc_url($auth_url) . '" target="_blank">Test Google OAuth Flow</a> (opens in new tab)';
                echo '</div>';
            }
            break;
            
        case 'disable_plugin':
            echo '<h2>Temporarily Disable SSO</h2>';
            
            // Set a temporary option to bypass SSO
            if (isset($_GET['confirm'])) {
                update_option('admin_login_sso_emergency_bypass', time() + 3600); // 1 hour bypass
                echo '<div class="success">SSO temporarily disabled for 1 hour. You can now access wp-admin normally.</div>';
            } else {
                echo '<div class="warning">This will temporarily disable Google SSO for 1 hour.</div>';
                echo '<p><a href="?action=disable_plugin&confirm=1" class="button">Confirm - Disable SSO for 1 hour</a></p>';
            }
            break;
            
        case 'clear_auth_meta':
            echo '<h2>Clear Authentication Meta</h2>';
            
            if (isset($_GET['confirm'])) {
                // Clear auth meta for all users
                $users = get_users();
                $count = 0;
                foreach ($users as $user) {
                    if (delete_user_meta($user->ID, 'admin_login_sso_authenticated')) {
                        $count++;
                    }
                }
                echo '<div class="success">Cleared authentication meta for ' . $count . ' users.</div>';
            } else {
                echo '<div class="warning">This will clear Google authentication status for all users.</div>';
                echo '<p><a href="?action=clear_auth_meta&confirm=1" class="button">Confirm - Clear All Auth Meta</a></p>';
            }
            break;
            
        case 'view_settings':
            echo '<h2>Current Plugin Settings</h2>';
            
            $settings = [
                'admin_login_sso_enabled' => get_option('admin_login_sso_enabled'),
                'admin_login_sso_client_id' => get_option('admin_login_sso_client_id'),
                'admin_login_sso_client_secret' => get_option('admin_login_sso_client_secret') ? '***' . substr(get_option('admin_login_sso_client_secret'), -4) : 'Not set',
                'admin_login_sso_allowed_domains' => get_option('admin_login_sso_allowed_domains'),
                'admin_login_sso_auto_create_users' => get_option('admin_login_sso_auto_create_users'),
                'admin_login_sso_button_text' => get_option('admin_login_sso_button_text'),
                'admin_login_sso_show_classic_login' => get_option('admin_login_sso_show_classic_login'),
                'admin_login_sso_emergency_bypass' => get_option('admin_login_sso_emergency_bypass')
            ];
            
            echo '<div class="info"><pre>' . print_r($settings, true) . '</pre></div>';
            
            // Check current user auth status
            $current_user_id = get_current_user_id();
            $is_google_auth = get_user_meta($current_user_id, 'admin_login_sso_authenticated', true);
            echo '<div class="info">';
            echo '<strong>Your Google Auth Status:</strong> ' . ($is_google_auth ? 'Authenticated' : 'Not authenticated') . '<br>';
            echo '<strong>Your User ID:</strong> ' . $current_user_id . '<br>';
            echo '</div>';
            break;
    }
    ?>
    
    <hr>
    <p><a href="?">&larr; Back to main menu</a> | <a href="<?php echo admin_url(); ?>">Go to WordPress Admin</a></p>
</body>
</html>