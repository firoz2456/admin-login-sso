<?php
/**
 * Debug script to check domain settings
 * 
 * Usage: Access this file directly in browser while logged in as admin
 */

// Load WordPress
$wp_load_path = dirname(__FILE__) . '/../../../../wp-load.php';
if (!file_exists($wp_load_path)) {
    die('Could not find wp-load.php');
}
require_once($wp_load_path);

// Check if user is admin
if (!current_user_can('manage_options')) {
    die('You must be logged in as an administrator to view this page.');
}

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>Admin Login SSO - Domain Settings Debug</h1>";
echo "<pre style='background: #f5f5f5; padding: 20px; border: 1px solid #ddd;'>";

// Check all relevant options
$options = array(
    'admin_login_sso_enabled',
    'admin_login_sso_client_id',
    'admin_login_sso_client_secret',
    'admin_login_sso_allowed_domains'
);

echo "=== OPTION VALUES ===\n\n";
foreach ($options as $option) {
    $value = get_option($option);
    echo "$option:\n";
    var_dump($value);
    
    // For allowed domains, show additional info
    if ($option === 'admin_login_sso_allowed_domains' && !empty($value)) {
        echo "\nRaw string length: " . strlen($value) . "\n";
        echo "Raw bytes: ";
        for ($i = 0; $i < strlen($value); $i++) {
            echo "[" . ord($value[$i]) . "]";
        }
        echo "\n\nParsed with wp_parse_list():\n";
        $parsed = wp_parse_list($value);
        var_dump($parsed);
        
        echo "\nParsed domains details:\n";
        foreach ($parsed as $idx => $domain) {
            echo "  [$idx] => \"$domain\" (length: " . strlen($domain) . ")\n";
        }
    }
    echo "\n" . str_repeat('-', 60) . "\n\n";
}

// Test the authentication handler
echo "\n=== AUTHENTICATION HANDLER TEST ===\n\n";

if (class_exists('Admin_Login_SSO_Auth')) {
    $auth = new Admin_Login_SSO_Auth();
    
    // Use reflection to call private method
    $reflection = new ReflectionClass($auth);
    $method = $reflection->getMethod('validate_email_domain');
    $method->setAccessible(true);
    
    $test_emails = array(
        'user@example.com',
        'admin@test.example.com',
        'user@gmail.com',
        'test@subdomain.example.com'
    );
    
    echo "Testing domain validation:\n\n";
    foreach ($test_emails as $email) {
        $result = $method->invoke($auth, $email);
        echo "$email => " . ($result ? 'ALLOWED' : 'DENIED') . "\n";
    }
} else {
    echo "Admin_Login_SSO_Auth class not found.\n";
}

// Show WordPress debug log if available
echo "\n=== RECENT DEBUG LOG ENTRIES ===\n\n";
$debug_log = WP_CONTENT_DIR . '/debug.log';
if (file_exists($debug_log)) {
    $lines = file($debug_log);
    $recent_lines = array_slice($lines, -50); // Last 50 lines
    $sso_lines = array_filter($recent_lines, function($line) {
        return strpos($line, '[Admin Login SSO]') !== false;
    });
    
    if (!empty($sso_lines)) {
        foreach ($sso_lines as $line) {
            echo htmlspecialchars($line);
        }
    } else {
        echo "No recent Admin Login SSO log entries found.\n";
    }
} else {
    echo "Debug log file not found. Enable WP_DEBUG_LOG in wp-config.php.\n";
}

echo "</pre>";

// Add form to update domains for testing
?>
<h2>Update Allowed Domains</h2>
<form method="post" action="options.php">
    <?php settings_fields('admin_login_sso_settings'); ?>
    <p>
        <label>Allowed Domains (comma-separated):<br>
        <textarea name="admin_login_sso_allowed_domains" rows="5" cols="60"><?php echo esc_textarea(get_option('admin_login_sso_allowed_domains')); ?></textarea>
        </label>
    </p>
    <p>Examples: example.com, *.example.org, gmail.com</p>
    <?php submit_button('Update Domains'); ?>
</form>