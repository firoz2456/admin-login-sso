<?php
/**
 * Test script for domain validation
 * 
 * Usage: Run this file directly from the browser or CLI to test domain validation
 */

// Load WordPress
$wp_load_path = dirname(__FILE__) . '/../../../../wp-load.php';
if (!file_exists($wp_load_path)) {
    die('Could not find wp-load.php. Please adjust the path.');
}
require_once($wp_load_path);

// Check if user is admin
if (!current_user_can('manage_options')) {
    die('You must be logged in as an administrator to run this test.');
}

echo "<h2>Admin Login SSO Domain Validation Test</h2>";
echo "<pre>";

// Get the allowed domains setting
$allowed_domains = get_option('admin_login_sso_allowed_domains');
echo "Raw allowed_domains from database: ";
var_dump($allowed_domains);
echo "\n";

// Test wp_parse_list
$parsed_domains = wp_parse_list($allowed_domains);
echo "Parsed domains using wp_parse_list(): ";
var_dump($parsed_domains);
echo "\n";

// Test email addresses
$test_emails = array(
    'user@example.com',
    'admin@subdomain.example.com',
    'test@anotherdomain.org',
    'user@gmail.com',
    'admin@company.example.com'
);

echo "Testing email validation:\n";
echo str_repeat('-', 80) . "\n";

foreach ($test_emails as $email) {
    echo "\nTesting email: $email\n";
    
    // Extract domain
    $email_parts = explode('@', $email);
    $email_domain = isset($email_parts[1]) ? strtolower($email_parts[1]) : '';
    echo "  Email domain: $email_domain\n";
    
    // Test against each allowed domain
    $matched = false;
    foreach ($parsed_domains as $domain) {
        $domain = strtolower(trim($domain));
        echo "  Checking against: '$domain'\n";
        
        // Exact match
        if ($domain === $email_domain) {
            echo "    ✓ EXACT MATCH!\n";
            $matched = true;
            break;
        }
        
        // Wildcard match
        if (str_starts_with($domain, '*.')) {
            $domain_suffix = substr($domain, 1);
            echo "    Wildcard check - suffix: '$domain_suffix'\n";
            
            if (str_ends_with($email_domain, $domain_suffix)) {
                echo "    ✓ WILDCARD MATCH!\n";
                $matched = true;
                break;
            }
        }
    }
    
    echo "  Result: " . ($matched ? "ALLOWED" : "DENIED") . "\n";
}

echo "\n" . str_repeat('-', 80) . "\n";

// Show current user info
$current_user = wp_get_current_user();
echo "\nCurrent user email: " . $current_user->user_email . "\n";

// Additional debugging info
echo "\nPHP version: " . PHP_VERSION . "\n";
echo "WordPress version: " . get_bloginfo('version') . "\n";

// Check if functions exist
echo "\nFunction checks:\n";
echo "  str_starts_with exists: " . (function_exists('str_starts_with') ? 'Yes' : 'No') . "\n";
echo "  str_ends_with exists: " . (function_exists('str_ends_with') ? 'Yes' : 'No') . "\n";

echo "</pre>";