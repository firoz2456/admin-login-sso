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

        // AJAX handlers for the WAF-safe Client Secret save flow.
        add_action('wp_ajax_admin_login_sso_save_secret', array($this, 'ajax_save_secret'));
        add_action('wp_ajax_admin_login_sso_clear_secret', array($this, 'ajax_clear_secret'));
    }

    /**
     * Initialize the admin class
     */
    public function init() {
        // Add admin styles & scripts
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));

        // Register the contextual help tab on our settings screen.
        add_action('load-settings_page_admin-login-sso', array($this, 'register_help_tab'));

        // Show activation notice
        add_action('admin_notices', array($this, 'show_activation_notice'));
    }

    /**
     * Register the WP contextual Help tab for this screen.
     */
    public function register_help_tab() {
        $screen = get_current_screen();
        if (!$screen) { return; }

        $screen->add_help_tab(array(
            'id'      => 'als-help-overview',
            'title'   => __('Overview', 'admin-login-sso'),
            'content' =>
                '<p>' . esc_html__('Admin Login SSO restricts wp-admin sign-in to Google accounts on domains you trust.', 'admin-login-sso') . '</p>' .
                '<p>' . esc_html__('Workflow: create OAuth credentials in Google Cloud Console, paste them into the Connect to Google card, add allowed domains, then flip the master switch.', 'admin-login-sso') . '</p>',
        ));

        $screen->add_help_tab(array(
            'id'      => 'als-help-troubleshooting',
            'title'   => __('Troubleshooting', 'admin-login-sso'),
            'content' =>
                '<p><strong>' . esc_html__('"redirect_uri_mismatch"', 'admin-login-sso') . '</strong> — ' . esc_html__('The Redirect URI in this plugin does not match what is registered in Google Cloud Console. Copy the URI from the Connect to Google card exactly — http vs https, trailing slashes, and case all matter.', 'admin-login-sso') . '</p>' .
                '<p><strong>' . esc_html__('"The link you followed has expired"', 'admin-login-sso') . '</strong> — ' . esc_html__('Your WAF/Cloudflare is stripping the Settings POST body. This plugin already saves the Client Secret via a WAF-safe AJAX channel; routine settings saves no longer contain the secret.', 'admin-login-sso') . '</p>' .
                '<p><strong>' . esc_html__('Locked out?', 'admin-login-sso') . '</strong> — ' . esc_html__('Disable SSO via WP-CLI: wp option update admin_login_sso_enabled 0', 'admin-login-sso') . '</p>' .
                '<p><strong>' . esc_html__('User signed in but has the wrong role', 'admin-login-sso') . '</strong> — ' . esc_html__('Roles are not changed for existing WordPress users — whatever role they already had is kept. Auto-create only applies the first time a Google account signs in.', 'admin-login-sso') . '</p>' .
                '<p><strong>' . esc_html__('How long does a Google session last?', 'admin-login-sso') . '</strong> — ' . esc_html__('Once signed in, the user gets a standard WordPress auth cookie. Sessions last as long as that cookie (default 48 hours, 14 days with "Remember Me") regardless of whether the user is still signed into Google.', 'admin-login-sso') . '</p>',
        ));

        $screen->set_help_sidebar(
            '<p><strong>' . esc_html__('Useful links', 'admin-login-sso') . '</strong></p>' .
            '<p><a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer">' . esc_html__('Google Cloud Console — Credentials', 'admin-login-sso') . '</a></p>' .
            '<p><a href="https://developers.google.com/identity/protocols/oauth2" target="_blank" rel="noopener noreferrer">' . esc_html__('Google OAuth 2.0 docs', 'admin-login-sso') . '</a></p>'
        );
    }

    /**
     * Enqueue admin scripts (settings page only).
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_admin_scripts($hook) {
        if ('settings_page_admin-login-sso' !== $hook) {
            return;
        }

        wp_enqueue_script(
            'admin-login-sso-secret-save',
            ADMIN_LOGIN_SSO_PLUGIN_URL . 'assets/js/secret-save.js',
            array(),
            ADMIN_LOGIN_SSO_VERSION,
            true
        );

        wp_localize_script(
            'admin-login-sso-secret-save',
            'AdminLoginSsoSecret',
            array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce('admin_login_sso_secret'),
                'i18n'    => array(
                    'saving'         => __('Saving…', 'admin-login-sso'),
                    'saved'          => __('Secret saved.', 'admin-login-sso'),
                    'cleared'        => __('Secret cleared.', 'admin-login-sso'),
                    'clearConfirm'   => __('Remove the saved Client Secret? You will need to re-enter it before SSO works again.', 'admin-login-sso'),
                    'errorGeneric'   => __('Could not save the secret. Please try again.', 'admin-login-sso'),
                    'errorEmpty'     => __('Please enter a Client Secret first.', 'admin-login-sso'),
                    'copied'         => __('Copied!', 'admin-login-sso'),
                    'cidEmpty'       => __('Enter a Client ID to check.', 'admin-login-sso'),
                    'cidOk'          => __('Format looks valid.', 'admin-login-sso'),
                    'cidBad'         => __('Expected a value ending in .apps.googleusercontent.com', 'admin-login-sso'),
                ),
            )
        );
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
            __('Admin Login SSO Settings', 'admin-login-sso'),
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
        
        // NOTE: The Client Secret is intentionally NOT registered as a settings field.
        // It is rendered and saved via a dedicated AJAX flow (see render_secret_section()
        // and ajax_save_secret()) to avoid transmitting the GOCSPX-* value through
        // wp-admin/options.php, where WAFs may match it as a leaked-secret signature.

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
     * Client ID field callback.
     */
    public function client_id_callback() {
        $client_id = get_option('admin_login_sso_client_id');
        ?>
        <input
            type="text"
            id="admin_login_sso_client_id"
            name="admin_login_sso_client_id"
            value="<?php echo esc_attr($client_id); ?>"
            class="regular-text code"
            placeholder="123456789-abcdef.apps.googleusercontent.com"
            spellcheck="false"
            autocomplete="off"
        />
        <button type="button" class="button" data-action="validate-client-id"><?php esc_html_e('Check format', 'admin-login-sso'); ?></button>
        <p class="description">
            <?php esc_html_e('Found in Google Cloud Console under APIs & Services → Credentials → your OAuth 2.0 Client ID.', 'admin-login-sso'); ?>
        </p>
        <p class="als-field-feedback" data-feedback-for="admin_login_sso_client_id" aria-live="polite"></p>
        <?php
    }

    /**
     * Allowed Domains field callback.
     */
    public function allowed_domains_callback() {
        $allowed_domains = get_option('admin_login_sso_allowed_domains');
        ?>
        <textarea
            id="admin_login_sso_allowed_domains"
            name="admin_login_sso_allowed_domains"
            rows="4"
            class="large-text code"
            placeholder="example.com, gmail.com, *.company.org"
            spellcheck="false"
            data-action="domain-preview"
        ><?php echo esc_textarea($allowed_domains); ?></textarea>
        <p class="description">
            <?php esc_html_e('Comma-separated. Use *.example.org to allow the base domain and all its subdomains. Matching is case-insensitive. If the list is empty, no one can sign in via Google.', 'admin-login-sso'); ?>
        </p>
        <div class="als-chip-preview" data-chip-preview-for="admin_login_sso_allowed_domains" aria-live="polite"></div>
        <?php
    }

    /**
     * Enabled field callback — just the toggle and a one-line status.
     * Page-level status, setup guide, and config-required messaging live in
     * render_status_banner() / render_quick_setup_card() instead.
     */
    public function enabled_callback() {
        $enabled = get_option('admin_login_sso_enabled');
        ?>
        <label for="admin_login_sso_enabled" class="als-toggle">
            <input type="checkbox" id="admin_login_sso_enabled" name="admin_login_sso_enabled" value="1" <?php checked('1', $enabled); ?> />
            <span class="als-toggle__label"><?php esc_html_e('Enable Google-only admin login', 'admin-login-sso'); ?></span>
        </label>
        <p class="description">
            <?php esc_html_e('When enabled, all wp-admin sign-ins require Google sign-in with an allowed email domain.', 'admin-login-sso'); ?>
        </p>
        <p class="description als-warning">
            <strong><?php esc_html_e('Test before enabling.', 'admin-login-sso'); ?></strong>
            <?php
            printf(
                /* translators: %s: the label of the Test Google sign-in button. */
                esc_html__('Use %s in the Quick setup guide first — if Google credentials are misconfigured you can lock yourself out. Recover via WP-CLI:', 'admin-login-sso'),
                '<strong>' . esc_html__('Test Google sign-in', 'admin-login-sso') . '</strong>'
            );
            ?>
            <code>wp option update admin_login_sso_enabled 0</code>
        </p>
        <?php
    }

    /**
     * Auto-create users field callback.
     */
    public function auto_create_users_callback() {
        $auto_create_users = get_option('admin_login_sso_auto_create_users');
        ?>
        <label for="admin_login_sso_auto_create_users">
            <input type="checkbox" id="admin_login_sso_auto_create_users" name="admin_login_sso_auto_create_users" value="1" <?php checked('1', $auto_create_users); ?> />
            <?php
            printf(
                /* translators: %s: Administrator role name (bolded). */
                esc_html__('Auto-create users as %s when they first sign in with an allowed domain', 'admin-login-sso'),
                '<strong>' . esc_html__('Administrator', 'admin-login-sso') . '</strong>'
            );
            ?>
        </label>
        <p class="description">
            <?php esc_html_e('Recommended only if every person on your allowed domain should have full admin access. When off, only existing WordPress users (matched by email) can sign in — new Google accounts are rejected.', 'admin-login-sso'); ?>
        </p>
        <?php
    }

    /**
     * Show classic login field callback.
     */
    public function show_classic_login_callback() {
        $show_classic = get_option('admin_login_sso_show_classic_login', '1');
        ?>
        <label for="admin_login_sso_show_classic_login">
            <input type="checkbox" id="admin_login_sso_show_classic_login" name="admin_login_sso_show_classic_login" value="1" <?php checked('1', $show_classic); ?> />
            <?php esc_html_e('Also show the username/password form on the login page', 'admin-login-sso'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Recommended as a fallback. If you turn this off and Google sign-in breaks, you will need to recover via WP-CLI or by editing wp_options directly.', 'admin-login-sso'); ?>
        </p>
        <?php
    }

    /**
     * Render settings page.
     */
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_GET['settings-updated'])) {
            add_settings_error(
                'admin_login_sso_messages',
                'admin_login_sso_message',
                __('Settings saved.', 'admin-login-sso'),
                'updated'
            );
        }

        // Surface a one-shot AJAX success/failure notice (set by ajax_save_secret/ajax_clear_secret).
        $this->surface_ajax_flash();

        $state = $this->compute_status_state();
        $guide_at_top = in_array($state, array('not-configured', 'enabled-incomplete'), true);
        ?>
        <div class="wrap als-wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php $this->render_status_banner(); ?>
            <?php settings_errors('admin_login_sso_messages'); ?>

            <?php if ($guide_at_top) { $this->render_quick_setup_card(); } ?>

            <form action="options.php" method="post" class="als-form">
                <?php settings_fields('admin_login_sso_settings'); ?>

                <section class="als-card" aria-labelledby="als-card-connect">
                    <h2 id="als-card-connect" class="als-card__title">
                        <span class="dashicons dashicons-google" aria-hidden="true"></span>
                        <?php esc_html_e('Connect to Google', 'admin-login-sso'); ?>
                    </h2>
                    <p class="als-card__intro">
                        <?php
                        echo wp_kses(
                            __('Paste your Google OAuth credentials below to let users sign in with their Google account. New to OAuth? Follow the <a href="#als-card-help">Quick setup guide</a>.', 'admin-login-sso'),
                            array('a' => array('href' => array()))
                        );
                        ?>
                    </p>

                    <?php $this->render_redirect_uri_row(); ?>

                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="admin_login_sso_client_id"><?php esc_html_e('Client ID', 'admin-login-sso'); ?></label></th>
                            <td><?php $this->client_id_callback(); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Client Secret', 'admin-login-sso'); ?></th>
                            <td><?php $this->render_secret_section(); ?></td>
                        </tr>
                    </table>
                </section>

                <section class="als-card" aria-labelledby="als-card-access">
                    <h2 id="als-card-access" class="als-card__title">
                        <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                        <?php esc_html_e('Access control', 'admin-login-sso'); ?>
                    </h2>
                    <p class="als-card__intro">
                        <?php esc_html_e('Decide which email domains can sign in and how new users are handled.', 'admin-login-sso'); ?>
                    </p>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="admin_login_sso_allowed_domains"><?php esc_html_e('Allowed email domains', 'admin-login-sso'); ?></label></th>
                            <td><?php $this->allowed_domains_callback(); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('New users', 'admin-login-sso'); ?></th>
                            <td><?php $this->auto_create_users_callback(); ?></td>
                        </tr>
                    </table>
                </section>

                <section class="als-card" aria-labelledby="als-card-behavior">
                    <h2 id="als-card-behavior" class="als-card__title">
                        <span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
                        <?php esc_html_e('Login behavior', 'admin-login-sso'); ?>
                    </h2>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><?php esc_html_e('Classic login', 'admin-login-sso'); ?></th>
                            <td><?php $this->show_classic_login_callback(); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('SSO master switch', 'admin-login-sso'); ?></th>
                            <td><?php $this->enabled_callback(); ?></td>
                        </tr>
                    </table>
                </section>

                <?php submit_button(__('Save changes', 'admin-login-sso')); ?>
            </form>

            <?php if (!$guide_at_top) { $this->render_quick_setup_card(); } ?>
        </div>
        <?php
    }

    /**
     * Compute the overall page state for the consolidated status banner.
     *
     * @return string One of: 'not-configured', 'configured-disabled', 'enabled', 'enabled-incomplete'.
     */
    private function compute_status_state() {
        $enabled = (bool) get_option('admin_login_sso_enabled');
        $client_id = (string) get_option('admin_login_sso_client_id', '');
        $client_secret = (string) get_option('admin_login_sso_client_secret', '');
        $allowed_domains = (string) get_option('admin_login_sso_allowed_domains', '');

        $configured = ('' !== $client_id && '' !== $client_secret && '' !== $allowed_domains);

        if (!$configured && !$enabled) {
            return 'not-configured';
        }
        if (!$configured && $enabled) {
            return 'enabled-incomplete';
        }
        if ($configured && !$enabled) {
            return 'configured-disabled';
        }
        return 'enabled';
    }

    /**
     * Render the single top-of-page status banner.
     */
    private function render_status_banner() {
        $state = $this->compute_status_state();
        $client_id = (string) get_option('admin_login_sso_client_id', '');
        $client_secret = (string) get_option('admin_login_sso_client_secret', '');
        $allowed_domains = (string) get_option('admin_login_sso_allowed_domains', '');
        $missing = array();
        if ('' === $client_id) { $missing[] = __('Client ID', 'admin-login-sso'); }
        if ('' === $client_secret) { $missing[] = __('Client Secret', 'admin-login-sso'); }
        if ('' === $allowed_domains) { $missing[] = __('Allowed domains', 'admin-login-sso'); }

        switch ($state) {
            case 'not-configured':
                $class = 'notice notice-info';
                $icon = 'dashicons-info';
                $heading = __('Set up Google SSO', 'admin-login-sso');
                $body = __('Add your Google OAuth credentials and at least one allowed domain to get started. SSO will stay off until you enable it.', 'admin-login-sso');
                break;
            case 'enabled-incomplete':
                $class = 'notice notice-error';
                $icon = 'dashicons-warning';
                $heading = __('SSO is enabled but required settings are missing', 'admin-login-sso');
                /* translators: %s: comma-separated list of missing fields. */
                $body = sprintf(__('Missing: %s. New sign-ins to wp-admin will fail until this is fixed. Existing logged-in sessions remain valid. Recover via WP-CLI: wp option update admin_login_sso_enabled 0', 'admin-login-sso'), implode(', ', $missing));
                break;
            case 'configured-disabled':
                $class = 'notice notice-warning';
                $icon = 'dashicons-flag';
                $heading = __('SSO is configured but not enabled', 'admin-login-sso');
                $body = __('Standard WordPress login is being used. Turn on the SSO master switch in the Login behavior section to activate Google sign-in.', 'admin-login-sso');
                break;
            case 'enabled':
            default:
                $class = 'notice notice-success';
                $icon = 'dashicons-yes-alt';
                $heading = __('SSO is active', 'admin-login-sso');
                $body = __('All wp-admin sign-ins require Google sign-in with an allowed email domain.', 'admin-login-sso');
                break;
        }
        ?>
        <div class="<?php echo esc_attr($class); ?> als-status-banner">
            <p class="als-status-banner__heading">
                <span class="dashicons <?php echo esc_attr($icon); ?>" aria-hidden="true"></span>
                <strong><?php echo esc_html($heading); ?></strong>
            </p>
            <p class="als-status-banner__body"><?php echo esc_html($body); ?></p>
        </div>
        <?php
    }

    /**
     * Render the Redirect URI display row (used inside the Connect to Google card).
     */
    private function render_redirect_uri_row() {
        $auth = new Admin_Login_SSO_Auth();
        $redirect_uri = $auth->get_redirect_uri_display();
        ?>
        <div class="als-redirect">
            <div class="als-redirect__label">
                <strong><?php esc_html_e('Redirect URI', 'admin-login-sso'); ?></strong>
                <span class="als-redirect__hint">
                    <?php esc_html_e('In Google Cloud Console, open your OAuth client and paste this into Authorized redirect URIs. The value must match exactly — http vs https, trailing slashes, and case all matter.', 'admin-login-sso'); ?>
                </span>
            </div>
            <div class="als-redirect__row">
                <code class="als-redirect__value" id="als-redirect-uri-value"><?php echo esc_html($redirect_uri); ?></code>
                <button
                    type="button"
                    class="button"
                    data-action="copy"
                    data-copy-target="#als-redirect-uri-value"
                ><?php esc_html_e('Copy', 'admin-login-sso'); ?></button>
            </div>
        </div>
        <?php
    }

    /**
     * Quick setup guide card — separate from the master switch.
     */
    private function render_quick_setup_card() {
        $client_id = (string) get_option('admin_login_sso_client_id', '');
        $client_secret = (string) get_option('admin_login_sso_client_secret', '');
        $can_test = ('' !== $client_id && '' !== $client_secret);
        $kses_a = array('a' => array('href' => array(), 'target' => array(), 'rel' => array()));
        ?>
        <section class="als-card als-card--help" aria-labelledby="als-card-help">
            <h2 id="als-card-help" class="als-card__title">
                <span class="dashicons dashicons-sos" aria-hidden="true"></span>
                <?php esc_html_e('Quick setup guide', 'admin-login-sso'); ?>
            </h2>
            <p class="als-card__intro">
                <?php esc_html_e('First-time setup takes about 5 minutes in Google Cloud Console.', 'admin-login-sso'); ?>
            </p>
            <ol class="als-steps">
                <li><?php
                    printf(
                        /* translators: %s: link to Google Cloud Console home. */
                        wp_kses(__('In <a href="%s" target="_blank" rel="noopener noreferrer">Google Cloud Console</a>, select or create a project for this site.', 'admin-login-sso'), $kses_a),
                        'https://console.cloud.google.com/'
                    );
                ?></li>
                <li><?php
                    echo wp_kses(__('Under <strong>APIs &amp; Services → OAuth consent screen</strong>, configure consent (User type, app name, support email). Required before you can create credentials.', 'admin-login-sso'), array('strong' => array()));
                ?></li>
                <li><?php
                    echo wp_kses(__('Under <strong>APIs &amp; Services → Credentials</strong>, click <strong>Create credentials → OAuth client ID</strong>. Application type: <strong>Web application</strong>.', 'admin-login-sso'), array('strong' => array()));
                ?></li>
                <li><?php
                    echo wp_kses(__('In <strong>Authorized redirect URIs</strong>, paste the Redirect URI from the Connect to Google card above (use the Copy button). It must match exactly — <code>http</code> vs <code>https</code>, trailing slashes, and case all matter. A mismatch causes <code>redirect_uri_mismatch</code> errors.', 'admin-login-sso'), array('strong' => array(), 'code' => array()));
                ?></li>
                <li><?php esc_html_e('After Google generates the credentials:', 'admin-login-sso'); ?>
                    <ul class="als-substeps">
                        <li><?php echo wp_kses(__('Paste the <strong>Client ID</strong> into the field above and click <strong>Save changes</strong>.', 'admin-login-sso'), array('strong' => array())); ?></li>
                        <li><?php echo wp_kses(__('Paste the <strong>Client Secret</strong> into its field above and click <strong>Save secret</strong> (this is a separate save).', 'admin-login-sso'), array('strong' => array())); ?></li>
                    </ul>
                </li>
                <li><?php echo wp_kses(__('In <strong>Access control</strong>, add your allowed email domains.', 'admin-login-sso'), array('strong' => array())); ?></li>
                <li><?php
                    echo wp_kses(__('Click <strong>Test Google sign-in</strong> below — you should see Google\'s sign-in screen and land back on <code>wp-login.php</code>. Only after a successful test, turn on the <strong>SSO master switch</strong> in Login behavior.', 'admin-login-sso'), array('strong' => array(), 'code' => array()));
                ?></li>
            </ol>
            <?php if ($can_test) :
                $auth = new Admin_Login_SSO_Auth();
                $test_url = $auth->get_auth_url();
                ?>
                <p>
                    <a class="button button-secondary" href="<?php echo esc_url($test_url); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Test Google sign-in', 'admin-login-sso'); ?>
                    </a>
                    <span class="description">
                        <?php esc_html_e('Opens Google sign-in in a new tab using the credentials saved here. A successful test redirects you back to wp-login.php. If you see redirect_uri_mismatch, recheck step 4.', 'admin-login-sso'); ?>
                    </span>
                </p>
            <?php else : ?>
                <p class="description">
                    <em><?php esc_html_e('Add a Client ID and Client Secret above to enable the Test Google sign-in button.', 'admin-login-sso'); ?></em>
                </p>
            <?php endif; ?>
        </section>
        <?php
    }

    /**
     * Surface a one-shot flash message stored by the AJAX handlers.
     */
    private function surface_ajax_flash() {
        $user_id = get_current_user_id();
        if (!$user_id) { return; }
        $flash = get_user_meta($user_id, '_als_flash', true);
        if (!is_array($flash) || empty($flash['message'])) {
            return;
        }
        delete_user_meta($user_id, '_als_flash');
        add_settings_error(
            'admin_login_sso_messages',
            'admin_login_sso_flash',
            (string) $flash['message'],
            isset($flash['type']) ? (string) $flash['type'] : 'success'
        );
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

    /**
     * Render the Client Secret management section.
     *
     * This is rendered OUTSIDE the Settings API form, so saving the rest of the
     * settings never re-transmits the secret value. The secret itself is saved
     * via AJAX (see ajax_save_secret).
     */
    public function render_secret_section() {
        $stored = (string) get_option('admin_login_sso_client_secret', '');
        $has_secret = ('' !== $stored);
        $masked = $has_secret ? $this->mask_secret($stored) : '';
        ?>
        <div
            id="admin-login-sso-secret-section"
            class="als-secret"
            data-state="<?php echo $has_secret ? 'saved' : 'empty'; ?>"
            aria-busy="false"
        >
            <div id="admin-login-sso-secret-status">
                <div class="admin-login-sso-secret-saved als-secret__saved"<?php echo $has_secret ? '' : ' hidden'; ?>>
                    <p class="als-secret__display">
                        <span class="als-secret__badge">
                            <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                            <?php esc_html_e('Configured', 'admin-login-sso'); ?>
                        </span>
                        <code class="als-secret__mask" id="admin-login-sso-secret-mask" tabindex="-1"><?php echo esc_html($masked); ?></code>
                    </p>
                    <p>
                        <button type="button" class="button" id="admin-login-sso-secret-update-btn"><?php esc_html_e('Update', 'admin-login-sso'); ?></button>
                        <button type="button" class="button button-link-delete als-secret__clear" id="admin-login-sso-secret-clear-btn"><?php esc_html_e('Clear', 'admin-login-sso'); ?></button>
                    </p>
                </div>

                <div class="admin-login-sso-secret-form als-secret__form"<?php echo $has_secret ? ' hidden' : ''; ?>>
                    <p>
                        <input
                            type="password"
                            id="admin-login-sso-secret-input"
                            class="regular-text"
                            autocomplete="off"
                            placeholder="<?php echo $has_secret ? esc_attr__('Enter new secret to replace…', 'admin-login-sso') : esc_attr__('GOCSPX-…', 'admin-login-sso'); ?>"
                            aria-label="<?php esc_attr_e('Google Client Secret', 'admin-login-sso'); ?>"
                        />
                        <button type="button" class="button button-primary" id="admin-login-sso-secret-save-btn"><?php esc_html_e('Save secret', 'admin-login-sso'); ?></button>
                        <button type="button" class="button" id="admin-login-sso-secret-cancel-btn" hidden><?php esc_html_e('Cancel', 'admin-login-sso'); ?></button>
                    </p>
                    <p class="description">
                        <?php if ($has_secret) : ?>
                            <?php esc_html_e('Saving replaces the current secret. Existing logged-in sessions remain valid until they expire.', 'admin-login-sso'); ?>
                        <?php else : ?>
                            <?php esc_html_e('Found in Google Cloud Console alongside your Client ID. The secret saves on its own (Save secret) — it is never sent through the main Save changes form.', 'admin-login-sso'); ?>
                        <?php endif; ?>
                    </p>
                </div>

                <div id="admin-login-sso-secret-feedback" class="als-feedback" aria-live="polite"></div>
            </div>
        </div>
        <?php
    }

    /**
     * Build a masked display string for a stored secret.
     *
     * @param string $secret The raw secret.
     * @return string e.g. "••••••••6789"
     */
    private function mask_secret($secret) {
        $len = strlen($secret);
        if ($len <= 4) {
            return str_repeat('•', max(0, $len));
        }
        return str_repeat('•', 8) . substr($secret, -4);
    }

    /**
     * AJAX: save the Google Client Secret.
     *
     * Accepts a JSON request body (or form body as fallback) containing:
     *   - _ajax_nonce: nonce for the 'admin_login_sso_secret' action
     *   - gauth_blob:  base64-encoded Client Secret (neutral field name + encoding
     *                  defeats WAF pattern-matching on the GOCSPX- prefix)
     */
    public function ajax_save_secret() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions.', 'admin-login-sso')), 403);
        }

        $payload = $this->read_json_or_post_payload();
        $nonce = isset($payload['_ajax_nonce']) ? (string) $payload['_ajax_nonce'] : '';

        if (!wp_verify_nonce($nonce, 'admin_login_sso_secret')) {
            wp_send_json_error(array('message' => __('Security check failed. Please reload the page and try again.', 'admin-login-sso')), 403);
        }

        $blob = isset($payload['gauth_blob']) ? (string) $payload['gauth_blob'] : '';
        if ('' === $blob) {
            wp_send_json_error(array('message' => __('No secret provided.', 'admin-login-sso')), 400);
        }

        // Base64-decode the transported value.
        $decoded = base64_decode($blob, true);
        if (false === $decoded || '' === $decoded) {
            wp_send_json_error(array('message' => __('Could not decode the submitted value.', 'admin-login-sso')), 400);
        }

        // Sanitize. Mirrors Admin_Login_SSO::sanitize_client_secret() without re-running
        // plugin bootstrap. Length warning is downgraded to a soft response field so the
        // UI can surface it; the value is still stored either way.
        $clean = sanitize_text_field($decoded);
        if ('' === $clean) {
            wp_send_json_error(array('message' => __('The provided secret is empty after sanitization.', 'admin-login-sso')), 400);
        }
        $warning = '';
        if (strlen($clean) < 10) {
            $warning = __('Warning: the Client Secret looks unusually short. Please double-check it.', 'admin-login-sso');
        }

        update_option('admin_login_sso_client_secret', $clean);

        $this->set_ajax_flash(__('Google Client Secret saved.', 'admin-login-sso'), 'success');

        wp_send_json_success(array(
            'message' => __('Secret saved.', 'admin-login-sso'),
            'masked'  => $this->mask_secret($clean),
            'warning' => $warning,
        ));
    }

    /**
     * AJAX: clear the stored Google Client Secret.
     */
    public function ajax_clear_secret() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions.', 'admin-login-sso')), 403);
        }

        $payload = $this->read_json_or_post_payload();
        $nonce = isset($payload['_ajax_nonce']) ? (string) $payload['_ajax_nonce'] : '';

        if (!wp_verify_nonce($nonce, 'admin_login_sso_secret')) {
            wp_send_json_error(array('message' => __('Security check failed. Please reload the page and try again.', 'admin-login-sso')), 403);
        }

        delete_option('admin_login_sso_client_secret');

        $this->set_ajax_flash(__('Google Client Secret cleared.', 'admin-login-sso'), 'success');

        wp_send_json_success(array(
            'message' => __('Secret cleared.', 'admin-login-sso'),
        ));
    }

    /**
     * Stash a flash message to surface on the next settings-page load.
     * Persists across the AJAX → reload boundary so a refresh still shows
     * the success notice via WP's native settings_errors() pipeline.
     */
    private function set_ajax_flash($message, $type = 'success') {
        $user_id = get_current_user_id();
        if (!$user_id) { return; }
        update_user_meta($user_id, '_als_flash', array(
            'message' => (string) $message,
            'type'    => (string) $type,
        ));
    }

    /**
     * Read the request payload, accepting either JSON or standard form-encoded POST.
     *
     * JSON is preferred because most WAFs inspect application/x-www-form-urlencoded
     * bodies more aggressively. The form fallback keeps the endpoint usable from
     * environments where fetch() can't send a JSON body.
     *
     * @return array
     */
    private function read_json_or_post_payload() {
        $content_type = isset($_SERVER['CONTENT_TYPE']) ? strtolower((string) $_SERVER['CONTENT_TYPE']) : '';
        if (false !== strpos($content_type, 'application/json')) {
            $raw = file_get_contents('php://input');
            if (is_string($raw) && '' !== $raw) {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }
            return array();
        }
        return wp_unslash($_POST);
    }
}