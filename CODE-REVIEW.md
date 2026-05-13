# Code Review — admin-login-sso 1.2.1

Reviewer: Claude (Opus 4.7)
Branch: `chore/cleanup-and-review`
Base commit: `79bd846`
Date: 2026-05-13

## Scope

Files reviewed:

- `admin-login-sso.php` (bootstrap)
- `includes/class-admin-login-sso.php` (orchestrator, sanitization)
- `includes/class-admin-login-sso-auth.php` (OAuth flow)
- `includes/class-admin-login-sso-user.php` (user provisioning, encryption)
- `admin/class-admin-login-sso-admin.php` (settings UI, secret-save AJAX)
- `assets/js/secret-save.js` (client-side WAF-safe save)

Severity classes: **CRITICAL / HIGH / MEDIUM / LOW / INFO**. CRITICAL and HIGH are scheduled for inline fix on this branch. MEDIUM and below are documented as 1.2.2+ follow-ups unless the fix is trivial.

---

## Finding 1: Access token is never persisted — token storage and logout revocation are dead code

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-user.php:180-183` (write path), `includes/class-admin-login-sso-auth.php:503-524` (read/revoke path)
- **Description:** `Admin_Login_SSO_Auth::handle_oauth_callback()` calls `get_user_info($token_data['access_token'])` and passes the resulting profile (from `https://www.googleapis.com/oauth2/v3/userinfo`) into `process_user_login($user_info)`. The userinfo endpoint returns `email`, `sub`, `picture`, `given_name`, `family_name` — it does **not** return `access_token`. Inside `Admin_Login_SSO_User::update_user_meta()` the conditional `if (!empty($user_info['access_token']))` is therefore always false, so `encrypt_token()` is never invoked and `admin_login_sso_access_token` user meta is never written. As a consequence:
  1. `Admin_Login_SSO_Auth::handle_logout()` always finds the meta empty and never reaches the `GOOGLE_REVOKE_URL` call.
  2. The CHANGELOG / readme.txt claim "Properly manage OAuth tokens and revoke them on logout" is inaccurate.
- **Recommendation:** Inject the token into the user_info array before passing it to `process_user()` (e.g., `$user_info['access_token'] = $token_data['access_token']; $user_info['expires_in'] = $token_data['expires_in'] ?? null;`), or change the User class to accept token data as a second parameter. Either way, add a unit test or guarded log so silent regressions are visible.
- **Status:** [x] fixed in commit `b0e9e58`

---

## Finding 2: Encryption key falls back to a hardcoded constant when `AUTH_KEY` is undefined

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-user.php:234-238`
- **Description:** `get_encryption_key()` returns `hash('sha256', AUTH_KEY . 'admin_login_sso_token_encryption', true)` — but the ternary `defined('AUTH_KEY') ? AUTH_KEY : 'admin-login-sso-default-key'` means a misconfigured install (or a future code path that runs before `wp-config.php` defines salts) derives the key from a *publicly known* literal in this source file. Anyone with read access to the file would be able to decrypt every stored token from a snapshot of `wp_usermeta`. The cost of getting it right is a one-line refusal.
- **Recommendation:** Throw/return early if `AUTH_KEY` is not defined or is the WordPress placeholder `'put your unique phrase here'`. Have `encrypt_token` return an empty string in that case and log a `WP_DEBUG_LOG` error so the missing-salt condition is loud.
- **Status:** [x] fixed in commit `2e0fa3d`

---

## Finding 3: `encrypt_token` silently falls back to plain base64 when OpenSSL is unavailable

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-user.php:198-204`, mirror at `:220-222`
- **Description:** When `openssl_encrypt` is missing the function returns `base64_encode($token)`, which is **not** encryption — the value is trivially reversible by anyone reading the database. The matching `decrypt_token` path further compounds this: when `openssl_decrypt` is missing it returns `$data` raw, which would include the leading 16-byte IV from previously-encrypted entries and yield garbage for legitimate reads, but cleartext for entries written in the fallback path.
- **Recommendation:** Refuse to store tokens when OpenSSL is unavailable. PHP 8.0+ ships OpenSSL on every distribution that targets WordPress 6.4, so this fallback is defending against a configuration that effectively does not exist; treating it as an error is correct.
- **Status:** [x] fixed in commit `2e0fa3d`

---

## Finding 4: Status banner / config gates read `wp_options` directly, bypassing env/constant overrides

- **Severity:** MEDIUM
- **File:** `admin/class-admin-login-sso-admin.php:434, 457, 535, 666`, also `includes/class-admin-login-sso.php:249, 252`
- **Description:** `Admin_Login_SSO_Auth::get_client_secret()` prefers `getenv('ADMIN_LOGIN_SSO_CLIENT_SECRET')` and the `ADMIN_LOGIN_SSO_CLIENT_SECRET` PHP constant over the option, but five other call sites read `get_option('admin_login_sso_client_secret')` directly. Effect when the secret is set via env/constant only:
  - Status banner says "missing Client Secret".
  - Quick setup card never enables the **Test Google sign-in** button.
  - `render_secret_section()` shows the empty form (encouraging the user to overwrite the env value with a DB value).
  - `sanitize_checkbox()` refuses to enable SSO with "Cannot enable SSO: Please configure Google Client ID and Client Secret first."
- **Recommendation:** Replace these `get_option()` calls with `Admin_Login_SSO_Auth::get_client_secret()`. For the `render_secret_section` case, also surface a "Secret is set via environment variable / constant" badge instead of the input form.
- **Status:** [x] fixed in commit `3aae0c2`

---

## Finding 5: `Admin_Login_SSO::sanitize_client_secret()` is dead code

- **Severity:** LOW
- **File:** `includes/class-admin-login-sso.php:310-329`; comment at `:92-97` claims the AJAX handler invokes it.
- **Description:** `ajax_save_secret()` in the admin class inlines its own sanitize+length-check logic and never calls `sanitize_client_secret()`. The orchestrator method is unreachable, and the in-source comment promises a contract that does not exist.
- **Recommendation:** Delete `sanitize_client_secret()` (and the misleading comment) or have `ajax_save_secret()` delegate to it. Keep one path.
- **Status:** [ ] open — recommend deletion in 1.2.2; not blocking.

---

## Finding 6: `FILTER_VALIDATE_DOMAIN` is invoked without `FILTER_FLAG_HOSTNAME`

- **Severity:** MEDIUM
- **File:** `includes/class-admin-login-sso.php:204`
- **Description:** `filter_var($domain, FILTER_VALIDATE_DOMAIN)` without flags only checks that the string is a possible domain-as-a-DNS-name (length 1-253, no embedded whitespace). It accepts e.g. `--foo`, `_.com`, single labels, and empty subparts. Combined with the OR in the conditional, anything that fails the wildcard regex but is loosely "a string with a dot" will sneak into the allowed-domains list.
- **Recommendation:** Pass `FILTER_FLAG_HOSTNAME` (RFC 952 hostname rules) and also tighten the wildcard regex to forbid `_` (use `[a-z0-9-]` instead of `\w`).
- **Status:** [x] fixed in commit `9be0815`

---

## Finding 7: Translator-supplied strings echoed without escaping in activation/notice paths

- **Severity:** MEDIUM
- **File:** `admin-login-sso.php:90, 95-97, 114-116`; `admin/class-admin-login-sso-admin.php:635, 638, 641, 645, 648, 652`
- **Description:** `__()` returns the translated string un-escaped. Several places echo it directly inside HTML attributes or inline HTML (`'<a href="…">' . __('Settings', …) . '</a>'`, `_e('Admin Login SSO has been activated!', …)`). The practical risk is bounded — only admins see these strings and only an authorized translator could inject HTML — but the consistent convention used elsewhere in the codebase is `esc_html__`/`esc_html_e`, and these are deviations from that standard.
- **Recommendation:** Replace `__` → `esc_html__` and `_e` → `esc_html_e` for these specific output sites. Leave `__` where the return value is still being passed to `printf`/`wp_kses` etc.
- **Status:** [x] fixed in commit `5d2bf2e`

---

## Finding 8: Domain validation logs full email + raw options to `error_log`

- **Severity:** LOW (privacy / log hygiene)
- **File:** `includes/class-admin-login-sso-auth.php:445-447, 458, 462, 470, 477, 484`
- **Description:** `Admin_Login_SSO_Auth::validate_email_domain()` writes user emails, the raw `admin_login_sso_allowed_domains` option, and per-iteration tracing into the PHP error log whenever `WP_DEBUG_LOG` is enabled. This is fine for the lifetime of one debugging session but pollutes log retention with PII and produces noisy lines on every login. The method is named `log_error` but is being used here for trace info.
- **Recommendation:** Gate the per-iteration traces behind a stricter constant (e.g., `defined('ADMIN_LOGIN_SSO_VERBOSE_LOG') && ADMIN_LOGIN_SSO_VERBOSE_LOG`) or remove them. Keep only the terminal "validation passed/failed for *domain*" line (without the full email).
- **Status:** [ ] open — recommend trim in 1.2.2.

---

## Finding 9: `restrict_admin_access` exempts entire pages (plugins.php, options-general.php) regardless of SSO state

- **Severity:** MEDIUM (defense-in-depth)
- **File:** `includes/class-admin-login-sso-auth.php:559-570`
- **Description:** When SSO is enabled, the restriction is bypassed for any request whose `SCRIPT_NAME` contains `plugins.php` or `options-general.php`. The intent ("don't lock admins out of recovery surfaces") is reasonable but the consequence is that a non-Google-authenticated user who still holds a valid cookie can browse the plugins list and *all* options-general subpages — including settings pages registered by other plugins. The bypass is page-level, not capability-level.
- **Recommendation:** Either (a) restrict the exemption to the plugin's own settings page (`page=admin-login-sso`) which is already separately exempted, or (b) keep the exemption but require a recent (e.g., 5-minute) `is_user_google_authenticated()` window before granting cross-page admin access. The existing super-admin grace path (`is_super_admin` + missing-config) already covers the lockout-during-initial-setup case.
- **Status:** [ ] open — recommend a follow-up RFC; the change has wider UX implications than this branch should absorb.

---

## Finding 10: `is_user_google_authenticated` flag is sticky and never cleared on logout

- **Severity:** MEDIUM
- **File:** `includes/class-admin-login-sso-auth.php:707`, set at `includes/class-admin-login-sso-user.php:177`, never cleared in `handle_logout` (`:503-524`)
- **Description:** The `admin_login_sso_authenticated` user meta is set to `'1'` on first Google login and stays `'1'` forever. `restrict_admin_access` uses it as the gate. Result: a user who once authenticated via Google and then logs back in via the classic password form is still treated as "Google authenticated" and passes the gate. This defeats the strict-SSO intent for any account that has previously used Google sign-in.
- **Recommendation:** Either (a) delete the meta in `handle_logout()`, (b) replace the boolean meta with a short-TTL transient keyed by user ID + session token, or (c) bind the flag to the session token via `WP_Session_Tokens` so a fresh password login starts unauthenticated.
- **Status:** [ ] open — recommend follow-up. Coupled with Finding 1; both warrant a focused token/session refactor in 1.2.2.

---

## Finding 11: Domain validation log message announces "Validating email" before validating

- **Severity:** INFO
- **File:** `includes/class-admin-login-sso-auth.php:445`
- **Description:** Method is named `log_error` but is used for both errors and trace. Caller intent is unclear, and `error_log` lines all share the same prefix making grep harder. Cosmetic.
- **Recommendation:** Add a `log_debug()` companion and route the trace lines through it. Pair with Finding 8.
- **Status:** [ ] open — trivial follow-up.

---

## Finding 12: `is_admin_login()` is a misnomer when SSO is enabled

- **Severity:** INFO
- **File:** `includes/class-admin-login-sso-auth.php:762-778`
- **Description:** The method short-circuits to `true` whenever `is_enabled()` is true, ignoring whether the request actually originated from a wp-admin redirect. The Google button is therefore injected into every login form, including front-end login forms exposed by themes/plugins. Intentional per the plugin's positioning, but the name is misleading.
- **Recommendation:** Rename to `should_show_google_login()` or document the actual semantics in a docblock. No code change to logic.
- **Status:** [ ] open — cosmetic.

---

## Finding 13: Auto-create users are unconditionally assigned `administrator`

- **Severity:** MEDIUM (by-design but high-impact)
- **File:** `includes/class-admin-login-sso-user.php:100`
- **Description:** When auto-create is enabled, every Google account on an allowed domain is created with the `administrator` role. The UI does disclose this ("Auto-create users as **Administrator**"), so it is not hidden — but the readme.txt 1.1.0 changelog entry ("Allow any user with valid email domain to login") and the FAQ entry ("they will see an error message indicating they need to contact the administrator") taken together imply granular control that doesn't exist. A `corp.example.com` directory of 500 employees + `auto_create_users = '1'` produces 500 admins.
- **Recommendation:** Add a `default_role` option (default `subscriber`, opt-in to `administrator`). At minimum, change the UI label from "Auto-create admin users" to "Auto-create users" and add a role picker.
- **Status:** [ ] open — UX/scope change, recommend a separate 1.3 feature ticket.

---

## Finding 14: Rate-limit transient resets its window on every below-threshold attempt

- **Severity:** LOW
- **File:** `includes/class-admin-login-sso-auth.php:818-831`
- **Description:** Each `set_transient(..., $attempts + 1, RATE_LIMIT_WINDOW)` overwrites the expiration timestamp, so the 15-minute window slides forward on every legitimate attempt. An attacker pacing requests slightly faster than `RATE_LIMIT_WINDOW / RATE_LIMIT_MAX_ATTEMPTS` keeps the counter under the cap and can sustain attempts indefinitely. Once the cap is reached, the lockout itself does *not* reset (the early `return true` skips the `set_transient`), which is the saving grace.
- **Recommendation:** On first hit (no existing transient), use `set_transient` with the full window; on subsequent hits, use `update_option`-style increment without renewing the TTL. Or pair the counter with a separate "first attempt timestamp" transient that determines whether to reset.
- **Status:** [ ] open — recommend follow-up.

---

## Finding 15: Domain wildcard regex allows leading-hyphen subdomains

- **Severity:** LOW
- **File:** `includes/class-admin-login-sso.php:204`
- **Description:** `'/^(\*\.)?([\w-]+\.)+[\w-]{2,}$/'` accepts `-bad.com` and `foo.-bad`. Hostnames may not start or end with a hyphen per RFC 952. Combined with Finding 6, the regex should be `'/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i'` or similar.
- **Recommendation:** Fold into Finding 6's fix.
- **Status:** [x] fixed in commit `9be0815` (folded into Finding 6's fix)

---

## Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| 1 | HIGH | Access token never persisted | fixed `b0e9e58` |
| 2 | HIGH | Encryption key fallback constant | fixed `2e0fa3d` |
| 3 | HIGH | base64 fallback for `encrypt_token` | fixed `2e0fa3d` |
| 4 | MEDIUM | Status gates ignore env/constant secret | fixed `3aae0c2` |
| 5 | LOW | Dead `sanitize_client_secret()` | open |
| 6 | MEDIUM | `FILTER_VALIDATE_DOMAIN` missing flag | fixed `9be0815` |
| 7 | MEDIUM | Unescaped translator strings | fixed `5d2bf2e` |
| 8 | LOW | Verbose PII logging | open |
| 9 | MEDIUM | Page-level restriction bypass | open |
| 10 | MEDIUM | Sticky `authenticated` meta after logout | open |
| 11 | INFO | `log_error` mixed with trace | open |
| 12 | INFO | `is_admin_login` misnamed | open |
| 13 | MEDIUM | Auto-create grants `administrator` | open |
| 14 | LOW | Rate-limit sliding window | open |
| 15 | LOW | Wildcard regex too permissive | fixed `9be0815` |
