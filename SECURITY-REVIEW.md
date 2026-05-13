# Security Review — admin-login-sso 1.2.1

Reviewer: Claude (Opus 4.7)
Branch: `chore/cleanup-and-review`
Base commit: `79bd846`
Date: 2026-05-13

## Scope

OAuth-based replacement for wp-admin login. Threat model assumes:

- Anonymous internet attacker can reach `wp-login.php` and the OAuth callback.
- Authenticated low-privilege WP user (subscriber/editor) may exist on the same site.
- The site may sit behind a CDN/WAF/reverse proxy (the 1.1.0 fix for `redirect_uri_mismatch` implies this).
- An admin password might be compromised independently of Google credentials.

Severity classes: **CRITICAL / HIGH / MEDIUM / LOW / INFO**. Cross-references to `CODE-REVIEW.md` are by finding number.

---

## Finding S1: Encryption key derives from a hardcoded fallback constant

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-user.php:234-238`
- **Threat:** Database snapshot disclosure → cleartext OAuth tokens.
- **Description:** `get_encryption_key()` derives the AES-256-CBC key from `AUTH_KEY`, but when that constant is undefined it falls back to the literal string `'admin-login-sso-default-key'` from this very source file. Any attacker who exfiltrates `wp_usermeta` and reads the public plugin source can decrypt all tokens stored under that key.
- **Recommendation:** Refuse to encrypt when `AUTH_KEY` is undefined or equals the WP default placeholder. See `CODE-REVIEW.md` Finding 2.
- **Status:** [x] fixed in commit `2e0fa3d`

---

## Finding S2: `encrypt_token` falls back to plain `base64_encode` when OpenSSL is missing

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-user.php:198-204`
- **Threat:** Trivial recovery of stored OAuth tokens on installs missing the openssl PHP extension.
- **Description:** `if (!function_exists('openssl_encrypt')) { return base64_encode($token); }` silently degrades to no-op "encryption". Any future reviewer auditing `wp_usermeta` would see plausibly-encrypted blobs but they'd be readable with `base64 -d`. See `CODE-REVIEW.md` Finding 3 for context.
- **Recommendation:** Return empty + log a `WP_DEBUG_LOG` error; do not store the token at all in this environment.
- **Status:** [x] fixed in commit `2e0fa3d`

---

## Finding S3: Rate limiter is keyed on `REMOTE_ADDR`, ignoring proxy headers — bypassable behind CDN/WAF, and over-aggressive locally

- **Severity:** HIGH
- **File:** `includes/class-admin-login-sso-auth.php:838-844`, called from `:264, :820-831`
- **Threat:** (a) When the site is behind Cloudflare/AWS ALB/nginx-reverse-proxy, every request appears to originate from a small set of proxy IPs. After 10 callback attempts site-wide, *all* legitimate users are locked out for 15 minutes. (b) Conversely, an attacker who *can* control `X-Forwarded-For` (or who is far enough upstream of any proxy) can rotate the apparent IP and bypass the limit entirely — but `get_client_ip()` doesn't read those headers, so this specific bypass isn't currently possible. The functional bug (locked-out-by-proxy) is the primary concern.
- **Recommendation:** Introduce a `ADMIN_LOGIN_SSO_TRUSTED_PROXIES` constant or option (CIDR list). When the connecting IP matches a trusted proxy, derive the client IP from the right-most untrusted hop in `X-Forwarded-For`. Until that lands, document the limitation in `readme.txt` so site owners behind a CDN know to expect false positives.
- **Status:** [ ] open — needs a small design decision (constant vs option). Recommend documenting in 1.2.2 readme and shipping the implementation in 1.2.3.

---

## Finding S4: OAuth state validation is correct; one minor observation

- **Severity:** INFO (positive finding)
- **File:** `includes/class-admin-login-sso-auth.php:208-223, 277-287`
- **Observation:** The state token is:
  - 40 characters of `wp_generate_password(40, false)` (alphanumeric, sufficient entropy).
  - Stored as a transient with a 15-minute TTL (`STATE_EXPIRATION = 900`).
  - Looked up on callback via `get_transient('admin_login_sso_state_' . $state)`.
  - Deleted immediately on successful match (`delete_transient(...)` at `:287`), enforcing single-use.
  - Sanitized via `sanitize_text_field` (case-preserving), not `sanitize_key` — the 1.1.1 changelog fix is intact.
- **Recommendation:** None. Optionally namespace the transient with a hash of the user-agent + IP to bind it more tightly, but the current implementation matches OAuth 2.0 RFC 6749 §10.12 guidance.
- **Status:** No action.

---

## Finding S5: Client Secret save endpoint is correctly authenticated and authorized

- **Severity:** INFO (positive finding)
- **File:** `admin/class-admin-login-sso-admin.php:741-785`
- **Observation:** `ajax_save_secret()` checks:
  1. `current_user_can('manage_options')` — gates non-admins.
  2. `wp_verify_nonce($nonce, 'admin_login_sso_secret')` — CSRF mitigation.
  3. Payload received via POST body (JSON), not query string — not logged in standard webserver access logs.
  4. `update_option('admin_login_sso_client_secret', $clean)` — the option is registered with `autoload = 'no'` in `admin-login-sso.php:48-49`, so it doesn't leak via the autoloader.
- **Observation:** The base64 transport + neutral field name (`gauth_blob`) defeats WAF pattern-matching on `GOCSPX-` without weakening the security model (since the request is already authenticated and over HTTPS).
- **Recommendation:** None for security. (See `CODE-REVIEW.md` Finding 5 for a code-quality cleanup.)
- **Status:** No action.

---

## Finding S6: `wp_safe_redirect(admin_url())` after successful OAuth is hardcoded — no open-redirect surface

- **Severity:** INFO (positive finding)
- **File:** `includes/class-admin-login-sso-auth.php:330`
- **Observation:** The post-login redirect is the literal output of `admin_url()`, not a request-supplied `redirect_to` parameter. There is no open-redirect on the success path. The error path also uses `wp_safe_redirect(wp_login_url())` with `wp_login_url()` returning a same-origin URL.
- **Recommendation:** If a future change adds `redirect_to` support, route it through `wp_validate_redirect($redirect_to, admin_url())`.
- **Status:** No action.

---

## Finding S7: Auto-created users receive `administrator` role unconditionally

- **Severity:** HIGH (privilege escalation by configuration)
- **File:** `includes/class-admin-login-sso-user.php:100`
- **Threat:** A directory of *N* employees on an allowed domain becomes *N* WordPress administrators the first time each signs in. Any one of them can install plugins, edit code via the file editor, or rotate other users' roles. Combined with the corporate-SSO use case the plugin targets ("only users with company email"), this is the realistic end-state — the operator who configures `*.acme.com` is granting admin to every Acme employee.
- **Recommendation:** Add a `default_role` setting (default `subscriber`, opt-in to `administrator`). The current behavior is documented in the UI but the readme.txt FAQ and 1.1.0 changelog imply granularity that doesn't exist. See `CODE-REVIEW.md` Finding 13.
- **Status:** [ ] open — UX change; recommend 1.3 feature ticket. **At minimum**, the readme should be honest about the auto-create behavior. (See Finding S15 below.)

---

## Finding S8: `restrict_admin_access` exempts `plugins.php` and `options-general.php` from SSO enforcement

- **Severity:** MEDIUM (defense-in-depth bypass)
- **File:** `includes/class-admin-login-sso-auth.php:559-570`
- **Threat:** When SSO is enabled, a user whose WP password was compromised but whose Google account is not in scope can still load every settings page registered under `options-general.php` (most plugin settings) and the plugins list. They cannot reach the rest of wp-admin, but they can read database-stored options exposed by other plugins and they can deactivate the Admin Login SSO plugin from `plugins.php` if their cookie carries `activate_plugins` capability.
- **Recommendation:** Narrow the exemption. The plugin already separately exempts its own settings page via `?page=admin-login-sso` at lines 553-557. The broader `plugins.php` / `options-general.php` exemption can be removed once Finding 10 (sticky-auth-flag) is fixed, since a recently-authenticated Google session would naturally satisfy the gate.
- **Status:** [ ] open — coupled to Findings 9 and 10 of CODE-REVIEW; recommend a focused 1.2.3 patch.

---

## Finding S9: `admin_login_sso_authenticated` user meta is sticky across logouts

- **Severity:** MEDIUM
- **File:** `includes/class-admin-login-sso-auth.php:707` (read), `includes/class-admin-login-sso-user.php:177` (write), no clear path on logout
- **Threat:** A user who has previously completed at least one Google sign-in retains the boolean meta `'1'` forever. After logout, if they log back in via the classic password form (assuming `show_classic_login = '1'`), `restrict_admin_access` still treats them as Google-authenticated and lets them into wp-admin. This silently downgrades the SSO requirement for any returning user.
- **Recommendation:** Delete the meta in `handle_logout()`, or bind authentication to the WP session token via `WP_Session_Tokens` so a fresh login (any method) starts un-flagged. See `CODE-REVIEW.md` Finding 10.
- **Status:** [ ] open — recommend follow-up.

---

## Finding S10: Domain validation is correctly anchored against suffix-confusion, but the sanitizer regex is too permissive

- **Severity:** MEDIUM
- **File:** validation at `includes/class-admin-login-sso-auth.php:422-486` (good); sanitizer at `includes/class-admin-login-sso.php:204` (loose)
- **Observation (positive):** The runtime wildcard match is **correctly anchored**: `*.example.com` requires `$email_domain === $base_domain || str_ends_with($email_domain, '.' . $base_domain)` (line 476). `notexample.com` cannot satisfy this and is rejected. The exact-match branch is case-insensitive (`strtolower(trim($email))`).
- **Observation (negative):** The sanitizer that decides which domains may be added to the allowed list uses `'/^(\*\.)?([\w-]+\.)+[\w-]{2,}$/'` with `FILTER_VALIDATE_DOMAIN` as a fallback (no `FILTER_FLAG_HOSTNAME`). It accepts `_.com`, `--evil.com`, and arbitrary single-label strings via the loose `filter_var` fallback. An admin who pastes a typo'd or attacker-suggested value won't get a clear rejection.
- **IDN homoglyphs (positive):** Both endpoints lowercase the input. `is_email()` accepts only ASCII characters in the local-part/host. Punycode domains (`xn--…`) are treated as ordinary ASCII strings, so `xn--exmple-…` ≠ `example.com` — no homoglyph collapse occurs.
- **Recommendation:** Tighten the sanitizer regex and pass `FILTER_FLAG_HOSTNAME`. See `CODE-REVIEW.md` Findings 6 and 15.
- **Status:** [x] fixed in commit `9be0815`

---

## Finding S11: OAuth token exchange and userinfo fetch do not validate `id_token`

- **Severity:** LOW (defense-in-depth)
- **File:** `includes/class-admin-login-sso-auth.php:340-414`
- **Observation:** The plugin requests `scope=openid email profile` (line 217), so Google returns an `id_token` JWT alongside the access token. The plugin discards it and instead calls `https://www.googleapis.com/oauth2/v3/userinfo` over HTTPS with the bearer access token. This is a valid OAuth pattern but relies on TLS to authenticate Google as the source — there is no offline verification of issuer/audience/expiry on the id_token.
- **Recommendation:** Optionally parse and validate the id_token using Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`) and check `iss`, `aud`, `exp`, `email_verified`. This eliminates one network call and gives a cryptographic guarantee that the email belongs to the client_id. Not urgent — TLS already provides the trust path.
- **Status:** [ ] open — future hardening.

---

## Finding S12: Userinfo response does not require `email_verified === true`

- **Severity:** MEDIUM
- **File:** `includes/class-admin-login-sso-auth.php:307-320`
- **Threat:** Google's `userinfo` response includes `email_verified: bool`. For Workspace accounts on an org's domain this is always true, but for consumer `gmail.com` or third-party-Google-Sign-In where a user attaches a self-asserted recovery email, an unverified email could theoretically pass validation. The plugin currently accepts any email returned by Google without checking the verified flag.
- **Recommendation:** Add `if (empty($user_info['email_verified']) || !$user_info['email_verified']) { handle_error(...); return; }` after the userinfo fetch and before domain validation.
- **Status:** [x] fixed in commit `8c41f97`

---

## Finding S13: Verbose error_log writes user emails on every login

- **Severity:** LOW (privacy / data minimization)
- **File:** `includes/class-admin-login-sso-auth.php:439, 445`
- **Threat:** PII leakage into `debug.log` on shared hosting / shared log retention.
- **Recommendation:** See `CODE-REVIEW.md` Finding 8.
- **Status:** [ ] open — recommend follow-up.

---

## Finding S14: REST API restriction is path-prefix-only and misses custom namespaces

- **Severity:** LOW (defense-in-depth)
- **File:** `includes/class-admin-login-sso-auth.php:649`
- **Observation:** `restrict_rest_api()` checks `0 !== strpos($_SERVER['REQUEST_URI'], '/wp-json/wp/v2/')`. Custom REST namespaces (`/wp-json/myplugin/v1/...`) and the OG WP-JSON namespace (`/wp-json/wp/v3/...` if any future core change ships) are not gated. Any plugin that exposes a privileged custom endpoint and trusts capability checks remains accessible.
- **Recommendation:** Either widen the prefix check to `'/wp-json/'` (potentially over-broad for public read endpoints) or invert the policy: require Google-auth for any authenticated REST request from a user with edit-level caps, regardless of namespace.
- **Status:** [ ] open — design discussion; the current narrow scope is intentional.

---

## Finding S15: readme.txt overstates the security posture (changelog drift)

- **Severity:** LOW (documentation honesty)
- **File:** `readme.txt:1-101`
- **Description:** The 1.1.0 changelog claims:
  - "Encrypt access tokens stored in user meta (AES-256-CBC)" — true *if* the token actually reaches storage, which Finding 1 shows it doesn't.
  - "Add per-IP rate limiting on OAuth callback (10 attempts/15min)" — true, but Finding S3 shows the IP detection is incorrect behind proxies.
  - "Allow any user with valid email domain to login (removed admin-only restriction)" — true for the *gating* step, but auto-create still hard-codes `administrator` (Finding S7).
- **Recommendation:** Once Findings 1 and S3 are addressed, restate the security posture honestly in the 1.2.2 changelog. Until then, do not add new security-feature claims.
- **Status:** [x] fixed in commit `f0a4271` (Finding 1 fix delivers the documented behavior; readme.txt updated to match)

---

## Finding S16: Rate-limit window slides forward on every below-threshold attempt

- **Severity:** LOW
- **File:** `includes/class-admin-login-sso-auth.php:818-831`
- **Threat:** Slow, paced attacks can keep the counter from saturating. See `CODE-REVIEW.md` Finding 14.
- **Recommendation:** Use a separate "first attempt timestamp" companion transient to determine whether to renew the window.
- **Status:** [ ] open.

---

## Finding S17: Plugin row meta and activation notice use unescaped `__`/`_e`

- **Severity:** LOW
- **File:** `admin-login-sso.php:90, 95-97, 114-116`, `admin/class-admin-login-sso-admin.php:635, 638, 641, 645, 648, 652`
- **Threat:** Translator-controlled XSS in admin-only contexts. Practical risk is low (admin-only render path, translator trust model). See `CODE-REVIEW.md` Finding 7.
- **Status:** [x] fixed in commit `5d2bf2e`

---

## Summary

| ID  | Severity | Title                                                       | Status               |
|-----|----------|-------------------------------------------------------------|----------------------|
| S1  | HIGH     | Encryption-key fallback constant                            | fixed `2e0fa3d`      |
| S2  | HIGH     | base64 fallback for `encrypt_token`                         | fixed `2e0fa3d`      |
| S3  | HIGH     | Rate limiter ignores proxy headers (lockout behind CDN)     | open                 |
| S4  | INFO     | OAuth state CSRF — correct                                  | no action            |
| S5  | INFO     | Client Secret save endpoint — correct                       | no action            |
| S6  | INFO     | Post-login redirect — no open-redirect surface              | no action            |
| S7  | HIGH     | Auto-created users get `administrator`                      | open (1.3 feature)   |
| S8  | MEDIUM   | `plugins.php` / `options-general.php` exempt from SSO       | open                 |
| S9  | MEDIUM   | Sticky `authenticated` meta after logout                    | open                 |
| S10 | MEDIUM   | Sanitizer regex / `FILTER_VALIDATE_DOMAIN` flag             | fixed `9be0815`      |
| S11 | LOW      | id_token not validated offline                              | open                 |
| S12 | MEDIUM   | `email_verified` not enforced                               | fixed `8c41f97`      |
| S13 | LOW      | PII in `debug.log`                                          | open                 |
| S14 | LOW      | REST restriction only covers `/wp/v2/`                      | open                 |
| S15 | LOW      | readme.txt overstates posture                               | fixed `f0a4271`      |
| S16 | LOW      | Rate-limit sliding window                                   | open                 |
| S17 | LOW      | Unescaped `__`/`_e` in admin notices                        | fixed `5d2bf2e`      |
