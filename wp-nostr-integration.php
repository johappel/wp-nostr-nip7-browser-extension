<?php
/**
 * Plugin Name: Nostr Integration
 * Description: NIP-07 Extension Integration für Nostr Login
 * Version: 0.0.1
 * Author: Joachim Happel
 * License: GPL v2 or later
 */

// Verhindere direkten Zugriff
if (!defined('ABSPATH')) {
    exit;
}

// Hooks registrieren
add_action('wp_enqueue_scripts', 'nostr_enqueue_scripts');
add_action('rest_api_init', 'nostr_register_endpoints');
add_action('admin_menu', 'nostr_admin_menu');
add_action('admin_init', 'nostr_admin_init');
add_action('template_redirect', 'nostr_maybe_render_auth_broker_page');

function nostr_get_or_create_domain_secret() {
    $secret = get_option('nostr_domain_secret');
    if (!$secret) {
        $secret = wp_generate_password(64, true, true);
        update_option('nostr_domain_secret', $secret);
    }
    return $secret;
}

function nostr_normalize_domain($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    // Falls eine URL eingetragen wurde, Host extrahieren.
    if (preg_match('/^https?:\/\//i', $value)) {
        $host = parse_url($value, PHP_URL_HOST);
        return $host ? strtolower($host) : '';
    }

    // Host-only Eingaben (ggf. mit Pfad/Port) normalisieren.
    $value = preg_replace('/^\/\//', '', $value);
    $value = preg_replace('/\/.*$/', '', $value);
    $value = preg_replace('/:\d+$/', '', $value);
    return strtolower(trim($value));
}

function nostr_get_default_primary_domain() {
    $home = wp_parse_url(home_url());
    $scheme = isset($home['scheme']) ? $home['scheme'] : 'https';
    $host = isset($home['host']) ? $home['host'] : parse_url(home_url(), PHP_URL_HOST);
    if (!$host) {
        return '';
    }
    $port = isset($home['port']) ? ':' . $home['port'] : '';
    return $scheme . '://' . $host . $port;
}

// ============================================================
// Frontend Scripts
// ============================================================

function nostr_enqueue_scripts() {
    // Nur für eingeloggte User laden
    if (!is_user_logged_in()) {
        return;
    }

    $script_path = plugin_dir_path(__FILE__) . 'nostr-integration.js';
    $style_path = plugin_dir_path(__FILE__) . 'nostr-integration.css';
    $script_version = file_exists($script_path) ? (string) filemtime($script_path) : '1.0.0';
    $style_version = file_exists($style_path) ? (string) filemtime($style_path) : '1.0.0';

    wp_enqueue_script(
        'nostr-integration',
        plugins_url('nostr-integration.js', __FILE__),
        [],
        $script_version,
        true
    );
    
    $current_user = wp_get_current_user();
    $current_user_id = get_current_user_id();
    $current_pubkey = strtolower((string) get_user_meta($current_user_id, 'nostr_pubkey', true));
    $current_avatar = get_avatar_url($current_user_id, ['size' => 96]);
    $profile_relay_url = trim((string) get_option('nostr_profile_relay_url', ''));
    $publish_kind0 = get_option('nostr_publish_kind0_on_register', 1);
    $profile_nip05 = trim((string) get_option('nostr_profile_nip05', ''));

    wp_localize_script('nostr-integration', 'nostrConfig', [
        'restUrl' => rest_url('nostr/v1/'),
        'nonce' => wp_create_nonce('wp_rest'),
        'siteDomain' => parse_url(home_url(), PHP_URL_HOST),
        'isLoggedIn' => is_user_logged_in(),
        'wpUserId' => $current_user_id,
        'wpDisplayName' => $current_user ? $current_user->display_name : '',
        'wpAvatarUrl' => $current_avatar ? $current_avatar : '',
        'wpPubkey' => $current_pubkey,
        'wpUserLogin' => $current_user ? $current_user->user_login : '',
        'primaryDomain' => get_option('nostr_primary_domain', nostr_get_default_primary_domain()),
        'domainSecret' => nostr_get_or_create_domain_secret(),
        'profileRelayUrl' => $profile_relay_url,
        'publishKind0OnRegister' => !empty($publish_kind0),
        'profileNip05' => $profile_nip05,
        'authBrokerEnabled' => nostr_is_auth_broker_enabled(),
        'authBrokerUrl' => nostr_is_auth_broker_enabled() ? nostr_get_auth_broker_url() : '',
        'authBrokerOrigin' => nostr_get_auth_broker_origin(),
        'authBrokerRpId' => nostr_get_auth_broker_rp_id(),
        // extensionStoreUrl bleibt fuer Rueckwaertskompatibilitaet erhalten.
        'extensionStoreUrl' => get_option('nostr_extension_store_url', 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]'),
        'extensionStoreUrlChrome' => get_option(
            'nostr_extension_store_url_chrome',
            get_option('nostr_extension_store_url', 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]')
        ),
        'extensionStoreUrlFirefox' => get_option(
            'nostr_extension_store_url_firefox',
            'https://addons.mozilla.org/firefox/addon/[ADDON_SLUG]'
        )
    ]);
    
    // CSS für Modal
    wp_enqueue_style(
        'nostr-integration-css',
        plugins_url('nostr-integration.css', __FILE__),
        [],
        $style_version
    );
}

// ============================================================
// REST API Endpoints
// ============================================================

function nostr_register_endpoints() {
    // Registrierung eines neuen Npub
    register_rest_route('nostr/v1', '/register', [
        'methods' => 'POST',
        'callback' => 'nostr_handle_register',
        'permission_callback' => 'is_user_logged_in'
    ]);
    register_rest_route('nostr/v1', '/register/replace', [
        'methods' => 'POST',
        'callback' => 'nostr_handle_replace_register',
        'permission_callback' => 'is_user_logged_in'
    ]);
    
    // Aktueller User Status
    register_rest_route('nostr/v1', '/user', [
        'methods' => 'GET',
        'callback' => 'nostr_get_user',
        'permission_callback' => 'is_user_logged_in'
    ]);
    
    // Domain-Whitelist (öffentlich für Extension)
    register_rest_route('nostr/v1', '/domains', [
        'methods' => 'GET',
        'callback' => 'nostr_get_domains',
        'permission_callback' => '__return_true'
    ]);

    register_rest_route('nostr/v1', '/viewer', [
        'methods' => 'GET',
        'callback' => 'nostr_get_viewer',
        'permission_callback' => '__return_true'
    ]);

    // Encrypted key backup endpoints (user-scoped)
    register_rest_route('nostr/v1', '/backup/upload', [
        'methods' => 'POST',
        'callback' => 'nostr_backup_upload',
        'permission_callback' => 'is_user_logged_in'
    ]);
    register_rest_route('nostr/v1', '/backup/metadata', [
        'methods' => 'POST',
        'callback' => 'nostr_backup_metadata',
        'permission_callback' => 'is_user_logged_in'
    ]);
    register_rest_route('nostr/v1', '/backup/download', [
        'methods' => 'POST',
        'callback' => 'nostr_backup_download',
        'permission_callback' => 'is_user_logged_in'
    ]);
    register_rest_route('nostr/v1', '/backup/delete', [
        'methods' => 'POST',
        'callback' => 'nostr_backup_delete',
        'permission_callback' => 'is_user_logged_in'
    ]);

    // Primary-Domain Auth Broker (WebAuthn Assertion)
    register_rest_route('nostr/v1', '/webauthn/assert/challenge', [
        'methods' => 'POST',
        'callback' => 'nostr_webauthn_assert_challenge',
        'permission_callback' => 'is_user_logged_in'
    ]);
    register_rest_route('nostr/v1', '/webauthn/assert/verify', [
        'methods' => 'POST',
        'callback' => 'nostr_webauthn_assert_verify',
        'permission_callback' => 'is_user_logged_in'
    ]);
}

function nostr_handle_register(WP_REST_Request $request) {
    $pubkey = strtolower(sanitize_text_field($request->get_param('pubkey')));
    $replace = nostr_sanitize_checkbox($request->get_param('replace')) === 1;
    $expected_current = strtolower(sanitize_text_field($request->get_param('expectedCurrentPubkey')));
    $user_id = get_current_user_id();
    
    // Validiere hex Pubkey Format (64 hex chars)
    if (!preg_match('/^[a-f0-9]{64}$/', $pubkey)) {
        return new WP_Error(
            'invalid_pubkey', 
            'Ungueltiges Pubkey Format', 
            ['status' => 400]
        );
    }

    // Bestehenden Key dieses Users nicht stillschweigend ueberschreiben.
    $current_pubkey = strtolower((string) get_user_meta($user_id, 'nostr_pubkey', true));
    if ($current_pubkey !== '') {
        if ($current_pubkey === $pubkey) {
            return [
                'success' => true,
                'pubkey' => $current_pubkey,
                'registered' => get_user_meta($user_id, 'nostr_registered', true),
                'unchanged' => true
            ];
        }

        if ($replace) {
            if ($expected_current !== '' && $expected_current !== $current_pubkey) {
                return new WP_Error(
                    'pubkey_changed_concurrently',
                    'Der aktuell registrierte Pubkey hat sich geaendert. Bitte Seite neu laden und erneut pruefen.',
                    ['status' => 409, 'currentPubkey' => $current_pubkey]
                );
            }

            $existing_user = get_users([
                'meta_key' => 'nostr_pubkey',
                'meta_value' => $pubkey,
                'number' => 1,
                'exclude' => [$user_id]
            ]);
            if (!empty($existing_user)) {
                return new WP_Error(
                    'pubkey_in_use',
                    'Dieser Pubkey ist bereits einem anderen Account zugeordnet',
                    ['status' => 409]
                );
            }

            update_user_meta($user_id, 'nostr_pubkey', $pubkey);
            update_user_meta($user_id, 'nostr_registered', current_time('mysql'));
            return [
                'success' => true,
                'pubkey' => $pubkey,
                'previousPubkey' => $current_pubkey,
                'registered' => current_time('mysql'),
                'replaced' => true
            ];
        }

        return new WP_Error(
            'pubkey_already_registered',
            'Fuer diesen Account ist bereits ein anderer Nostr-Pubkey registriert. Bitte zuerst bewusst wechseln (Key-Rotation), statt zu ueberschreiben.',
            ['status' => 409, 'currentPubkey' => $current_pubkey]
        );
    }
    
    // Pruefe ob dieser Pubkey bereits einem anderen User zugeordnet ist
    $existing_user = get_users([
        'meta_key' => 'nostr_pubkey',
        'meta_value' => $pubkey,
        'number' => 1,
        'exclude' => [$user_id]
    ]);
    
    if (!empty($existing_user)) {
        return new WP_Error(
            'pubkey_in_use',
            'Dieser Pubkey ist bereits einem anderen Account zugeordnet',
            ['status' => 409]
        );
    }
    
    // Speichere hex-pubkey (Server koennte optional npub ableiten)
    update_user_meta($user_id, 'nostr_pubkey', strtolower($pubkey));
    update_user_meta($user_id, 'nostr_registered', current_time('mysql'));
    
    return [
        'success' => true, 
        'pubkey' => $pubkey,
        'registered' => current_time('mysql')
    ];
}

function nostr_get_user() {
    $user_id = get_current_user_id();
    return [
        'pubkey' => get_user_meta($user_id, 'nostr_pubkey', true),
        'registered' => get_user_meta($user_id, 'nostr_registered', true),
        'userId' => $user_id
    ];
}

function nostr_handle_replace_register(WP_REST_Request $request) {
    $pubkey = strtolower(sanitize_text_field($request->get_param('pubkey')));
    $expected_current = strtolower(sanitize_text_field($request->get_param('expectedCurrentPubkey')));
    $user_id = get_current_user_id();

    if (!preg_match('/^[a-f0-9]{64}$/', $pubkey)) {
        return new WP_Error(
            'invalid_pubkey',
            'Ungueltiges Pubkey Format',
            ['status' => 400]
        );
    }

    $current_pubkey = strtolower((string) get_user_meta($user_id, 'nostr_pubkey', true));
    if ($expected_current !== '' && $current_pubkey !== '' && $expected_current !== $current_pubkey) {
        return new WP_Error(
            'pubkey_changed_concurrently',
            'Der aktuell registrierte Pubkey hat sich geaendert. Bitte Seite neu laden und erneut pruefen.',
            ['status' => 409, 'currentPubkey' => $current_pubkey]
        );
    }

    $existing_user = get_users([
        'meta_key' => 'nostr_pubkey',
        'meta_value' => $pubkey,
        'number' => 1,
        'exclude' => [$user_id]
    ]);
    if (!empty($existing_user)) {
        return new WP_Error(
            'pubkey_in_use',
            'Dieser Pubkey ist bereits einem anderen Account zugeordnet',
            ['status' => 409]
        );
    }

    update_user_meta($user_id, 'nostr_pubkey', $pubkey);
    update_user_meta($user_id, 'nostr_registered', current_time('mysql'));

    return [
        'success' => true,
        'pubkey' => $pubkey,
        'previousPubkey' => $current_pubkey !== '' ? $current_pubkey : null,
        'registered' => current_time('mysql'),
        'replaced' => true
    ];
}

function nostr_get_viewer() {
    if (!is_user_logged_in()) {
        return [
            'isLoggedIn' => false,
            'userId' => null,
            'displayName' => null,
            'avatarUrl' => null,
            'pubkey' => null,
            'authBrokerEnabled' => nostr_is_auth_broker_enabled(),
            'authBrokerUrl' => nostr_is_auth_broker_enabled() ? nostr_get_auth_broker_url() : '',
            'authBrokerOrigin' => nostr_get_auth_broker_origin(),
            'authBrokerRpId' => nostr_get_auth_broker_rp_id()
        ];
    }

    $user_id = get_current_user_id();
    $user = wp_get_current_user();
    $pubkey = strtolower((string) get_user_meta($user_id, 'nostr_pubkey', true));
    $avatar = get_avatar_url($user_id, ['size' => 96]);

    return [
        'isLoggedIn' => true,
        'userId' => $user_id,
        'displayName' => $user ? $user->display_name : '',
        'avatarUrl' => $avatar ? $avatar : '',
        'pubkey' => $pubkey !== '' ? $pubkey : null,
        'authBrokerEnabled' => nostr_is_auth_broker_enabled(),
        'authBrokerUrl' => nostr_is_auth_broker_enabled() ? nostr_get_auth_broker_url() : '',
        'authBrokerOrigin' => nostr_get_auth_broker_origin(),
        'authBrokerRpId' => nostr_get_auth_broker_rp_id()
    ];
}

function nostr_get_domains() {
    $domains = get_option('nostr_allowed_domains', [
        parse_url(home_url(), PHP_URL_HOST)
    ]);
    
    // Stelle sicher, dass domains ein Array ist
    if (!is_array($domains)) {
        $domains = preg_split('/\r\n|\r|\n/', (string) $domains);
        $domains = array_filter(array_map('trim', $domains));
    }
    $domains = array_values(array_unique($domains));
    if (empty($domains)) {
        $domains = [parse_url(home_url(), PHP_URL_HOST)];
    }
    
    $payload = json_encode($domains);
    $secret  = nostr_get_or_create_domain_secret();
    
    $timestamp = time();
    $signature = hash_hmac('sha256', $payload . '|' . $timestamp, $secret);
    
    return [
        'domains'   => array_values($domains),
        'updated'   => $timestamp,
        'signature' => $signature
    ];
}

function nostr_is_auth_broker_enabled() {
    return (int) get_option('nostr_auth_broker_enabled', 0) === 1;
}

function nostr_is_auth_broker_dev_mode_enabled() {
    return (int) get_option('nostr_auth_broker_dev_mode_unverified', 0) === 1;
}

function nostr_get_auth_broker_origin() {
    $configured = trim((string) get_option('nostr_auth_broker_origin', ''));
    if ($configured !== '') {
        return untrailingslashit($configured);
    }
    return untrailingslashit(home_url());
}

function nostr_get_auth_broker_url() {
    $origin = nostr_get_auth_broker_origin();
    if ($origin === '') {
        return '';
    }
    return untrailingslashit($origin) . '/?nostr_auth_broker=1';
}

function nostr_get_auth_broker_rp_id() {
    $configured = trim((string) get_option('nostr_auth_broker_rp_id', ''));
    if ($configured !== '') {
        return strtolower($configured);
    }
    $host = parse_url(nostr_get_auth_broker_origin(), PHP_URL_HOST);
    return $host ? strtolower($host) : strtolower((string) parse_url(home_url(), PHP_URL_HOST));
}

function nostr_base64url_encode($binary) {
    return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
}

function nostr_base64url_decode($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return null;
    }
    $normalized = strtr($value, '-_', '+/');
    $padding = strlen($normalized) % 4;
    if ($padding > 0) {
        $normalized .= str_repeat('=', 4 - $padding);
    }
    $decoded = base64_decode($normalized, true);
    return $decoded === false ? null : $decoded;
}

function nostr_webauthn_challenge_transient_key($user_id, $challenge_id) {
    return 'nostr_webauthn_ch_' . md5($user_id . '|' . $challenge_id);
}

function nostr_webauthn_assert_challenge(WP_REST_Request $request) {
    if (!nostr_is_auth_broker_enabled()) {
        return new WP_Error('auth_broker_disabled', 'Primary-domain auth broker is disabled', ['status' => 503]);
    }

    $user_id = get_current_user_id();
    $intent = sanitize_text_field((string) $request->get_param('intent'));
    if ($intent === '') {
        $intent = 'generic';
    }

    $challenge_bytes = random_bytes(32);
    $challenge = nostr_base64url_encode($challenge_bytes);
    $challenge_id = bin2hex(random_bytes(16));
    $origin = nostr_get_auth_broker_origin();
    $rp_id = nostr_get_auth_broker_rp_id();

    $record = [
        'userId' => $user_id,
        'intent' => $intent,
        'challenge' => $challenge,
        'origin' => $origin,
        'rpId' => $rp_id,
        'createdAt' => time()
    ];
    set_transient(
        nostr_webauthn_challenge_transient_key($user_id, $challenge_id),
        $record,
        3 * MINUTE_IN_SECONDS
    );

    return [
        'challengeId' => $challenge_id,
        'challengeOptions' => [
            'challenge' => $challenge,
            'rpId' => $rp_id,
            'timeout' => 120000,
            'userVerification' => 'preferred'
        ],
        'origin' => $origin,
        'rpId' => $rp_id,
        'intent' => $intent
    ];
}

function nostr_auth_broker_sign_result_token($claims) {
    $payload = wp_json_encode($claims);
    $payload_b64 = nostr_base64url_encode($payload);
    $signature = hash_hmac('sha256', $payload_b64, wp_salt('auth'));
    return $payload_b64 . '.' . $signature;
}

function nostr_webauthn_assert_verify(WP_REST_Request $request) {
    if (!nostr_is_auth_broker_enabled()) {
        return new WP_Error('auth_broker_disabled', 'Primary-domain auth broker is disabled', ['status' => 503]);
    }

    $user_id = get_current_user_id();
    $challenge_id = sanitize_text_field((string) $request->get_param('challengeId'));
    if ($challenge_id === '') {
        return new WP_Error('invalid_challenge_id', 'challengeId is required', ['status' => 400]);
    }

    $transient_key = nostr_webauthn_challenge_transient_key($user_id, $challenge_id);
    $record = get_transient($transient_key);
    delete_transient($transient_key);
    if (!is_array($record)) {
        return new WP_Error('challenge_not_found', 'Challenge expired or invalid', ['status' => 400]);
    }

    $client_data_json_b64 = (string) $request->get_param('clientDataJSON');
    $credential_id = sanitize_text_field((string) $request->get_param('credentialId'));

    $client_data_raw = nostr_base64url_decode($client_data_json_b64);
    if ($client_data_raw === null) {
        return new WP_Error('invalid_client_data', 'clientDataJSON is invalid', ['status' => 400]);
    }
    $client_data = json_decode($client_data_raw, true);
    if (!is_array($client_data)) {
        return new WP_Error('invalid_client_data', 'clientDataJSON cannot be parsed', ['status' => 400]);
    }

    $type = isset($client_data['type']) ? (string) $client_data['type'] : '';
    $challenge = isset($client_data['challenge']) ? (string) $client_data['challenge'] : '';
    $origin = isset($client_data['origin']) ? untrailingslashit((string) $client_data['origin']) : '';
    $expected_origin = untrailingslashit((string) $record['origin']);

    if ($type !== 'webauthn.get') {
        return new WP_Error('invalid_assertion_type', 'Unexpected WebAuthn assertion type', ['status' => 400]);
    }
    if ($challenge !== (string) $record['challenge']) {
        return new WP_Error('challenge_mismatch', 'Assertion challenge does not match', ['status' => 400]);
    }
    if ($origin !== $expected_origin) {
        return new WP_Error('origin_mismatch', 'Assertion origin does not match auth broker origin', ['status' => 400]);
    }

    if (!nostr_is_auth_broker_dev_mode_enabled()) {
        return new WP_Error(
            'webauthn_verifier_unavailable',
            'Server-side WebAuthn signature verification is not enabled yet. Enable dev mode for initial integration tests.',
            ['status' => 501]
        );
    }

    $now = time();
    $claims = [
        'iss' => 'wp-nostr-auth-broker',
        'userId' => $user_id,
        'intent' => (string) $record['intent'],
        'challengeId' => $challenge_id,
        'credentialId' => $credential_id,
        'iat' => $now,
        'exp' => $now + 120,
        'mode' => 'dev-unverified'
    ];

    return [
        'success' => true,
        'token' => nostr_auth_broker_sign_result_token($claims),
        'expiresAt' => $claims['exp'],
        'mode' => $claims['mode']
    ];
}

function nostr_maybe_render_auth_broker_page() {
    if (!isset($_GET['nostr_auth_broker'])) {
        return;
    }

    if (!nostr_is_auth_broker_enabled()) {
        status_header(503);
        wp_die('Nostr Auth Broker is disabled.');
    }

    if (!is_user_logged_in()) {
        auth_redirect();
        exit;
    }

    nocache_headers();
    $script_url = plugins_url('nostr-auth-broker.js', __FILE__);
    $config = [
        'restUrl' => rest_url('nostr/v1/'),
        'nonce' => wp_create_nonce('wp_rest'),
        'origin' => nostr_get_auth_broker_origin(),
        'rpId' => nostr_get_auth_broker_rp_id()
    ];
    ?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nostr Auth Broker</title>
  <style>
    body { font-family: "Segoe UI", Tahoma, sans-serif; margin: 0; padding: 16px; background: #f5f7fb; color: #1e2530; }
    .card { max-width: 560px; margin: 0 auto; background: #fff; border: 1px solid #d8dee9; border-radius: 10px; padding: 16px; }
    .status { font-size: 14px; margin-top: 10px; color: #3b4656; white-space: pre-line; }
    .small { font-size: 12px; color: #5a6677; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h1 style="margin:0 0 8px;font-size:20px;">Nostr Auth Broker</h1>
    <p style="margin:0;">Dieses Fenster wird von der Extension fuer Passkey-Auth genutzt.</p>
    <p id="nostr-auth-broker-status" class="status">Warte auf Extension-Anfrage...</p>
    <p class="small">Origin: <?php echo esc_html(nostr_get_auth_broker_origin()); ?> | RP-ID: <?php echo esc_html(nostr_get_auth_broker_rp_id()); ?></p>
  </div>
  <script>
    window.nostrAuthBrokerConfig = <?php echo wp_json_encode($config); ?>;
  </script>
  <script src="<?php echo esc_url($script_url); ?>"></script>
</body>
</html>
    <?php
    exit;
}

function nostr_backup_meta_key() {
    return 'nostr_encrypted_backup_v1';
}

function nostr_backup_is_hex_pubkey($value) {
    return is_string($value) && preg_match('/^[a-f0-9]{64}$/', strtolower($value)) === 1;
}

function nostr_backup_normalize_base64($value) {
    if (!is_string($value)) {
        return null;
    }
    $normalized = str_replace(["\r", "\n", "\t", " "], '', trim($value));
    return $normalized === '' ? null : $normalized;
}

function nostr_backup_validate_base64_field($value, $field_name, $min_len = 16, $max_len = 200000, $allow_null = false) {
    if ($allow_null && ($value === null || $value === '')) {
        return null;
    }

    $normalized = nostr_backup_normalize_base64($value);
    if ($normalized === null) {
        return new WP_Error('invalid_backup_field', $field_name . ' is required', ['status' => 400]);
    }

    if (strlen($normalized) < $min_len || strlen($normalized) > $max_len) {
        return new WP_Error('invalid_backup_field', $field_name . ' has invalid length', ['status' => 400]);
    }

    // Accept standard/base64url chars and optional '=' padding.
    if (!preg_match('/^[A-Za-z0-9+\/=_-]+$/', $normalized)) {
        return new WP_Error('invalid_backup_field', $field_name . ' must be base64-like encoded', ['status' => 400]);
    }

    return $normalized;
}

function nostr_backup_rate_limit($action, $limit, $window_seconds) {
    $user_id = get_current_user_id();
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    $bucket_key = 'nostr_rl_' . md5($action . '|' . $user_id . '|' . $ip);
    $now = time();

    $bucket = get_transient($bucket_key);
    if (!is_array($bucket) || !isset($bucket['count'], $bucket['reset_at']) || (int) $bucket['reset_at'] <= $now) {
        $bucket = [
            'count' => 0,
            'reset_at' => $now + $window_seconds
        ];
    }

    if ((int) $bucket['count'] >= $limit) {
        $retry_after = max(1, ((int) $bucket['reset_at']) - $now);
        return new WP_Error(
            'rate_limited',
            'Too many requests, please retry later',
            [
                'status' => 429,
                'retryAfter' => $retry_after
            ]
        );
    }

    $bucket['count'] = (int) $bucket['count'] + 1;
    $ttl = max(1, ((int) $bucket['reset_at']) - $now);
    set_transient($bucket_key, $bucket, $ttl);
    return true;
}

function nostr_backup_get_record($user_id) {
    $record = get_user_meta($user_id, nostr_backup_meta_key(), true);
    return is_array($record) ? $record : null;
}

function nostr_backup_upload(WP_REST_Request $request) {
    $rate_limit = nostr_backup_rate_limit('backup_upload', 20, 300);
    if (is_wp_error($rate_limit)) {
        return $rate_limit;
    }

    $user_id = get_current_user_id();
    $params = $request->get_json_params();
    if (!is_array($params)) {
        return new WP_Error('invalid_payload', 'Expected JSON payload', ['status' => 400]);
    }

    $version = isset($params['version']) ? (int) $params['version'] : 0;
    if ($version !== 1) {
        return new WP_Error('invalid_version', 'Unsupported backup version', ['status' => 400]);
    }

    $pubkey = isset($params['pubkey']) ? strtolower(trim((string) $params['pubkey'])) : '';
    if (!nostr_backup_is_hex_pubkey($pubkey)) {
        return new WP_Error('invalid_pubkey', 'Invalid pubkey format', ['status' => 400]);
    }

    $registered_pubkey = strtolower((string) get_user_meta($user_id, 'nostr_pubkey', true));
    if ($registered_pubkey !== '' && $registered_pubkey !== $pubkey) {
        return new WP_Error(
            'pubkey_mismatch',
            'Backup pubkey does not match currently registered account pubkey',
            ['status' => 409, 'currentPubkey' => $registered_pubkey]
        );
    }

    $backup_blob = nostr_backup_validate_base64_field($params['backupBlob'] ?? null, 'backupBlob', 32, 400000, false);
    if (is_wp_error($backup_blob)) return $backup_blob;

    $blob_iv = nostr_backup_validate_base64_field($params['blobIv'] ?? null, 'blobIv', 12, 512, false);
    if (is_wp_error($blob_iv)) return $blob_iv;

    $blob_aad = nostr_backup_validate_base64_field($params['blobAad'] ?? null, 'blobAad', 8, 8192, false);
    if (is_wp_error($blob_aad)) return $blob_aad;

    $wrapped_dek_passkey = nostr_backup_validate_base64_field($params['wrappedDekPasskey'] ?? null, 'wrappedDekPasskey', 16, 400000, false);
    if (is_wp_error($wrapped_dek_passkey)) return $wrapped_dek_passkey;

    $wrapped_dek_recovery = nostr_backup_validate_base64_field($params['wrappedDekRecovery'] ?? null, 'wrappedDekRecovery', 16, 400000, true);
    if (is_wp_error($wrapped_dek_recovery)) return $wrapped_dek_recovery;

    $key_fingerprint = nostr_backup_validate_base64_field($params['keyFingerprint'] ?? null, 'keyFingerprint', 16, 1024, false);
    if (is_wp_error($key_fingerprint)) return $key_fingerprint;

    $existing = nostr_backup_get_record($user_id);
    $created_at = $existing && isset($existing['createdAt']) ? (int) $existing['createdAt'] : time();
    $updated_at = time();

    $record = [
        'version' => 1,
        'pubkey' => $pubkey,
        'backupBlob' => $backup_blob,
        'blobIv' => $blob_iv,
        'blobAad' => $blob_aad,
        'wrappedDekPasskey' => $wrapped_dek_passkey,
        'wrappedDekRecovery' => $wrapped_dek_recovery,
        'keyFingerprint' => $key_fingerprint,
        'createdAt' => $created_at,
        'updatedAt' => $updated_at
    ];

    update_user_meta($user_id, nostr_backup_meta_key(), $record);

    return [
        'success' => true,
        'hasBackup' => true,
        'version' => 1,
        'pubkey' => $pubkey,
        'updatedAt' => $updated_at,
        'hasRecoveryWrap' => $wrapped_dek_recovery !== null
    ];
}

function nostr_backup_metadata() {
    $rate_limit = nostr_backup_rate_limit('backup_metadata', 60, 300);
    if (is_wp_error($rate_limit)) {
        return $rate_limit;
    }

    $user_id = get_current_user_id();
    $record = nostr_backup_get_record($user_id);

    if (!$record) {
        return [
            'hasBackup' => false,
            'version' => null,
            'pubkey' => null,
            'updatedAt' => null,
            'hasRecoveryWrap' => false
        ];
    }

    return [
        'hasBackup' => true,
        'version' => (int) ($record['version'] ?? 1),
        'pubkey' => (string) ($record['pubkey'] ?? ''),
        'updatedAt' => isset($record['updatedAt']) ? (int) $record['updatedAt'] : null,
        'hasRecoveryWrap' => !empty($record['wrappedDekRecovery'])
    ];
}

function nostr_backup_download(WP_REST_Request $request) {
    $rate_limit = nostr_backup_rate_limit('backup_download', 20, 300);
    if (is_wp_error($rate_limit)) {
        return $rate_limit;
    }

    $user_id = get_current_user_id();
    $record = nostr_backup_get_record($user_id);
    if (!$record) {
        return new WP_Error('backup_not_found', 'No backup found', ['status' => 404]);
    }

    $expected_pubkey = strtolower(trim((string) $request->get_param('expectedPubkey')));
    if ($expected_pubkey !== '' && (!nostr_backup_is_hex_pubkey($expected_pubkey) || $expected_pubkey !== (string) $record['pubkey'])) {
        return new WP_Error(
            'backup_pubkey_mismatch',
            'Stored backup pubkey does not match expected pubkey',
            ['status' => 409, 'storedPubkey' => (string) $record['pubkey']]
        );
    }

    return [
        'hasBackup' => true,
        'version' => (int) ($record['version'] ?? 1),
        'pubkey' => (string) ($record['pubkey'] ?? ''),
        'backupBlob' => (string) ($record['backupBlob'] ?? ''),
        'blobIv' => (string) ($record['blobIv'] ?? ''),
        'blobAad' => (string) ($record['blobAad'] ?? ''),
        'wrappedDekPasskey' => (string) ($record['wrappedDekPasskey'] ?? ''),
        'wrappedDekRecovery' => isset($record['wrappedDekRecovery']) ? $record['wrappedDekRecovery'] : null,
        'keyFingerprint' => (string) ($record['keyFingerprint'] ?? ''),
        'updatedAt' => isset($record['updatedAt']) ? (int) $record['updatedAt'] : null,
        'hasRecoveryWrap' => !empty($record['wrappedDekRecovery'])
    ];
}

function nostr_backup_delete() {
    $rate_limit = nostr_backup_rate_limit('backup_delete', 20, 300);
    if (is_wp_error($rate_limit)) {
        return $rate_limit;
    }

    $user_id = get_current_user_id();
    $deleted = delete_user_meta($user_id, nostr_backup_meta_key());

    return [
        'success' => true,
        'deleted' => (bool) $deleted
    ];
}

// ============================================================
// Admin Interface
// ============================================================

function nostr_admin_menu() {
    add_options_page(
        'Nostr Einstellungen',
        'Nostr',
        'manage_options',
        'nostr-settings',
        'nostr_settings_page'
    );
}

function nostr_sanitize_allowed_domains($value) {
    if (is_array($value)) {
        $lines = $value;
    } else {
        $lines = preg_split('/\r\n|\r|\n/', (string) $value);
    }

    $lines = array_map('nostr_normalize_domain', $lines);
    $lines = array_filter(array_map('trim', $lines));
    $lines = array_values(array_unique($lines));

    return implode("\n", $lines);
}

function nostr_sanitize_primary_domain($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return nostr_get_default_primary_domain();
    }
    return untrailingslashit($value);
}

function nostr_sanitize_checkbox($value) {
    if (is_bool($value)) {
        return $value ? 1 : 0;
    }
    $value = strtolower(trim((string) $value));
    return in_array($value, ['1', 'true', 'on', 'yes'], true) ? 1 : 0;
}

function nostr_sanitize_profile_relay_url($value) {
    $raw = trim((string) $value);
    if ($raw === '') {
        return '';
    }

    $parts = preg_split('/[\r\n,\s;]+/', $raw);
    $parts = is_array($parts) ? $parts : [];
    $valid = [];

    foreach ($parts as $entry) {
        $entry = trim((string) $entry);
        if ($entry === '') {
            continue;
        }
        if (preg_match('/^(wss?|https?):\/\/[^\s]+$/i', $entry) !== 1) {
            continue;
        }
        $valid[] = $entry;
    }

    $valid = array_values(array_unique($valid));
    return implode("\n", $valid);
}

function nostr_sanitize_auth_broker_origin($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return untrailingslashit(home_url());
    }
    $value = untrailingslashit($value);
    if (preg_match('/^https?:\/\/[^\s\/$.?#].[^\s]*$/i', $value) !== 1) {
        return untrailingslashit(home_url());
    }
    return $value;
}

function nostr_sanitize_auth_broker_rp_id($value) {
    $value = strtolower(trim((string) $value));
    if ($value === '') {
        $host = parse_url(nostr_get_auth_broker_origin(), PHP_URL_HOST);
        return $host ? strtolower($host) : '';
    }
    if (preg_match('/^[a-z0-9.-]+$/', $value) !== 1) {
        $host = parse_url(nostr_get_auth_broker_origin(), PHP_URL_HOST);
        return $host ? strtolower($host) : '';
    }
    return $value;
}

function nostr_admin_init() {
    register_setting('nostr_options', 'nostr_allowed_domains', [
        'type' => 'string',
        'sanitize_callback' => 'nostr_sanitize_allowed_domains'
    ]);
    register_setting('nostr_options', 'nostr_primary_domain', [
        'type' => 'string',
        'sanitize_callback' => 'nostr_sanitize_primary_domain'
    ]);
    register_setting('nostr_options', 'nostr_min_extension_version', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field'
    ]);
    register_setting('nostr_options', 'nostr_extension_store_url', [
        'type' => 'string',
        'sanitize_callback' => 'esc_url_raw'
    ]);
    register_setting('nostr_options', 'nostr_extension_store_url_chrome', [
        'type' => 'string',
        'sanitize_callback' => 'esc_url_raw'
    ]);
    register_setting('nostr_options', 'nostr_extension_store_url_firefox', [
        'type' => 'string',
        'sanitize_callback' => 'esc_url_raw'
    ]);
    register_setting('nostr_options', 'nostr_profile_relay_url', [
        'type' => 'string',
        'sanitize_callback' => 'nostr_sanitize_profile_relay_url'
    ]);
    register_setting('nostr_options', 'nostr_publish_kind0_on_register', [
        'type' => 'integer',
        'sanitize_callback' => 'nostr_sanitize_checkbox'
    ]);
    register_setting('nostr_options', 'nostr_profile_nip05', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field'
    ]);
    register_setting('nostr_options', 'nostr_auth_broker_enabled', [
        'type' => 'integer',
        'sanitize_callback' => 'nostr_sanitize_checkbox'
    ]);
    register_setting('nostr_options', 'nostr_auth_broker_origin', [
        'type' => 'string',
        'sanitize_callback' => 'nostr_sanitize_auth_broker_origin'
    ]);
    register_setting('nostr_options', 'nostr_auth_broker_rp_id', [
        'type' => 'string',
        'sanitize_callback' => 'nostr_sanitize_auth_broker_rp_id'
    ]);
    register_setting('nostr_options', 'nostr_auth_broker_dev_mode_unverified', [
        'type' => 'integer',
        'sanitize_callback' => 'nostr_sanitize_checkbox'
    ]);
}

function nostr_settings_page() {
    ?>
    <div class="wrap">
        <h1>Nostr Integration Einstellungen</h1>
        
        <form method="post" action="options.php">
            <?php settings_fields('nostr_options'); ?>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="nostr_primary_domain">Primäre Domain</label>
                    </th>
                    <td>
                        <input type="text" 
                               id="nostr_primary_domain"
                               name="nostr_primary_domain" 
                               value="<?php echo esc_attr(get_option('nostr_primary_domain', nostr_get_default_primary_domain())); ?>" 
                               class="regular-text" />
                        <p class="description">
                            Hauptdomain für Extension-Updates (z.B. example.com)
                        </p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="nostr_allowed_domains">Erlaubte Domains</label>
                    </th>
                    <td>
                        <textarea id="nostr_allowed_domains"
                                  name="nostr_allowed_domains" 
                                  rows="5" 
                                  cols="50"
                                  class="large-text"><?php 
                            $domains = get_option('nostr_allowed_domains', parse_url(home_url(), PHP_URL_HOST));
                            if (is_array($domains)) {
                                echo esc_textarea(implode("\n", $domains));
                            } else {
                                echo esc_textarea((string) $domains);
                            }
                        ?></textarea>
                        <p class="description">
                            Eine Domain pro Zeile. Diese Domains werden der Extension als vertrauenswürdig mitgeteilt.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Primary-Domain Auth Broker</th>
                    <td>
                        <label for="nostr_auth_broker_enabled">
                            <input type="checkbox"
                                   id="nostr_auth_broker_enabled"
                                   name="nostr_auth_broker_enabled"
                                   value="1"
                                   <?php checked((int) get_option('nostr_auth_broker_enabled', 0), 1); ?> />
                            Auth-Broker fuer WebAuthn-Challenge/Assertion aktivieren
                        </label>
                        <p class="description">
                            Broker-URL: <code><?php echo esc_html(nostr_get_auth_broker_url()); ?></code>
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="nostr_auth_broker_origin">Auth-Broker Origin</label>
                    </th>
                    <td>
                        <input type="text"
                               id="nostr_auth_broker_origin"
                               name="nostr_auth_broker_origin"
                               value="<?php echo esc_attr(get_option('nostr_auth_broker_origin', untrailingslashit(home_url()))); ?>"
                               class="regular-text" />
                        <p class="description">
                            Stabile Origin fuer Passkey-Flow (z.B. https://auth.edufeed.org).
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="nostr_auth_broker_rp_id">WebAuthn RP-ID</label>
                    </th>
                    <td>
                        <input type="text"
                               id="nostr_auth_broker_rp_id"
                               name="nostr_auth_broker_rp_id"
                               value="<?php echo esc_attr(get_option('nostr_auth_broker_rp_id', parse_url(untrailingslashit(home_url()), PHP_URL_HOST))); ?>"
                               class="regular-text" />
                        <p class="description">
                            Beispiel: <code>edufeed.org</code> fuer gemeinsame Nutzung ueber Subdomains.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Auth-Broker Dev Mode</th>
                    <td>
                        <label for="nostr_auth_broker_dev_mode_unverified">
                            <input type="checkbox"
                                   id="nostr_auth_broker_dev_mode_unverified"
                                   name="nostr_auth_broker_dev_mode_unverified"
                                   value="1"
                                   <?php checked((int) get_option('nostr_auth_broker_dev_mode_unverified', 0), 1); ?> />
                            Unverifizierte Assertion fuer Integrations-Tests erlauben (NICHT fuer Produktion)
                        </label>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="nostr_min_extension_version">Minimale Extension-Version</label>
                    </th>
                    <td>
                        <input type="text" 
                               id="nostr_min_extension_version"
                               name="nostr_min_extension_version" 
                               value="<?php echo esc_attr(get_option('nostr_min_extension_version', '1.0.0')); ?>" 
                               class="regular-text" />
                        <p class="description">
                            User mit älteren Versionen werden zum Update aufgefordert (Semver-Format: X.Y.Z)
                        </p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="nostr_extension_store_url_chrome">Chrome Web Store URL</label>
                    </th>
                    <td>
                        <input type="url" 
                               id="nostr_extension_store_url_chrome"
                               name="nostr_extension_store_url_chrome" 
                               value="<?php echo esc_attr(get_option('nostr_extension_store_url_chrome', get_option('nostr_extension_store_url', 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]'))); ?>" 
                               class="regular-text" />
                        <p class="description">
                            Link zum Chrome Web Store fuer den Install-Prompt in Chrome/Chromium.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="nostr_profile_relay_url">Profil-Relay (kind:0)</label>
                    </th>
                    <td>
                        <input type="text"
                               id="nostr_profile_relay_url"
                               name="nostr_profile_relay_url"
                               value="<?php echo esc_attr(get_option('nostr_profile_relay_url', '')); ?>"
                               class="regular-text" />
                        <p class="description">
                            Optional: Relay-URL(s) fuer automatisches Profil-Publishing nach Registrierung (z.B. wss://relay.edufeed.org). Mehrere Werte per Komma oder Zeilenumbruch.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Auto-Publish Profil-Event</th>
                    <td>
                        <label for="nostr_publish_kind0_on_register">
                            <input type="checkbox"
                                   id="nostr_publish_kind0_on_register"
                                   name="nostr_publish_kind0_on_register"
                                   value="1"
                                   <?php checked((int) get_option('nostr_publish_kind0_on_register', 1), 1); ?> />
                            Nach erfolgreicher Registrierung ein kind:0 Event senden
                        </label>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="nostr_profile_nip05">NIP-05 Identifier (optional)</label>
                    </th>
                    <td>
                        <input type="text"
                               id="nostr_profile_nip05"
                               name="nostr_profile_nip05"
                               value="<?php echo esc_attr(get_option('nostr_profile_nip05', '')); ?>"
                               class="regular-text"
                               placeholder="z.B. joachim@edufeed.org" />
                        <p class="description">
                            Wird im kind:0 Profil als <code>nip05</code> gesetzt, wenn ausgefuellt.
                        </p>
                    </td>
                </tr>
                
                <tr>
                    <th scope="row">
                        <label for="nostr_extension_store_url_firefox">Firefox Add-ons URL</label>
                    </th>
                    <td>
                        <input type="url" 
                               id="nostr_extension_store_url_firefox"
                               name="nostr_extension_store_url_firefox" 
                               value="<?php echo esc_attr(get_option('nostr_extension_store_url_firefox', 'https://addons.mozilla.org/firefox/addon/[ADDON_SLUG]')); ?>" 
                               class="regular-text" />
                        <p class="description">
                            Link zu addons.mozilla.org fuer den Install-Prompt in Firefox.
                        </p>
                    </td>
                </tr>
            </table>
            
            <?php submit_button('Einstellungen speichern'); ?>
        </form>
        
        <hr />
        
        <h2>Domain-Sync Secret</h2>
        <p>Das Secret wird verwendet, um die Domain-Liste kryptografisch zu signieren.</p>
        <code><?php echo esc_html(get_option('nostr_domain_secret', 'Noch nicht generiert')); ?></code>
    </div>
    <?php
}
