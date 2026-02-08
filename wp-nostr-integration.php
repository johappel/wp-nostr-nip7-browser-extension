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

    wp_enqueue_script(
        'nostr-integration',
        plugins_url('nostr-integration.js', __FILE__),
        [],
        '1.0.0',
        true
    );
    
    wp_localize_script('nostr-integration', 'nostrConfig', [
        'restUrl' => rest_url('nostr/v1/'),
        'nonce' => wp_create_nonce('wp_rest'),
        'siteDomain' => parse_url(home_url(), PHP_URL_HOST),
        'isLoggedIn' => is_user_logged_in(),
        'primaryDomain' => get_option('nostr_primary_domain', nostr_get_default_primary_domain()),
        'domainSecret' => nostr_get_or_create_domain_secret(),
        'extensionStoreUrl' => get_option('nostr_extension_store_url', 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]')
    ]);
    
    // CSS für Modal
    wp_enqueue_style(
        'nostr-integration-css',
        plugins_url('nostr-integration.css', __FILE__),
        [],
        '1.0.0'
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
}

function nostr_handle_register(WP_REST_Request $request) {
    $pubkey = sanitize_text_field($request->get_param('pubkey'));
    $user_id = get_current_user_id();
    
    // Validiere hex Pubkey Format (64 hex chars)
    if (!preg_match('/^[a-f0-9]{64}$/', $pubkey)) {
        return new WP_Error(
            'invalid_pubkey', 
            'Ungültiges Pubkey Format', 
            ['status' => 400]
        );
    }
    
    // Prüfe ob dieser Pubkey bereits einem anderen User zugeordnet ist
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
    
    // Speichere hex-pubkey (Server könnte optional npub ableiten)
    update_user_meta($user_id, 'nostr_pubkey', $pubkey);
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
                        <label for="nostr_extension_store_url">Extension Store URL</label>
                    </th>
                    <td>
                        <input type="url" 
                               id="nostr_extension_store_url"
                               name="nostr_extension_store_url" 
                               value="<?php echo esc_attr(get_option('nostr_extension_store_url', 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]')); ?>" 
                               class="regular-text" />
                        <p class="description">
                            Link zum Chrome Web Store (wird im Install-Prompt angezeigt)
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
