# TASK-02: WordPress Integration & Detection

## Ziel
WordPress erkennt Extension-Status und bietet Installation an falls nicht vorhanden. User können ihre Npub mit ihrem WordPress-Account verknüpfen.

## Abhängigkeiten
- **TASK-01: Extension Grundgerüst** muss abgeschlossen sein
- Extension muss `NOSTR_PING` und `NOSTR_PING_RESPONSE` unterstützen

## Ergebnis
Nach Abschluss dieses Tasks:
- WordPress erkennt automatisch ob die Extension installiert ist
- Install-Prompt wird bei fehlender Extension angezeigt
- Npub-Registrierung funktioniert via REST API
- User-Meta wird in WordPress gespeichert

---

## Zu erstellende Dateien

### 1. WordPress Plugin Hauptdatei

**Pfad:** `wordpress-plugin/wp-nostr-integration.php`

```php
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
        plugins_url('js/nostr-integration.js', __FILE__),
        [],
        '1.0.0',
        true
    );
    
    wp_localize_script('nostr-integration', 'nostrConfig', [
        'restUrl' => rest_url('nostr/v1/'),
        'nonce' => wp_create_nonce('wp_rest'),
        'siteDomain' => parse_url(home_url(), PHP_URL_HOST),
        'isLoggedIn' => is_user_logged_in()
    ]);
    
    // CSS für Modal
    wp_enqueue_style(
        'nostr-integration-css',
        plugins_url('css/nostr-integration.css', __FILE__),
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
        $domains = array_filter(array_map('trim', explode("\n", $domains)));
    }
    
    $payload = json_encode($domains);
    $secret  = get_option('nostr_domain_secret');
    
    // Secret beim ersten Aufruf generieren
    if (!$secret) {
        $secret = wp_generate_password(64, true, true);
        update_option('nostr_domain_secret', $secret);
    }
    
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

function nostr_admin_init() {
    register_setting('nostr_options', 'nostr_allowed_domains');
    register_setting('nostr_options', 'nostr_primary_domain');
    register_setting('nostr_options', 'nostr_min_extension_version');
    register_setting('nostr_options', 'nostr_extension_store_url');
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
                               value="<?php echo esc_attr(get_option('nostr_primary_domain', parse_url(home_url(), PHP_URL_HOST))); ?>" 
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
                            $domains = get_option('nostr_allowed_domains', []);
                            if (is_array($domains)) {
                                echo esc_textarea(implode("\n", $domains));
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
```

### 2. WordPress Frontend JavaScript

**Pfad:** `wordpress-plugin/js/nostr-integration.js`

```javascript
/**
 * Nostr WordPress Integration
 * Erkennt NIP-07 Extension und ermöglicht Registrierung
 */
class NostrWPIntegration {
  constructor() {
    this.config = window.nostrConfig || {};
    this.hasExtension = false;
    this.npub = null;
    this.init();
  }

  async init() {
    // Nur für eingeloggte User
    if (!this.config.isLoggedIn) {
      return;
    }

    // 1. Extension Detection
    this.hasExtension = await this.detectExtension();
    
    if (!this.hasExtension) {
      this.showInstallPrompt();
      return;
    }

    // 2. Prüfe ob User registriert ist
    const wpUser = await this.getCurrentWPUser();
    
    if (!wpUser.pubkey) {
      // 3. Registrierungs-Flow
      await this.handleRegistration();
    } else {
      // 4. Prüfe ob Npub übereinstimmt
      await this.verifyExistingUser(wpUser.pubkey);
    }
  }

  async detectExtension() {
    return new Promise((resolve) => {
      // Ping an Extension
      window.postMessage({ type: 'NOSTR_PING', _id: 'detect' }, '*');
      
      const handler = (e) => {
        if (e.data.type === 'NOSTR_PING_RESPONSE') {
          window.removeEventListener('message', handler);
          console.log('[Nostr] Extension detected:', e.data.version);
          resolve(true);
        }
      };
      
      window.addEventListener('message', handler);
      
      // Timeout nach 500ms
      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve(false);
      }, 500);
    });
  }

  showInstallPrompt() {
    const storeUrl = this.config.extensionStoreUrl || 
                     'https://chrome.google.com/webstore/detail/[EXTENSION_ID]';
    
    const modal = document.createElement('div');
    modal.id = 'nostr-install-modal';
    modal.innerHTML = `
      <div class="nostr-modal-backdrop">
        <div class="nostr-modal">
          <h3>🔐 Nostr Signer erforderlich</h3>
          <p>Für die sichere Anmeldung mit Nostr benötigst du unsere Browser Extension.</p>
          
          <div class="install-steps">
            <ol>
              <li>Extension aus dem Store herunterladen</li>
              <li>Extension installieren</li>
              <li>Diese Seite neu laden</li>
            </ol>
          </div>
          
          <div class="nostr-modal-actions">
            <a href="${storeUrl}" 
               target="_blank" 
               rel="noopener noreferrer"
               class="nostr-btn nostr-btn-primary">
              Extension installieren
            </a>
            
            <button class="nostr-btn nostr-btn-secondary" id="nostr-dismiss">
              Später erinnern
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    
    // Dismiss Handler
    document.getElementById('nostr-dismiss').onclick = () => {
      modal.remove();
      // Merke dir, dass User dismissed hat (Session Storage)
      sessionStorage.setItem('nostr_install_dismissed', 'true');
    };
    
    // Nicht anzeigen wenn bereits dismissed
    if (sessionStorage.getItem('nostr_install_dismissed') === 'true') {
      modal.remove();
    }
  }

  async handleRegistration() {
    try {
      // Zeige Registrierungs-Button
      this.showRegistrationUI();
    } catch (error) {
      console.error('[Nostr] Registration setup failed:', error);
    }
  }

  showRegistrationUI() {
    // Prüfe ob bereits ein Registrierungs-Button existiert
    if (document.getElementById('nostr-register-btn')) {
      return;
    }

    const container = document.createElement('div');
    container.id = 'nostr-register-container';
    container.innerHTML = `
      <div class="nostr-register-prompt">
        <p>🔗 Verknüpfe deinen Nostr-Account mit deinem WordPress-Profil</p>
        <button id="nostr-register-btn" class="nostr-btn nostr-btn-primary">
          Mit Nostr verknüpfen
        </button>
      </div>
    `;
    
    // Füge zum Body oder einem geeigneten Container hinzu
    const target = document.querySelector('.entry-content') || 
                   document.querySelector('main') || 
                   document.body;
    target.insertBefore(container, target.firstChild);
    
    // Click Handler
    document.getElementById('nostr-register-btn').onclick = async () => {
      await this.performRegistration();
    };
  }

  async performRegistration() {
    const btn = document.getElementById('nostr-register-btn');
    btn.disabled = true;
    btn.textContent = 'Registriere...';

    try {
      // NIP-07: getPublicKey() gibt hex-pubkey zurück
      const hexPubkey = await window.nostr.getPublicKey();
      
      // Sende hex-pubkey an WordPress
      const response = await fetch(`${this.config.restUrl}register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WP-Nonce': this.config.nonce
        },
        body: JSON.stringify({ pubkey: hexPubkey })
      });
      
      const result = await response.json();
      
      if (response.ok && result.success) {
        this.showRegistrationSuccess();
        // Entferne Registrierungs-Button
        document.getElementById('nostr-register-container')?.remove();
      } else {
        throw new Error(result.message || 'Registrierung fehlgeschlagen');
      }
    } catch (error) {
      console.error('[Nostr] Registration failed:', error);
      this.showError(error.message);
      btn.disabled = false;
      btn.textContent = 'Mit Nostr verknüpfen';
    }
  }

  async verifyExistingUser(expectedPubkey) {
    try {
      const currentPubkey = await window.nostr.getPublicKey();
      if (currentPubkey !== expectedPubkey) {
        this.showKeyMismatchWarning(expectedPubkey, currentPubkey);
      } else {
        console.log('[Nostr] Key verified successfully');
        this.showVerifiedStatus();
      }
    } catch (error) {
      console.error('[Nostr] Verification failed:', error);
    }
  }

  showKeyMismatchWarning(expected, actual) {
    console.warn('[Nostr] Key mismatch:', { expected, actual });
    
    const warning = document.createElement('div');
    warning.className = 'nostr-warning';
    warning.innerHTML = `
      <p>⚠️ Dein Nostr-Schlüssel stimmt nicht mit dem registrierten Schlüssel überein.</p>
      <p>Bitte prüfe, ob du die richtige Extension verwendest.</p>
    `;
    
    const target = document.querySelector('.entry-content') || 
                   document.querySelector('main') || 
                   document.body;
    target.insertBefore(warning, target.firstChild);
  }

  showRegistrationSuccess() {
    const success = document.createElement('div');
    success.className = 'nostr-success';
    success.innerHTML = `
      <p>✅ Dein Nostr-Account wurde erfolgreich verknüpft!</p>
    `;
    
    const target = document.querySelector('.entry-content') || 
                   document.querySelector('main') || 
                   document.body;
    target.insertBefore(success, target.firstChild);
    
    // Nach 5 Sekunden ausblenden
    setTimeout(() => success.remove(), 5000);
  }

  showVerifiedStatus() {
    // Zeige einen kleinen Verified-Badge an
    const badge = document.createElement('div');
    badge.className = 'nostr-verified-badge';
    badge.innerHTML = '✓ Nostr verifiziert';
    badge.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#4CAF50;color:white;padding:8px 16px;border-radius:4px;font-size:14px;z-index:9999;';
    document.body.appendChild(badge);
    
    setTimeout(() => badge.remove(), 3000);
  }

  showError(message) {
    const error = document.createElement('div');
    error.className = 'nostr-error';
    error.innerHTML = `<p>❌ Fehler: ${message}</p>`;
    
    const container = document.getElementById('nostr-register-container');
    if (container) {
      container.insertBefore(error, container.firstChild);
      setTimeout(() => error.remove(), 5000);
    }
  }

  async getCurrentWPUser() {
    try {
      const response = await fetch(`${this.config.restUrl}user`, {
        headers: { 'X-WP-Nonce': this.config.nonce }
      });
      return await response.json();
    } catch (error) {
      console.error('[Nostr] Failed to get user:', error);
      return { pubkey: null };
    }
  }
}

// Initialisierung wenn DOM bereit
document.addEventListener('DOMContentLoaded', () => {
  window.nostrWP = new NostrWPIntegration();
});
```

### 3. WordPress CSS

**Pfad:** `wordpress-plugin/css/nostr-integration.css`

```css
/* Nostr Integration Styles */

/* Modal Backdrop */
.nostr-modal-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
}

/* Modal */
.nostr-modal {
  background: white;
  padding: 24px;
  border-radius: 8px;
  max-width: 450px;
  width: 90%;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
}

.nostr-modal h3 {
  margin: 0 0 16px 0;
  font-size: 20px;
}

.nostr-modal p {
  margin: 0 0 12px 0;
  color: #555;
}

.install-steps ol {
  margin: 16px 0;
  padding-left: 24px;
}

.install-steps li {
  margin-bottom: 8px;
}

.nostr-modal-actions {
  display: flex;
  gap: 12px;
  margin-top: 20px;
}

/* Buttons */
.nostr-btn {
  display: inline-block;
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  font-size: 14px;
  cursor: pointer;
  text-decoration: none;
  transition: background 0.2s;
}

.nostr-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.nostr-btn-primary {
  background: #6441a5;
  color: white;
}

.nostr-btn-primary:hover:not(:disabled) {
  background: #543a8c;
}

.nostr-btn-secondary {
  background: #e0e0e0;
  color: #333;
}

.nostr-btn-secondary:hover:not(:disabled) {
  background: #d0d0d0;
}

/* Registration Prompt */
.nostr-register-prompt {
  background: #f5f5f5;
  padding: 16px;
  border-radius: 8px;
  margin: 16px 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}

.nostr-register-prompt p {
  margin: 0;
  flex: 1;
  min-width: 200px;
}

/* Status Messages */
.nostr-success,
.nostr-warning,
.nostr-error {
  padding: 12px 16px;
  border-radius: 4px;
  margin: 16px 0;
}

.nostr-success {
  background: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
}

.nostr-warning {
  background: #fff3cd;
  color: #856404;
  border: 1px solid #ffeeba;
}

.nostr-error {
  background: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
}

/* Verified Badge */
.nostr-verified-badge {
  animation: fadeInOut 3s ease-in-out;
}

@keyframes fadeInOut {
  0% { opacity: 0; transform: translateY(10px); }
  20% { opacity: 1; transform: translateY(0); }
  80% { opacity: 1; transform: translateY(0); }
  100% { opacity: 0; transform: translateY(-10px); }
}
```

---

## Sicherheitsregeln für diesen Task

### KOMMUNIKATION REGELN (relevant für TASK-02)
- Alle REST-Endpoints verwenden WordPress Nonce-Validierung (`X-WP-Nonce`)
- HTTPS sollte für alle Domain-Kommunikationen erzwungen werden
- Keine Inline-Scripts, nur externe JS-Files
- Domain-Listen vom Server müssen HMAC-signiert sein

### DOMAIN REGELN (relevant für TASK-02)
- Domain-Whitelist wird mit HMAC-SHA256 signiert
- Secret wird beim ersten Aufruf automatisch generiert

---

## Akzeptanzkriterien

- [ ] WordPress Plugin lässt sich ohne Fehler aktivieren
- [ ] Extension Detection funktioniert zuverlässig
- [ ] Install-Prompt wird bei fehlender Extension angezeigt
- [ ] Registrierungs-Button wird angezeigt wenn User noch nicht registriert
- [ ] Npub-Registrierung funktioniert via REST API
- [ ] User-Meta wird korrekt in WordPress gespeichert
- [ ] Key-Mismatch wird erkannt und angezeigt
- [ ] Admin-Settings-Page ist funktional
- [ ] Domain-Liste wird mit HMAC-Signatur zurückgegeben

---

## Test-Anleitung

### 1. WordPress Plugin Installation
1. Kopiere den `wordpress-plugin` Ordner in `/wp-content/plugins/`
2. Aktiviere das Plugin in WordPress Admin
3. Gehe zu Einstellungen → Nostr und konfiguriere die Optionen

### 2. Extension Detection Test
1. Öffne eine WordPress-Seite als eingeloggter User
2. Öffne Browser Console
3. Prüfe ob `[Nostr] Extension detected: 1.0.0` erscheint

### 3. Registrierung Test
1. Als User ohne registrierten Npub
2. Klicke auf "Mit Nostr verknüpfen"
3. Bestätige den Key-Access in der Extension
4. Prüfe ob Erfolgsmeldung erscheint

### 4. REST API Test
```bash
# User Status abfragen (mit WordPress Cookie)
curl -X GET "https://your-site.com/wp-json/nostr/v1/user" \
  -H "X-WP-Nonce: YOUR_NONCE"

# Domains abfragen (öffentlich)
curl -X GET "https://your-site.com/wp-json/nostr/v1/domains"
```

---

## Nächste Schritte

Nach Abschluss dieses Tasks:
1. **TASK-05: Multi-Domain Whitelist Management** - Erweiterte Domain-Verwaltung
2. **TASK-06: Extension Update Mechanismus** - Versionsprüfung implementieren
