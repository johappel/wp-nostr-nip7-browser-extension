## AGENTS.md - NIP-07 Extension für WordPress Nostr Integration

```markdown
# AGENTS.md: NIP-07 Signer Extension für WordPress Nostr Integration

## Projektübersicht

Entwicklung einer Browser Extension (Chrome/Firefox), die:
1. NIP-07 Signer-Funktionalität bereitstellt
2. Nahtlos mit WordPress-Instanzen integriert
3. Automatische Domain-Authentifizierung über Whitelist
4. Sichere Key-Generierung mit Backup-Export

---

## Architektur

### Komponenten

```text
┌─────────────────┐     ┌────────────────────┐     ┌─────────────────┐
│  WordPress Site │◄───►│  Browser Extension │◄───►│  Nostr Relays   │
│  (PHP/REST API) │     │  (Manifest V3)     │     │  (WebSocket)    │
└─────────────────┘     └────────────────────┘     └─────────────────┘
         ▲                        │
         └────────────────────────┘
              Domain Whitelist
              Npub Registration
```

### Technik-Stack

| Komponente | Technologie | Begründung |
|------------|-------------|------------|
| Extension Core | Vanilla JS + WebExtension API | Maximale Kompatibilität |
| Nostr Crypto | nostr-tools v2+ (ES Module) | Standard-Implementierung |
| Build Pipeline | Rollup / esbuild | nostr-tools Bundling für MV3 Service Worker |
| WordPress Backend | PHP + REST API | Native Integration |
| Key Storage | Extension Storage API + AES-GCM | Verschlüsselt mit User-Passwort |
| UI | Vanilla JS + CSS | Keine Dependencies |
| Browser Compat | webextension-polyfill | Chrome + Firefox Unterstützung |

---

## TASK 1: Extension Grundgerüst

### Ziel
Manifest V3 Extension mit Content Script Injection für NIP-07 API.

### Dateien erstellen

**manifest.json**
```json
{
  "manifest_version": 3,
  "name": "WordPress Nostr Signer",
  "version": "1.0.0",
  "description": "NIP-07 Signer für WordPress Nostr Integration",
  "permissions": [
    "storage",
    "activeTab",
    "alarms"
  ],
  "host_permissions": [
    "https://*/*"
  ],
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_end",
      "world": "ISOLATED"
    }
  ],
  "web_accessible_resources": [
    {
      "resources": ["inpage.js", "dialog.html", "dialog.css"],
      "matches": ["<all_urls>"]
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  }
}
```

**content.js** (Bridge zwischen Webseite und Background)
```javascript
// Injiziert inpage.js in MAIN world für window.nostr Zugriff
const script = document.createElement('script');
script.src = chrome.runtime.getURL('inpage.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);

// Message Bridge: Webseite <-> Background Script
// WICHTIG: _id muss durchgereicht werden für Request/Response-Korrelation
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data.type?.startsWith('NOSTR_')) return;

  try {
    const response = await chrome.runtime.sendMessage({
      type: event.data.type,
      payload: event.data.payload,
      _id: event.data._id,
      domain: window.location.hostname,
      origin: window.location.origin
    });

    window.postMessage({
      type: event.data.type + '_RESPONSE',
      _id: event.data._id,
      result: response?.result ?? null,
      error: response?.error ?? null
    }, '*');
  } catch (err) {
    window.postMessage({
      type: event.data.type + '_RESPONSE',
      _id: event.data._id,
      error: err.message || 'Extension communication failed'
    }, '*');
  }
});
```

**inpage.js** (NIP-07 API im Webseiten-Kontext)
```javascript
// NIP-07 Standard API
window.nostr = {
  getPublicKey: async () => {
    return sendRequest('NOSTR_GET_PUBLIC_KEY');
  },
  
  signEvent: async (event) => {
    return sendRequest('NOSTR_SIGN_EVENT', event);
  },
  
  getRelays: async () => {
    return sendRequest('NOSTR_GET_RELAYS');
  },
  
  nip04: {
    encrypt: async (pubkey, plaintext) => {
      return sendRequest('NOSTR_NIP04_ENCRYPT', { pubkey, plaintext });
    },
    decrypt: async (pubkey, ciphertext) => {
      return sendRequest('NOSTR_NIP04_DECRYPT', { pubkey, ciphertext });
    }
  },
  
  nip44: {
    encrypt: async (pubkey, plaintext) => {
      return sendRequest('NOSTR_NIP44_ENCRYPT', { pubkey, plaintext });
    },
    decrypt: async (pubkey, ciphertext) => {
      return sendRequest('NOSTR_NIP44_DECRYPT', { pubkey, ciphertext });
    }
  }
};

function sendRequest(type, payload = null) {
  return new Promise((resolve, reject) => {
    const id = crypto.randomUUID();
    const handler = (e) => {
      if (e.data.type === type + '_RESPONSE' && e.data._id === id) {
        window.removeEventListener('message', handler);
        if (e.data.error) reject(new Error(e.data.error));
        else resolve(e.data.result);
      }
    };
    window.addEventListener('message', handler);
    window.postMessage({ type, payload, _id: id }, '*');
  });
}
```

### Akzeptanzkriterien
- [ ] Extension lädt in Chrome und Firefox
- [ ] `window.nostr` ist auf jeder Webseite verfügbar
- [ ] Kommunikation mit Background Script funktioniert
- [ ] Keine Fehler in DevTools Console

---

## TASK 2: WordPress Integration & Detection

### Ziel
WordPress erkennt Extension-Status und bietet Installation an falls nicht vorhanden.

### WordPress Frontend Code

**wp-nostr-integration.php** (Plugin Header)
```php
<?php
/**
 * Plugin Name: Nostr Integration
 * Description: NIP-07 Extension Integration für Nostr Login
 * Version: 1.0.0
 */

add_action('wp_enqueue_scripts', 'nostr_enqueue_scripts');
add_action('rest_api_init', 'nostr_register_endpoints');

function nostr_enqueue_scripts() {
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
        'siteDomain' => parse_url(home_url(), PHP_URL_HOST)
    ]);
}
```

**js/nostr-integration.js** (Frontend Detection)
```javascript
class NostrWPIntegration {
  constructor() {
    this.config = window.nostrConfig;
    this.hasExtension = false;
    this.npub = null;
    this.init();
  }

  async init() {
    // 1. Extension Detection
    this.hasExtension = await this.detectExtension();
    
    if (!this.hasExtension) {
      this.showInstallPrompt();
      return;
    }

    // 2. Prüfe ob User registriert ist
    const wpUser = await this.getCurrentWPUser();
    
    if (!wpUser.npub) {
      // 3. Registrierungs-Flow
      await this.handleRegistration();
    } else {
      // 4. Prüfe ob Npub übereinstimmt
      await this.verifyExistingUser(wpUser.npub);
    }
  }

  async detectExtension() {
    return new Promise((resolve) => {
      // Ping an Extension
      window.postMessage({ type: 'NOSTR_PING', _id: 'detect' }, '*');
      
      const handler = (e) => {
        if (e.data.type === 'NOSTR_PING_RESPONSE') {
          window.removeEventListener('message', handler);
          resolve(true);
        }
      };
      
      window.addEventListener('message', handler);
      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve(false);
      }, 500);
    });
  }

  showInstallPrompt() {
    const modal = document.createElement('div');
    modal.id = 'nostr-install-modal';
    modal.innerHTML = `
      <div class="nostr-modal-backdrop">
        <div class="nostr-modal">
          <h3>Nostr Signer erforderlich</h3>
          <p>Für die sichere Anmeldung benötigst du unsere Browser Extension.</p>
          
          <div class="install-steps">
            <ol>
              <li>Extension aus Chrome Web Store herunterladen</li>
              <li>Extension installieren und öffnen</li>
              <li>Seite neu laden</li>
            </ol>
          </div>
          
          <a href="https://chrome.google.com/webstore/detail/[EXTENSION_ID]" 
             target="_blank" 
             class="nostr-btn primary">
            Zu Chrome Web Store
          </a>
          
          <button onclick="this.closest('#nostr-install-modal').remove()" 
                  class="nostr-btn secondary">
            Später erinnern
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  async handleRegistration() {
    try {
      // NIP-07: getPublicKey() gibt hex-pubkey zurück
      const hexPubkey = await window.nostr.getPublicKey();
      
      // Sende hex-pubkey an WordPress (Server konvertiert zu npub)
      const response = await fetch(`${this.config.restUrl}register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WP-Nonce': this.config.nonce
        },
        body: JSON.stringify({ pubkey: hexPubkey })
      });
      
      if (response.ok) {
        // Extension zeigt parallel Backup-Dialog (außerhalb WordPress Kontrolle)
        this.showRegistrationSuccess();
      }
    } catch (error) {
      console.error('Registration failed:', error);
    }
  }

  async verifyExistingUser(expectedPubkey) {
    try {
      const currentPubkey = await window.nostr.getPublicKey();
      if (currentPubkey !== expectedPubkey) {
        this.showKeyMismatchWarning(expectedPubkey, currentPubkey);
      }
    } catch (error) {
      console.error('Verification failed:', error);
    }
  }

  async getCurrentWPUser() {
    const response = await fetch(`${this.config.restUrl}user`, {
      headers: { 'X-WP-Nonce': this.config.nonce }
    });
    return response.json();
  }

  showKeyMismatchWarning(expected, actual) {
    console.warn('Nostr key mismatch: extension key differs from registered key');
  }

  showRegistrationSuccess() {
    // WordPress zeigt Erfolgsmeldung
    // Extension zeigt parallel Backup-Dialog
  }
}

// Initialisierung
document.addEventListener('DOMContentLoaded', () => {
  window.nostrWP = new NostrWPIntegration();
});
```

### WordPress REST Endpoints

```php
// REST API Endpoints registrieren
function nostr_register_endpoints() {
    register_rest_route('nostr/v1', '/register', [
        'methods' => 'POST',
        'callback' => 'nostr_handle_register',
        'permission_callback' => 'is_user_logged_in'
    ]);
    
    register_rest_route('nostr/v1', '/user', [
        'methods' => 'GET',
        'callback' => 'nostr_get_user',
        'permission_callback' => 'is_user_logged_in'
    ]);
    
    register_rest_route('nostr/v1', '/domains', [
        'methods' => 'GET',
        'callback' => 'nostr_get_domains',
        'permission_callback' => '__return_true' // Öffentlich für Extension
    ]);
}

function nostr_handle_register(WP_REST_Request $request) {
    $pubkey = sanitize_text_field($request->get_param('pubkey'));
    $user_id = get_current_user_id();
    
    // Validiere hex Pubkey Format (64 hex chars)
    if (!preg_match('/^[a-f0-9]{64}$/', $pubkey)) {
        return new WP_Error('invalid_pubkey', 'Ungültiges Pubkey Format', ['status' => 400]);
    }
    
    // Server-seitig npub ableiten (optional, für Display)
    // Primär wird hex-pubkey gespeichert
    update_user_meta($user_id, 'nostr_pubkey', $pubkey);
    update_user_meta($user_id, 'nostr_registered', current_time('mysql'));
    
    return ['success' => true, 'pubkey' => $pubkey];
}

function nostr_get_user() {
    $user_id = get_current_user_id();
    return [
        'pubkey' => get_user_meta($user_id, 'nostr_pubkey', true),
        'registered' => get_user_meta($user_id, 'nostr_registered', true)
    ];
}

// Whitelist der erlaubten Domains (mit HMAC-Signatur)
function nostr_get_domains() {
    $domains = get_option('nostr_allowed_domains', [
        parse_url(home_url(), PHP_URL_HOST)
    ]);
    
    $payload = json_encode($domains);
    $secret  = get_option('nostr_domain_secret', wp_generate_password(64, true, true));
    
    // Beim ersten Aufruf secret speichern
    if (!get_option('nostr_domain_secret')) {
        update_option('nostr_domain_secret', $secret);
    }
    
    $signature = hash_hmac('sha256', $payload . '|' . time(), $secret);
    
    return [
        'domains'   => $domains,
        'updated'   => time(),
        'signature' => $signature
    ];
}
```

### Akzeptanzkriterien
- [ ] WordPress erkennt Extension-Status zuverlässig
- [ ] Install-Prompt wird bei fehlender Extension angezeigt
- [ ] Npub-Registrierung funktioniert via REST API
- [ ] User-Meta wird in WordPress gespeichert

---

## TASK 3: Extension Key-Management & UI

### Ziel
Sichere Key-Generierung, Storage und Backup-Dialog.

**background.js** (Service Worker)

> **Build-Hinweis:** Dieses Modul muss mit Rollup/esbuild gebundelt werden,
> da MV3 Service Worker keine bare `import`-Specifier unterstützen.
> Siehe TASK 7: Build Pipeline.

```javascript
// --- nostr-tools v2 API ---
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';

const CURRENT_VERSION = '1.0.0';

// ============================================================
// Key Manager – AES-GCM verschlüsselter Storage
// ============================================================
class KeyManager {
  // Storage Keys
  static STORAGE_KEY = 'encrypted_nsec';
  static SALT_KEY   = 'encryption_salt';
  static IV_KEY     = 'encryption_iv';

  async hasKey() {
    const result = await chrome.storage.local.get([KeyManager.STORAGE_KEY]);
    return !!result[KeyManager.STORAGE_KEY];
  }

  // --- Schlüssel generieren ---
  async generateKey(password) {
    const secretKey = generateSecretKey();          // Uint8Array (32 bytes)
    const pubkey    = getPublicKey(secretKey);       // hex string
    const npub      = nip19.npubEncode(pubkey);
    const nsecBech32 = nip19.nsecEncode(secretKey);

    await this.storeKey(secretKey, password);
    secretKey.fill(0);                              // Memory wipe

    return { pubkey, npub, nsecBech32 };
  }

  // --- AES-GCM verschlüsselt speichern ---
  async storeKey(secretKey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));

    const enc      = new TextEncoder();
    const baseKey  = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey   = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, secretKey
    );

    await chrome.storage.local.set({
      [KeyManager.STORAGE_KEY]: Array.from(new Uint8Array(ciphertext)),
      [KeyManager.SALT_KEY]:    Array.from(salt),
      [KeyManager.IV_KEY]:      Array.from(iv),
      created: Date.now()
    });
  }

  // --- Entschlüsseln und Secret Key laden ---
  async getKey(password) {
    const result = await chrome.storage.local.get([
      KeyManager.STORAGE_KEY, KeyManager.SALT_KEY, KeyManager.IV_KEY
    ]);
    if (!result[KeyManager.STORAGE_KEY]) return null;

    const ciphertext = new Uint8Array(result[KeyManager.STORAGE_KEY]);
    const salt       = new Uint8Array(result[KeyManager.SALT_KEY]);
    const iv         = new Uint8Array(result[KeyManager.IV_KEY]);

    const enc     = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey  = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, aesKey, ciphertext
    );

    return new Uint8Array(decrypted); // 32-byte secret key
  }

  // --- Event signieren (NIP-07 konform) ---
  async signEvent(eventTemplate, password) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    // finalizeEvent fügt id, pubkey, sig hinzu und gibt vollständiges Event zurück
    const signed = finalizeEvent(eventTemplate, secretKey);
    secretKey.fill(0);

    return signed; // { id, pubkey, created_at, kind, tags, content, sig }
  }
}

// Global Instance
const keyManager = new KeyManager();

// Passwort-Cache (nur für laufende Session, wird bei SW-Stop gelöscht)
let cachedPassword = null;

// ============================================================
// Message Handler
// ============================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request, sender)
    .then(result => sendResponse({ result }))
    .catch(e => sendResponse({ error: e.message }));
  return true; // Async response
});

async function handleMessage(request, sender) {
  const domain = sender.tab?.url ? new URL(sender.tab.url).hostname : null;

  // PING erfordert keine Domain-Validierung (für Extension-Detection)
  if (request.type === 'NOSTR_PING') {
    return { pong: true, version: CURRENT_VERSION };
  }

  // NOSTR_CHECK_VERSION erfordert keine Domain-Validierung
  if (request.type === 'NOSTR_CHECK_VERSION') {
    return {
      version: CURRENT_VERSION,
      updateRequired: !semverSatisfies(CURRENT_VERSION, request.payload?.minVersion)
    };
  }

  // Domain-Validierung mit Bootstrapping
  const domainStatus = await checkDomainAccess(domain);
  if (domainStatus === 'blocked') {
    throw new Error('Domain not authorized');
  }
  if (domainStatus === 'pending') {
    // User muss Domain erst bestätigen
    const allowed = await promptDomainApproval(domain);
    if (!allowed) throw new Error('Domain rejected by user');
  }

  switch (request.type) {
    case 'NOSTR_GET_PUBLIC_KEY': {
      if (!await keyManager.hasKey()) {
        // Erst Passwort vom User abfragen
        cachedPassword = await promptPassword('create');
        if (!cachedPassword) throw new Error('Password required');

        const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(cachedPassword);

        // Backup-Dialog mit nsec öffnen
        await openBackupDialog(npub, nsecBech32);

        // NIP-07: getPublicKey() gibt hex-String zurück
        return pubkey;
      }

      // Passwort für Entschlüsselung
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
      }

      const secretKey = await keyManager.getKey(cachedPassword);
      const pubkey = getPublicKey(secretKey);
      secretKey.fill(0);
      // NIP-07: gibt hex-String zurück (NICHT npub)
      return pubkey;
    }

    case 'NOSTR_SIGN_EVENT': {
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
      }

      // Sensitive Events (Kind 0, 3, 4) erfordern explizite Bestätigung
      const sensitiveKinds = [0, 3, 4];
      if (sensitiveKinds.includes(request.payload?.kind)) {
        const confirmed = await promptSignConfirmation(request.payload, domain);
        if (!confirmed) throw new Error('Signing rejected by user');
      }

      // NIP-07: signEvent() gibt vollständiges signiertes Event zurück
      return await keyManager.signEvent(request.payload, cachedPassword);
    }

    case 'NOSTR_GET_RELAYS': {
      const { relays = {} } = await chrome.storage.local.get('relays');
      return relays; // { "wss://relay.example.com": { read: true, write: true } }
    }

    case 'NOSTR_NIP04_ENCRYPT':
    case 'NOSTR_NIP04_DECRYPT':
      return handleNIP04(request, cachedPassword);

    case 'NOSTR_NIP44_ENCRYPT':
    case 'NOSTR_NIP44_DECRYPT':
      return handleNIP44(request, cachedPassword);

    default:
      throw new Error('Unknown method: ' + request.type);
  }
}

// ============================================================
// Domain-Zugriffskontrolle mit Bootstrapping
// ============================================================
async function checkDomainAccess(domain) {
  if (!domain) return 'blocked';

  const { allowedDomains = [], blockedDomains = [] } =
    await chrome.storage.local.get(['allowedDomains', 'blockedDomains']);

  if (blockedDomains.includes(domain)) return 'blocked';
  if (allowedDomains.includes(domain)) return 'allowed';

  // Domain ist noch unbekannt -> User fragen (Bootstrapping)
  return 'pending';
}

async function promptDomainApproval(domain) {
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=domain&domain=${encodeURIComponent(domain)}`,
      type: 'popup', width: 450, height: 350, focused: true
    }, (window) => {
      // Dialog kommuniziert Ergebnis über chrome.storage
      const listener = (changes) => {
        if (changes.domainApprovalResult) {
          chrome.storage.onChanged.removeListener(listener);
          const { domain: d, allowed } = changes.domainApprovalResult.newValue;
          if (d === domain) resolve(allowed);
        }
      };
      chrome.storage.onChanged.addListener(listener);
    });
  });
}

async function isDomainAllowed(domain) {
  const status = await checkDomainAccess(domain);
  return status === 'allowed';
}

async function updateDomainWhitelist() {
  try {
    const { primaryDomain } = await chrome.storage.local.get('primaryDomain');
    if (!primaryDomain) return;

    const response = await fetch(`https://${primaryDomain}/wp-json/nostr/v1/domains`);
    const data = await response.json();

    // Signatur der Domain-Liste verifizieren (HMAC mit shared secret)
    if (!data.signature || !await verifyDomainSignature(data)) {
      console.error('Domain list signature invalid');
      return;
    }

    await chrome.storage.local.set({
      allowedDomains: data.domains,
      lastDomainUpdate: Date.now()
    });
  } catch (e) {
    console.error('Failed to update domains:', e);
  }
}

// ============================================================
// UI-Dialoge
// ============================================================
async function promptPassword(mode) {
  // Öffnet dialog.html?type=password&mode=create|unlock
  // Gibt Passwort via chrome.storage.session zurück
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=password&mode=${mode}`,
      type: 'popup', width: 400, height: 300, focused: true
    });
    const listener = (changes) => {
      if (changes.passwordResult) {
        chrome.storage.onChanged.removeListener(listener);
        resolve(changes.passwordResult.newValue);
        // Sofort aus Storage löschen
        chrome.storage.session.remove('passwordResult');
      }
    };
    chrome.storage.onChanged.addListener(listener);
  });
}

async function promptSignConfirmation(event, domain) {
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=confirm&domain=${encodeURIComponent(domain)}&kind=${event.kind}`,
      type: 'popup', width: 500, height: 400, focused: true
    });
    const listener = (changes) => {
      if (changes.signConfirmResult) {
        chrome.storage.onChanged.removeListener(listener);
        resolve(changes.signConfirmResult.newValue);
      }
    };
    chrome.storage.onChanged.addListener(listener);
  });
}

async function openBackupDialog(npub, nsecBech32) {
  await chrome.windows.create({
    url: `dialog.html?type=backup&npub=${encodeURIComponent(npub)}&nsec=${encodeURIComponent(nsecBech32)}`,
    type: 'popup',
    width: 500,
    height: 600,
    focused: true
  });
}

// ============================================================
// Semver-Vergleich
// ============================================================
function semverSatisfies(current, minimum) {
  if (!minimum) return true;
  const parse = (v) => v.split('.').map(Number);
  const [cMajor, cMinor, cPatch] = parse(current);
  const [mMajor, mMinor, mPatch] = parse(minimum);
  if (cMajor !== mMajor) return cMajor > mMajor;
  if (cMinor !== mMinor) return cMinor > mMinor;
  return cPatch >= mPatch;
}

// ============================================================
// Domain-Signatur-Verifikation (Platzhalter)
// ============================================================
async function verifyDomainSignature(data) {
  // TODO: HMAC-SHA256 mit shared secret verifizieren
  // Das shared secret wird beim ersten Handshake WP <-> Extension ausgetauscht
  return true; // Temporär: immer akzeptieren (vor Production implementieren!)
}

// ============================================================
// Alarm: Periodisches Domain-Sync
// ============================================================
chrome.alarms.create('domainSync', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'domainSync') updateDomainWhitelist();
});
```

**dialog.html** (Backup/Confirm Dialoge)
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="dialog.css">
</head>
<body>
  <div id="app">
    <!-- Dynamisch via JS gefüllt -->
  </div>
  <script src="dialog.js"></script>
</body>
</html>
```

**dialog.js** (Dialog Logik)
```javascript
const params = new URLSearchParams(window.location.search);
const type = params.get('type');

switch (type) {
  case 'backup':
    showBackupDialog(params.get('npub'), params.get('nsec'));
    break;
  case 'password':
    showPasswordDialog(params.get('mode'));
    break;
  case 'domain':
    showDomainApprovalDialog(params.get('domain'));
    break;
  case 'confirm':
    showConfirmDialog(params.get('domain'), Number(params.get('kind')));
    break;
}

function showBackupDialog(npub, nsec) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog backup">
      <h2>🔐 Dein Nostr Schlüsselpaar</h2>
      <p class="warning">⚠️ WICHTIG: Speichere deinen privaten Schlüssel JETZT!
      Er wird nach Schließen dieses Dialogs nicht mehr angezeigt.</p>
      
      <div class="key-box">
        <label>Öffentlicher Schlüssel (Npub):</label>
        <code id="npub-display">${npub}</code>
        <button onclick="copyToClipboard('npub-display')">Kopieren</button>
      </div>
      
      <div class="key-box nsec-box">
        <label>Privater Schlüssel (Nsec) – GEHEIM HALTEN:</label>
        <code id="nsec-display" class="blurred">${nsec}</code>
        <button onclick="toggleVisibility('nsec-display')">Anzeigen</button>
        <button onclick="copyToClipboard('nsec-display')">Kopieren</button>
      </div>
      
      <div class="actions">
        <button id="download" class="primary">Schlüssel als Datei speichern</button>
        <label><input type="checkbox" id="confirm-saved" />
          Ich habe meinen privaten Schlüssel sicher gespeichert</label>
        <button id="close" class="secondary" disabled>Weiter</button>
      </div>
      
      <p class="hint">Ohne den privaten Schlüssel kannst du dein Konto
      nicht wiederherstellen. Es gibt keinen "Passwort vergessen"-Mechanismus.</p>
    </div>
  `;

  // Weiter-Button erst nach Checkbox aktiv
  document.getElementById('confirm-saved').onchange = (e) => {
    document.getElementById('close').disabled = !e.target.checked;
  };
  
  document.getElementById('download').onclick = () => {
    const blob = new Blob(
      [`Nostr Schlüssel-Backup\n==================\n\nNpub: ${npub}\nNsec: ${nsec}\n\n⚠️ NIEMALS TEILEN!`],
      { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'nostr-backup.txt'; a.click();
    URL.revokeObjectURL(url);
  };
  
  document.getElementById('close').onclick = () => window.close();
}

function showPasswordDialog(mode) {
  const app = document.getElementById('app');
  const isCreate = mode === 'create';
  app.innerHTML = `
    <div class="dialog password">
      <h2>${isCreate ? '🔑 Passwort festlegen' : '🔓 Extension entsperren'}</h2>
      <p>${isCreate
        ? 'Dieses Passwort schützt deinen privaten Schlüssel.'
        : 'Gib dein Passwort ein um fortzufahren.'}</p>
      
      <input type="password" id="password" placeholder="Passwort" autofocus />
      ${isCreate ? '<input type="password" id="password-confirm" placeholder="Passwort wiederholen" />' : ''}
      <p id="error" class="error" hidden></p>
      
      <div class="actions">
        <button id="submit" class="primary">${isCreate ? 'Festlegen' : 'Entsperren'}</button>
        <button id="cancel" class="secondary">Abbrechen</button>
      </div>
    </div>
  `;

  document.getElementById('submit').onclick = async () => {
    const pw = document.getElementById('password').value;
    if (isCreate) {
      const pw2 = document.getElementById('password-confirm').value;
      if (pw !== pw2) {
        document.getElementById('error').textContent = 'Passwörter stimmen nicht überein';
        document.getElementById('error').hidden = false;
        return;
      }
      if (pw.length < 8) {
        document.getElementById('error').textContent = 'Mindestens 8 Zeichen';
        document.getElementById('error').hidden = false;
        return;
      }
    }
    await chrome.storage.session.set({ passwordResult: pw });
    window.close();
  };
  document.getElementById('cancel').onclick = () => {
    chrome.storage.session.set({ passwordResult: null });
    window.close();
  };
}

function showDomainApprovalDialog(domain) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog domain">
      <h2>🌐 Neue Domain</h2>
      <p>Die Webseite <strong>${domain}</strong> möchte auf deine Nostr-Identität zugreifen.</p>
      <p>Möchtest du dieser Domain vertrauen?</p>
      
      <div class="actions">
        <button id="allow" class="primary">Erlauben</button>
        <button id="deny" class="secondary">Ablehnen</button>
        <label><input type="checkbox" id="remember" checked /> Entscheidung merken</label>
      </div>
    </div>
  `;

  const respond = async (allowed) => {
    const remember = document.getElementById('remember').checked;
    if (remember) {
      const storageKey = allowed ? 'allowedDomains' : 'blockedDomains';
      const { [storageKey]: list = [] } = await chrome.storage.local.get(storageKey);
      list.push(domain);
      await chrome.storage.local.set({ [storageKey]: list });
    }
    await chrome.storage.local.set({
      domainApprovalResult: { domain, allowed }
    });
    window.close();
  };

  document.getElementById('allow').onclick = () => respond(true);
  document.getElementById('deny').onclick = () => respond(false);
}

function showConfirmDialog(domain, kind) {
  const kindNames = { 0: 'Profil-Metadaten', 3: 'Kontaktliste', 4: 'Verschlüsselte Nachricht' };
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog confirm">
      <h2>✍️ Signatur-Anfrage</h2>
      <p><strong>${domain}</strong> möchte ein Event signieren:</p>
      <div class="event-info">
        <span class="kind">Kind ${kind}: ${kindNames[kind] || 'Unbekannt'}</span>
      </div>
      <p class="warning">⚠️ Dies ist ein sensitiver Event-Typ. Bitte prüfe sorgfältig.</p>
      
      <div class="actions">
        <button id="confirm" class="primary">Signieren</button>
        <button id="reject" class="secondary">Ablehnen</button>
      </div>
    </div>
  `;

  document.getElementById('confirm').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: true });
    window.close();
  };
  document.getElementById('reject').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: false });
    window.close();
  };
}

// --- Hilfsfunktionen ---
function copyToClipboard(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text);
}
function toggleVisibility(elementId) {
  document.getElementById(elementId).classList.toggle('blurred');
}
```

### Akzeptanzkriterien
- [ ] Key wird nur einmal generiert
- [ ] Backup-Dialog öffnet automatisch nach Generierung
- [ ] Nsec wird nie unverschlüsselt gespeichert
- [ ] Signatur-Requests zeigen Domain-Herkunft

---

## TASK 4: NIP-04 & NIP-44 Encryption

### Ziel
Verschlüsselte Nachrichten entsprechend NIP-04 (Legacy) und NIP-44 (Recommended) Standard.

**Erweiterung background.js** (wird ins gebundelte background.js integriert)

> **Hinweis:** NIP-04 ist deprecated zugunsten von NIP-17/NIP-44.
> Wird hier nur für Abwärtskompatibilität bereitgestellt.

```javascript
import { nip04 } from 'nostr-tools';
import { v2 as nip44 } from 'nostr-tools/nip44';

async function handleNIP04(request, password) {
  const secretKey = await keyManager.getKey(password);
  if (!secretKey) throw new Error('Key not available');

  const { pubkey, plaintext, ciphertext } = request.payload;

  try {
    if (request.type === 'NOSTR_NIP04_ENCRYPT') {
      // nip04.encrypt erwartet hex-privkey, hex-pubkey, plaintext
      const encrypted = await nip04.encrypt(secretKey, pubkey, plaintext);
      return encrypted; // NIP-07: gibt ciphertext-string zurück
    } else {
      const decrypted = await nip04.decrypt(secretKey, pubkey, ciphertext);
      return decrypted; // NIP-07: gibt plaintext-string zurück
    }
  } finally {
    secretKey.fill(0);
  }
}

async function handleNIP44(request, password) {
  const secretKey = await keyManager.getKey(password);
  if (!secretKey) throw new Error('Key not available');

  const { pubkey, plaintext, ciphertext } = request.payload;

  try {
    // NIP-44 v2: Erst Conversation Key ableiten, dann encrypt/decrypt
    const conversationKey = nip44.utils.getConversationKey(
      secretKey, pubkey
    );

    if (request.type === 'NOSTR_NIP44_ENCRYPT') {
      const encrypted = nip44.encrypt(plaintext, conversationKey);
      return encrypted; // NIP-07: gibt ciphertext-string zurück
    } else {
      const decrypted = nip44.decrypt(ciphertext, conversationKey);
      return decrypted; // NIP-07: gibt plaintext-string zurück
    }
  } finally {
    secretKey.fill(0);
  }
}
```

### Akzeptanzkriterien
- [ ] NIP-04 Kompatibilität mit bestehenden Clients
- [ ] NIP-44 als Standard für neue Implementierungen
- [ ] Automatische Algorithmus-Erkennung beim Decrypt

---

## TASK 5: Multi-Domain Whitelist Management

### Ziel
Automatische Synchronisation erlaubter Domains über alle WordPress-Instanzen.

**WordPress Admin Interface**
```php
// Admin Settings Page
add_action('admin_menu', 'nostr_admin_menu');

function nostr_admin_menu() {
    add_options_page(
        'Nostr Einstellungen',
        'Nostr',
        'manage_options',
        'nostr-settings',
        'nostr_settings_page'
    );
}

function nostr_settings_page() {
    ?>
    <div class="wrap">
        <h1>Nostr Integration</h1>
        
        <form method="post" action="options.php">
            <?php settings_fields('nostr_options'); ?>
            
            <table class="form-table">
                <tr>
                    <th>Primäre Domain</th>
                    <td>
                        <input type="text" name="nostr_primary_domain" 
                               value="<?php echo esc_attr(get_option('nostr_primary_domain')); ?>" />
                        <p class="description">Hauptdomain für Extension-Updates</p>
                    </td>
                </tr>
                <tr>
                    <th>Erlaubte Domains</th>
                    <td>
                        <textarea name="nostr_allowed_domains" rows="5" cols="50"><?php 
                            echo esc_textarea(implode("\n", get_option('nostr_allowed_domains', []))); 
                        ?></textarea>
                        <p class="description">Eine Domain pro Zeile</p>
                    </td>
                </tr>
            </table>
            
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}
```

**Extension Domain Sync**
```javascript
// background.js - Domain Synchronisation (mit Signatur-Verifikation)

async function syncDomainsFromWordPress() {
  const { wordpressSites = [] } = await chrome.storage.local.get('wordpressSites');
  
  for (const site of wordpressSites) {
    try {
      const response = await fetch(`${site}/wp-json/nostr/v1/domains`);
      const data = await response.json();
      
      // Domain-Signatur verifizieren (verhindert Injection durch Dritte)
      if (!data.signature || !await verifyDomainSignature(data)) {
        console.error(`Invalid signature from ${site}, skipping`);
        continue;
      }
      
      // Merge mit bestehenden Domains
      const { allowedDomains = [] } = await chrome.storage.local.get('allowedDomains');
      const merged = [...new Set([...allowedDomains, ...data.domains])];
      
      await chrome.storage.local.set({
        allowedDomains: merged,
        lastDomainUpdate: Date.now()
      });
    } catch (e) {
      console.error(`Failed to sync ${site}:`, e);
    }
  }
}

// Regelmäßiges Sync (alle 5 Minuten)
chrome.alarms.create('domainSync', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'domainSync') syncDomainsFromWordPress();
});
```

### Akzeptanzkriterien
- [ ] Admin kann Domains in WordPress verwalten
- [ ] Extension aktualisiert Whitelist automatisch
- [ ] Neue WordPress-Instanzen werden erkannt
- [ ] User kann manuell Domains hinzufügen (Fallback)

---

## TASK 6: Extension Update Mechanismus

### Ziel
Benachrichtigung über neue Versionen und forced updates bei Sicherheitskritischen Änderungen.

**WordPress Update Check**
```javascript
// In WordPress: Prüfe Extension Version
async function checkExtensionVersion() {
  const minVersion = '1.0.0'; // Aus WordPress Option
  
  const hasExtension = await detectExtension();
  if (!hasExtension) return;
  
  // Ping mit Versionsprüfung
  window.postMessage({ 
    type: 'NOSTR_CHECK_VERSION',
    minVersion: minVersion 
  }, '*');
  
  window.addEventListener('message', (e) => {
    if (e.data.type === 'NOSTR_VERSION_RESPONSE') {
      if (e.data.version !== minVersion) {
        showUpdatePrompt(e.data.version, minVersion);
      }
    }
  });
}
```

**Extension Version Handler**
```javascript
// background.js - wird im handleMessage switch bereits behandelt
// NOSTR_CHECK_VERSION nutzt semverSatisfies() aus background.js
// Kein separater Handler nötig, da bereits in handleMessage integriert.
```

### Akzeptanzkriterien
- [ ] WordPress kann minimale Extension-Version vorgeben
- [ ] User wird bei veralteter Extension benachrichtigt
- [ ] Semantischer Versionsvergleich (1.1.0 > 1.0.0)
- [ ] Update-Link führt direkt zum Chrome Web Store

---

## TASK 7: Build Pipeline & Browser-Kompatibilität

### Ziel
nostr-tools als ES Module in MV3 Service Worker bundeln. Chrome + Firefox Kompatibilität.

**package.json**
```json
{
  "name": "wp-nostr-nip7-extension",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "build": "rollup -c",
    "build:watch": "rollup -c --watch",
    "build:firefox": "rollup -c --environment TARGET:firefox",
    "package:chrome": "npm run build && cd dist/chrome && zip -r ../../wp-nostr-chrome.zip .",
    "package:firefox": "npm run build:firefox && cd dist/firefox && zip -r ../../wp-nostr-firefox.zip ."
  },
  "devDependencies": {
    "@rollup/plugin-node-resolve": "^15.0.0",
    "@rollup/plugin-commonjs": "^25.0.0",
    "rollup": "^4.0.0",
    "rollup-plugin-copy": "^3.5.0"
  },
  "dependencies": {
    "nostr-tools": "^2.7.0"
  }
}
```

**rollup.config.js**
```javascript
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import copy from 'rollup-plugin-copy';

const isFirefox = process.env.TARGET === 'firefox';
const outDir = isFirefox ? 'dist/firefox' : 'dist/chrome';

export default [
  // Background (Service Worker) – nostr-tools muss gebundelt werden
  {
    input: 'src/background.js',
    output: { file: `${outDir}/background.js`, format: 'es' },
    plugins: [resolve({ browser: true }), commonjs()]
  },
  // Inpage Script – läuft im MAIN world der Webseite
  {
    input: 'src/inpage.js',
    output: { file: `${outDir}/inpage.js`, format: 'iife' },
    plugins: []
  }
];

// Content Script, Dialog JS, Popup JS werden direkt kopiert (keine ES-Imports)
// Siehe copy-Plugin in den Build-Targets
```

**Projektstruktur**
```text
src/
├── background.js        # Service Worker (importiert nostr-tools)
├── content.js           # Bridge Script (kein Bundling nötig)
├── inpage.js            # NIP-07 API (IIFE, kein Import)
├── dialog.js            # Dialog-Logik
├── dialog.html
├── dialog.css
├── popup.html           # Extension Popup
├── popup.js
├── popup.css
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
├── manifest.chrome.json # Chrome MV3 Manifest
└── manifest.firefox.json # Firefox MV3 Manifest (background.scripts statt service_worker)
```

**manifest.firefox.json** (Firefox-Unterschiede)
```json
{
  "manifest_version": 3,
  "name": "WordPress Nostr Signer",
  "version": "1.0.0",
  "background": {
    "scripts": ["background.js"],
    "type": "module"
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "nostr-signer@wordpress.org",
      "strict_min_version": "109.0"
    }
  }
}
```

### Build-Hinweise
- `nostr-tools` verwendet `@noble/curves` und `@noble/hashes` – beides muss durch Rollup aufgelöst werden
- Firefox MV3 unterstützt `background.scripts[]` statt `service_worker`
- `inpage.js` wird als IIFE gebundelt (kein Modul-Support im MAIN world)
- `content.js` braucht kein Bundling (nutzt nur Chrome/Browser APIs)

### Akzeptanzkriterien
- [ ] `npm run build` erzeugt lauffähige Extension in `dist/chrome/`
- [ ] `npm run build:firefox` erzeugt Firefox-kompatible Extension
- [ ] nostr-tools Imports sind im Bundle aufgelöst (keine bare specifiers)
- [ ] Extension lädt in Chrome und Firefox ohne Fehler

---

## TASK 8: Popup UI

### Ziel
Extension Popup für Status-Anzeige und Einstellungen.

**popup.html**
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="popup.css">
</head>
<body>
  <div id="popup">
    <header>
      <h1>⚡ Nostr Signer</h1>
      <span id="version" class="badge"></span>
    </header>
    
    <div id="status">
      <!-- Dynamisch: locked/unlocked/no-key -->
    </div>
    
    <div id="key-info" hidden>
      <label>Dein Public Key:</label>
      <code id="pubkey-display"></code>
      <button id="copy-pubkey">Kopieren</button>
    </div>
    
    <div id="domains-section">
      <h3>Erlaubte Domains</h3>
      <ul id="domain-list"></ul>
      <button id="manage-domains">Verwalten</button>
    </div>
    
    <div id="relay-section">
      <h3>Relays</h3>
      <ul id="relay-list"></ul>
      <button id="add-relay">Relay hinzufügen</button>
    </div>
    
    <footer>
      <button id="lock-btn">Sperren</button>
      <button id="settings-btn">Einstellungen</button>
    </footer>
  </div>
  <script src="popup.js"></script>
</body>
</html>
```

**popup.js**
```javascript
document.addEventListener('DOMContentLoaded', async () => {
  const version = document.getElementById('version');
  const status = document.getElementById('status');
  const keyInfo = document.getElementById('key-info');
  
  // Extension-Version anzeigen
  const manifest = chrome.runtime.getManifest();
  version.textContent = `v${manifest.version}`;
  
  // Key-Status prüfen
  const { encrypted_nsec } = await chrome.storage.local.get('encrypted_nsec');
  
  if (!encrypted_nsec) {
    status.innerHTML = '<p class="no-key">Kein Schlüssel vorhanden. Besuche eine WordPress-Seite zur Einrichtung.</p>';
    return;
  }
  
  status.innerHTML = '<p class="locked">🔒 Gesperrt – entsperre über eine verbundene Webseite</p>';
  
  // Domains laden
  const { allowedDomains = [] } = await chrome.storage.local.get('allowedDomains');
  const domainList = document.getElementById('domain-list');
  allowedDomains.forEach(d => {
    const li = document.createElement('li');
    li.textContent = d;
    domainList.appendChild(li);
  });
  
  // Relays laden
  const { relays = {} } = await chrome.storage.local.get('relays');
  const relayList = document.getElementById('relay-list');
  Object.entries(relays).forEach(([url, perms]) => {
    const li = document.createElement('li');
    li.textContent = `${url} (R:${perms.read} W:${perms.write})`;
    relayList.appendChild(li);
  });
  
  // Lock-Button
  document.getElementById('lock-btn').onclick = () => {
    chrome.runtime.sendMessage({ type: 'NOSTR_LOCK' });
    window.close();
  };
  
  // Copy-Button
  document.getElementById('copy-pubkey').onclick = () => {
    const text = document.getElementById('pubkey-display').textContent;
    navigator.clipboard.writeText(text);
  };
});
```

### Akzeptanzkriterien
- [ ] Popup zeigt Key-Status (vorhanden/gesperrt/entsperrt)
- [ ] Erlaubte Domains werden aufgelistet
- [ ] Konfigurierte Relays werden angezeigt
- [ ] Lock-Button sperrt die Extension

---

## Sicherheitsregeln (STRICT)

1. **NSEC REGELN:**
   - Nsec existiert NUR im Extension Storage (AES-GCM verschlüsselt mit User-Passwort)
   - Nsec wird NIE in den Webseiten-Kontext übertragen
   - Nach jeder Verwendung: Memory sofort überschreiben (`fill(0)`)
   - Hinweis: JS Garbage Collection kann Kopien im Speicher belassen – dies ist eine
     inhärente Limitation, die durch kurzlebige Variablen-Scopes minimiert wird

2. **DOMAIN REGELN:**
   - Jede Signatur-Anfrage MUSS Domain-Validierung bestehen
   - Unbekannte Domains lösen User-Consent-Dialog aus (Bootstrapping)
   - Whitelist wird NUR von autorisierten WordPress-Instanzen aktualisiert (HMAC-signiert)
   - User-Bestätigung für neue Domains außerhalb der Whitelist
   - PING und VERSION_CHECK sind ohne Domain-Validierung erlaubt (Extension-Detection)

3. **UI REGELN:**
   - Jede Signatur zeigt klar: WAS wird signiert, WOHER kommt die Anfrage
   - Sensitive Events (Kind 0, 3, 4) erfordern explizite Bestätigung
   - Backup-Dialog zeigt nsec nur einmal und erzwingt Checkbox-Bestätigung
   - Passwort-Dialog muss bei Ersteinrichtung Wiederholung verlangen (min. 8 Zeichen)

4. **KOMMUNIKATION REGELN:**
   - Alle REST-Endpoints verwenden WordPress Nonce-Validierung
   - HTTPS erzwungen für alle Domain-Kommunikationen
   - Keine Inline-Scripts, nur externe JS-Files
   - Message-Bridge nutzt `_id`-Korrelation für Request/Response-Zuordnung
   - Domain-Listen vom Server müssen HMAC-signiert sein

5. **KEY-STORAGE REGELN:**
   - Private Keys werden mit AES-GCM verschlüsselt (PBKDF2 600.000 Iterations)
   - Salt und IV werden separat gespeichert
   - Passwort wird nur im Memory gecacht (Service Worker Session, nicht persistiert)
   - Bei Service-Worker-Neustart muss User Passwort erneut eingeben

---

## Deployment Checkliste

- [ ] `npm run build` erfolgreich (Chrome + Firefox)
- [ ] Extension in Chrome Web Store hochladen ($5 Fee)
- [ ] Extension bei Firefox Add-ons hochladen (kostenlos)
- [ ] Extension ID in WordPress Plugin hinterlegen
- [ ] WordPress Plugin ZIP erstellen und installieren
- [ ] Test-User: Registrierung, Signatur, Domain-Wechsel
- [ ] Test: Domain-Bootstrapping (neue Domain ohne Whitelist)
- [ ] Test: Backup-Dialog Pflicht (nsec Export, Checkbox)
- [ ] Test: Passwort-Unlock nach Service-Worker-Restart
- [ ] Security Audit: XSS, CSRF, Key-Exposure Tests
- [ ] Verify: getPublicKey() gibt hex zurück, signEvent() gibt vollständiges Event zurück

---

## Ressourcen

- NIP-07: https://github.com/nostr-protocol/nips/blob/master/07.md
- NIP-44: https://github.com/nostr-protocol/nips/blob/master/44.md
- nostr-tools: https://github.com/nbd-wtf/nostr-tools
- WebExtension API: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions
```

---

## Nächste Schritte

1. Kopiere den obigen Inhalt in eine Datei namens `AGENTS.md`
2. Speichere sie in deinem Projekt-Root
3. Ein Agent kann damit die einzelnen Tasks abarbeiten

