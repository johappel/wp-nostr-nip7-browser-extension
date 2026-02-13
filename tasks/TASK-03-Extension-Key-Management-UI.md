# TASK-03: Extension Key-Management & UI

## Hinweis zum Iststand (2026-02)

Historisches Task-Dokument. Teile der gezeigten Message-Handler sind inzwischen obsolet.

- `NOSTR_CHECK_VERSION` entfernt
- `NOSTR_LOCK` entfernt

Aktueller Einstieg ohne Domain-Validierung bleibt `NOSTR_PING`; der aktive Handler-Satz ist in [API-Referenz.md](../API-Referenz.md) dokumentiert.

## Ziel
Sichere Key-Generierung, Storage und Backup-Dialog. Implementierung der NIP-07 API Methoden im Background Script.

## Abhängigkeiten
- **TASK-01: Extension Grundgerüst** muss abgeschlossen sein
- **TASK-07: Build Pipeline** muss abgeschlossen sein (für nostr-tools Bundling)

## Ergebnis
Nach Abschluss dieses Tasks:
- Private Key wird AES-GCM verschlüsselt gespeichert
- Passwort-Dialog für Ersteinrichtung und Entsperren
- Backup-Dialog zeigt nsec nur einmal an
- `getPublicKey` und `signEvent` funktionieren gemäß NIP-07 Spec

---

## Zu erstellende Dateien

### 1. lib/key-manager.js

**Pfad:** `src/lib/key-manager.js`

```javascript
// Key Manager – AES-GCM verschlüsselter Storage
// Extrahiert für bessere Testbarkeit

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';

export class KeyManager {
  // Storage Keys
  static STORAGE_KEY = 'encrypted_nsec';
  static SALT_KEY   = 'encryption_salt';
  static IV_KEY     = 'encryption_iv';
  
  constructor(storage = chrome.storage.local) {
    this.storage = storage;
  }

  async hasKey() {
    const result = await this.storage.get([KeyManager.STORAGE_KEY]);
    return !!result[KeyManager.STORAGE_KEY];
  }

  /**
   * Generiert einen neuen Schlüssel und speichert ihn verschlüsselt
   * @param {string} password - Passwort für Verschlüsselung
   * @returns {Promise<{pubkey: string, npub: string, nsecBech32: string}>}
   */
  async generateKey(password) {
    const secretKey = generateSecretKey();          // Uint8Array (32 bytes)
    const pubkey    = getPublicKey(secretKey);       // hex string
    const npub      = nip19.npubEncode(pubkey);
    const nsecBech32 = nip19.nsecEncode(secretKey);

    await this.storeKey(secretKey, password);
    secretKey.fill(0);                              // Memory wipe

    return { pubkey, npub, nsecBech32 };
  }

  /**
   * Speichert Secret Key AES-GCM verschlüsselt
   * @param {Uint8Array} secretKey - 32-byte secret key
   * @param {string} password - Passwort für Verschlüsselung
   */
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

    await this.storage.set({
      [KeyManager.STORAGE_KEY]: Array.from(new Uint8Array(ciphertext)),
      [KeyManager.SALT_KEY]:    Array.from(salt),
      [KeyManager.IV_KEY]:      Array.from(iv),
      created: Date.now()
    });
  }

  /**
   * Entschlüsselt und lädt Secret Key
   * @param {string} password - Passwort für Entschlüsselung
   * @returns {Promise<Uint8Array|null>} - 32-byte secret key oder null
   */
  async getKey(password) {
    const result = await this.storage.get([
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

  /**
   * Signiert ein Event
   * @param {object} eventTemplate - Event ohne id, pubkey, sig
   * @param {string} password - Passwort zum Entschlüsseln
   * @returns {Promise<object>} - Vollständiges signiertes Event
   */
  async signEvent(eventTemplate, password) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    // finalizeEvent fügt id, pubkey, sig hinzu und gibt vollständiges Event zurück
    const signed = finalizeEvent(eventTemplate, secretKey);
    secretKey.fill(0);

    return signed; // { id, pubkey, created_at, kind, tags, content, sig }
  }

  /**
   * Erfragt Public Key
   * @param {string} password - Passwort zum Entschlüsseln
   * @returns {Promise<string>} - Hex-String des Public Keys
   */
  async getPublicKey(password) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    const pubkey = getPublicKey(secretKey);
    secretKey.fill(0);
    
    return pubkey; // Hex-String (64 chars)
  }
}

export default KeyManager;
```

### 2. lib/domain-access.js

**Pfad:** `src/lib/domain-access.js`

```javascript
// Domain Access Control mit Bootstrapping

export const DOMAIN_STATUS = {
  BLOCKED: 'blocked',
  ALLOWED: 'allowed',
  PENDING: 'pending'
};

/**
 * Prüft Domain-Status
 * @param {string|null} domain - Zu prüfende Domain
 * @param {object} storage - Chrome storage API
 * @returns {Promise<string>} - DOMAIN_STATUS
 */
export async function checkDomainAccess(domain, storage = chrome.storage.local) {
  if (!domain) return DOMAIN_STATUS.BLOCKED;

  const { allowedDomains = [], blockedDomains = [] } =
    await storage.get(['allowedDomains', 'blockedDomains']);

  if (blockedDomains.includes(domain)) return DOMAIN_STATUS.BLOCKED;
  if (allowedDomains.includes(domain)) return DOMAIN_STATUS.ALLOWED;

  // Domain ist noch unbekannt -> User fragen (Bootstrapping)
  return DOMAIN_STATUS.PENDING;
}

/**
 * Fügt Domain zur Allowlist hinzu
 * @param {string} domain - Domain hinzuzufügen
 * @param {object} storage - Chrome storage API
 */
export async function allowDomain(domain, storage = chrome.storage.local) {
  const { allowedDomains = [] } = await storage.get(['allowedDomains']);
  if (!allowedDomains.includes(domain)) {
    allowedDomains.push(domain);
    await storage.set({ allowedDomains });
  }
}

/**
 * Fügt Domain zur Blocklist hinzu
 * @param {string} domain - Domain hinzuzufügen
 * @param {object} storage - Chrome storage API
 */
export async function blockDomain(domain, storage = chrome.storage.local) {
  const { blockedDomains = [] } = await storage.get(['blockedDomains']);
  if (!blockedDomains.includes(domain)) {
    blockedDomains.push(domain);
    await storage.set({ blockedDomains });
  }
}

export default checkDomainAccess;
```

### 3. lib/semver.js

**Pfad:** `src/lib/semver.js`

```javascript
// Semver-Vergleich für Version-Checking

/**
 * Vergleicht aktuelle Version mit minimaler Version
 * @param {string} current - Aktuelle Version (z.B. "1.0.0")
 * @param {string} minimum - Minimale Version (z.B. "1.0.0")
 * @returns {boolean} - true wenn current >= minimum
 */
export function semverSatisfies(current, minimum) {
  if (!minimum) return true;
  
  const parse = (v) => v.split('.').map(Number);
  const [cMajor, cMinor, cPatch] = parse(current);
  const [mMajor, mMinor, mPatch] = parse(minimum);
  
  if (cMajor !== mMajor) return cMajor > mMajor;
  if (cMinor !== mMinor) return cMinor > mMinor;
  return cPatch >= mPatch;
}

export default semverSatisfies;
```

### 4. background.js (vollständig)

**Pfad:** `src/background.js`

```javascript
// Background Service Worker
// Importiert nostr-tools via Rollup Bundle

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';
import { KeyManager } from './lib/key-manager.js';
import { checkDomainAccess, DOMAIN_STATUS, allowDomain, blockDomain } from './lib/domain-access.js';
import { semverSatisfies } from './lib/semver.js';

const CURRENT_VERSION = '1.0.0';

// Global KeyManager Instance
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

  // Hinweis (Iststand):
  // - NOSTR_CHECK_VERSION wurde entfernt
  // - NOSTR_LOCK wurde entfernt

  // Domain-Validierung mit Bootstrapping
  const domainStatus = await checkDomainAccess(domain);
  if (domainStatus === DOMAIN_STATUS.BLOCKED) {
    throw new Error('Domain not authorized');
  }
  if (domainStatus === DOMAIN_STATUS.PENDING) {
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
      if (!secretKey) throw new Error('Invalid password');
      
      const pubkey = getPublicKey(secretKey);
      secretKey.fill(0);
      // NIP-07: gibt hex-String zurück (NICHT npub)
      return pubkey;
    }

    case 'NOSTR_SIGN_EVENT': {
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
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
      // Wird in TASK-04 implementiert
      throw new Error('NIP-04 not yet implemented');

    case 'NOSTR_NIP44_ENCRYPT':
    case 'NOSTR_NIP44_DECRYPT':
      // Wird in TASK-04 implementiert
      throw new Error('NIP-44 not yet implemented');

    default:
      throw new Error('Unknown method: ' + request.type);
  }
}

// ============================================================
// UI-Dialoge
// ============================================================

async function promptPassword(mode) {
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=password&mode=${mode}`,
      type: 'popup', width: 400, height: 350, focused: true
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
        chrome.storage.local.remove('signConfirmResult');
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
    height: 650,
    focused: true
  });
}

async function promptDomainApproval(domain) {
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=domain&domain=${encodeURIComponent(domain)}`,
      type: 'popup', width: 450, height: 350, focused: true
    });
    
    const listener = (changes) => {
      if (changes.domainApprovalResult) {
        chrome.storage.onChanged.removeListener(listener);
        const { domain: d, allowed } = changes.domainApprovalResult.newValue;
        if (d === domain) {
          resolve(allowed);
          chrome.storage.local.remove('domainApprovalResult');
        }
      }
    };
    chrome.storage.onChanged.addListener(listener);
  });
}

// ============================================================
// Domain Sync (wird in TASK-05 ausgebaut)
// ============================================================
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

### 5. dialog.html

**Pfad:** `src/dialog.html` (ersetzt die vorhandene Stub-Datei)

```html
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nostr Signer</title>
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

### 6. dialog.js

**Pfad:** `src/dialog.js`

```javascript
// Dialog-Logik für Backup, Password und Confirmation

const params = new URLSearchParams(window.location.search);
const type = params.get('type');

document.addEventListener('DOMContentLoaded', () => {
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
    default:
      document.getElementById('app').innerHTML = '<p>Unbekannter Dialog-Typ</p>';
  }
});

function showBackupDialog(npub, nsec) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog backup">
      <h2>🔐 Dein Nostr Schlüsselpaar</h2>
      <p class="warning">⚠️ WICHTIG: Speichere deinen privaten Schlüssel JETZT!
      Er wird nach Schließen dieses Dialogs nicht mehr angezeigt.</p>
      
      <div class="key-box">
        <label>Öffentlicher Schlüssel (Npub):</label>
        <code id="npub-display">${escapeHtml(npub)}</code>
        <button onclick="copyToClipboard('npub-display')" class="btn-secondary">Kopieren</button>
      </div>
      
      <div class="key-box nsec-box">
        <label>Privater Schlüssel (Nsec) – GEHEIM HALTEN:</label>
        <code id="nsec-display" class="blurred">${escapeHtml(nsec)}</code>
        <div class="btn-group">
          <button onclick="toggleVisibility('nsec-display')" class="btn-secondary">Anzeigen</button>
          <button onclick="copyToClipboard('nsec-display')" class="btn-secondary">Kopieren</button>
        </div>
      </div>
      
      <div class="actions">
        <button id="download" class="btn-primary">
          💾 Schlüssel als Datei speichern
        </button>
        <label class="checkbox-label">
          <input type="checkbox" id="confirm-saved" />
          Ich habe meinen privaten Schlüssel sicher gespeichert
        </label>
        <button id="close" class="btn-primary" disabled>🔒 Weiter</button>
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
      [`Nostr Schlüssel-Backup\n==================\n\nNpub: ${npub}\nNsec: ${nsec}\n\n⚠️ NIEMALS TEILEN!\n`],
      { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nostr-backup-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
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
        ? 'Dieses Passwort schützt deinen privaten Schlüssel. Mindestens 8 Zeichen.'
        : 'Gib dein Passwort ein, um fortzufahren.'}</p>
      
      <div class="input-group">
        <input type="password" id="password" placeholder="Passwort" autofocus />
      </div>
      
      ${isCreate ? `
        <div class="input-group">
          <input type="password" id="password-confirm" placeholder="Passwort wiederholen" />
        </div>
      ` : ''}
      
      <p id="error" class="error" hidden></p>
      
      <div class="actions">
        <button id="submit" class="btn-primary">${isCreate ? 'Festlegen' : 'Entsperren'}</button>
        <button id="cancel" class="btn-secondary">Abbrechen</button>
      </div>
    </div>
  `;

  document.getElementById('submit').onclick = async () => {
    const pw = document.getElementById('password').value;
    const errorEl = document.getElementById('error');
    
    if (isCreate) {
      const pw2 = document.getElementById('password-confirm').value;
      if (pw !== pw2) {
        errorEl.textContent = '❌ Passwörter stimmen nicht überein';
        errorEl.hidden = false;
        return;
      }
      if (pw.length < 8) {
        errorEl.textContent = '❌ Mindestens 8 Zeichen erforderlich';
        errorEl.hidden = false;
        return;
      }
    }
    
    if (!pw) {
      errorEl.textContent = '❌ Passwort erforderlich';
      errorEl.hidden = false;
      return;
    }
    
    await chrome.storage.session.set({ passwordResult: pw });
    window.close();
  };
  
  document.getElementById('cancel').onclick = () => {
    chrome.storage.session.set({ passwordResult: null });
    window.close();
  };
  
  // Enter-Taste unterstützt
  document.getElementById('password').onkeypress = (e) => {
    if (e.key === 'Enter') document.getElementById('submit').click();
  };
  if (isCreate) {
    document.getElementById('password-confirm').onkeypress = (e) => {
      if (e.key === 'Enter') document.getElementById('submit').click();
    };
  }
}

function showDomainApprovalDialog(domain) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog domain">
      <h2>🌐 Neue Domain</h2>
      <p>Die Webseite <strong>${escapeHtml(domain)}</strong> möchte auf deine Nostr-Identität zugreifen.</p>
      <p>Möchtest du dieser Domain vertrauen?</p>
      
      <div class="actions">
        <button id="allow" class="btn-primary">✓ Erlauben</button>
        <button id="deny" class="btn-secondary">✗ Ablehnen</button>
        <label class="checkbox-label">
          <input type="checkbox" id="remember" checked />
          Entscheidung für diese Domain merken
        </label>
      </div>
    </div>
  `;

  const respond = async (allowed) => {
    const remember = document.getElementById('remember').checked;
    
    if (remember) {
      const storageKey = allowed ? 'allowedDomains' : 'blockedDomains';
      const { [storageKey]: list = [] } = await chrome.storage.local.get(storageKey);
      if (!list.includes(domain)) {
        list.push(domain);
        await chrome.storage.local.set({ [storageKey]: list });
      }
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
  const kindNames = { 
    0: 'Profil-Metadaten', 
    1: 'Text-Notiz',
    3: 'Kontaktliste', 
    4: 'Verschlüsselte Nachricht',
    5: 'Verschlüsselter Event (NIP-17)',
    6: 'Repost',
    7: 'Reaction',
    9735: 'Zap Request'
  };
  const kindName = kindNames[kind] || `Unbekannt (Kind ${kind})`;
  
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog confirm">
      <h2>✍️ Signatur-Anfrage</h2>
      <p><strong>${escapeHtml(domain)}</strong> möchte ein Event signieren:</p>
      <div class="event-info">
        <span class="kind">${kindName}</span>
      </div>
      <p class="warning">⚠️ Dies ist ein sensitiver Event-Typ. Bitte prüfe sorgfältig, ob du dieser Domain vertraust.</p>
      
      <div class="actions">
        <button id="confirm" class="btn-primary">Signieren</button>
        <button id="reject" class="btn-secondary">Ablehnen</button>
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
window.copyToClipboard = function(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    // Visuelles Feedback
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '✓ Kopiert!';
    setTimeout(() => btn.textContent = originalText, 1500);
  });
};

window.toggleVisibility = function(elementId) {
  const el = document.getElementById(elementId);
  el.classList.toggle('blurred');
  const btn = event.target;
  btn.textContent = el.classList.contains('blurred') ? 'Anzeigen' : 'Verbergen';
};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
```

### 7. dialog.css

**Pfad:** `src/dialog.css` (ersetzt die vorhandene Stub-Datei)

```css
/* Dialog Styles */

* {
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  margin: 0;
  padding: 0;
  background: #f5f5f5;
  color: #333;
  line-height: 1.5;
}

.dialog {
  max-width: 480px;
  margin: 0 auto;
  padding: 24px;
  background: white;
  min-height: 100vh;
}

h2 {
  margin: 0 0 16px 0;
  font-size: 20px;
  color: #6441a5;
}

p {
  margin: 0 0 16px 0;
  color: #555;
}

/* Key Boxes */
.key-box {
  background: #f8f9fa;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
}

.key-box label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.key-box code {
  display: block;
  word-break: break-all;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 13px;
  background: #f0f0f0;
  padding: 8px;
  border-radius: 4px;
  margin-bottom: 8px;
  color: #333;
}

.key-box button {
  margin-top: 4px;
}

.nsec-box {
  background: #fff8e1;
  border-color: #ffb300;
}

.nsec-box label {
  color: #f57c00;
}

.blurred {
  filter: blur(4px);
  user-select: none;
}

/* Warning */
.warning {
  background: #fff3cd;
  border: 1px solid #ffc107;
  color: #856404;
  padding: 12px;
  border-radius: 4px;
  font-size: 14px;
}

.event-info {
  background: #e3f2fd;
  padding: 12px 16px;
  border-radius: 4px;
  margin: 12px 0;
}

.kind {
  font-weight: 600;
  color: #1976d2;
}

/* Buttons */
button {
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  transition: all 0.2s;
}

.btn-primary {
  background: #6441a5;
  color: white;
  width: 100%;
}

.btn-primary:hover:not(:disabled) {
  background: #543a8c;
}

.btn-primary:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.btn-secondary {
  background: #e0e0e0;
  color: #333;
}

.btn-secondary:hover {
  background: #d0d0d0;
}

.btn-group {
  display: flex;
  gap: 8px;
}

.btn-group button {
  flex: 1;
}

/* Actions */
.actions {
  margin-top: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* Inputs */
.input-group {
  margin-bottom: 12px;
}

input[type="password"] {
  width: 100%;
  padding: 12px;
  font-size: 16px;
  border: 1px solid #ddd;
  border-radius: 4px;
  transition: border-color 0.2s;
}

input[type="password"]:focus {
  outline: none;
  border-color: #6441a5;
}

/* Checkbox */
.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  cursor: pointer;
  user-select: none;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

/* Error */
.error {
  background: #ffebee;
  color: #c62828;
  padding: 10px 12px;
  border-radius: 4px;
  font-size: 14px;
  margin: 12px 0;
}

/* Hint */
.hint {
  font-size: 12px;
  color: #888;
  margin-top: 16px;
  text-align: center;
}

/* Domain Dialog */
.domain p {
  font-size: 15px;
  margin-bottom: 20px;
}

.domain strong {
  color: #6441a5;
}

/* Responsive */
@media (max-width: 400px) {
  .dialog {
    padding: 16px;
  }
}
```

---

## Sicherheitsregeln für diesen Task

### NSEC REGELN
- Nsec existiert NUR im Extension Storage (AES-GCM verschlüsselt mit User-Passwort)
- Nsec wird NIE in den Webseiten-Kontext übertragen
- Nach jeder Verwendung: Memory sofort überschreiben (`fill(0)`)
- Backup-Dialog zeigt nsec nur einmal an

### KEY-STORAGE REGELN
- Private Keys werden mit AES-GCM verschlüsselt (PBKDF2 600.000 Iterations)
- Salt und IV werden separat gespeichert
- Passwort wird nur im Memory gecacht (Service Worker Session, nicht persistiert)
- Bei Service-Worker-Neustart muss User Passwort erneut eingeben

### UI REGELN
- Wichtig: `getPublicKey()` gibt **hex-String** zurück (NICHT npub)
- `signEvent()` gibt vollständiges Event zurück (mit id, pubkey, sig)
- Passwort-Dialog erzwingt 8 Zeichen Mindestlänge
- Passwort-Wiederholung bei Ersteinrichtung erforderlich

### DOMAIN REGELN
- PING und VERSION_CHECK sind ohne Domain-Validierung erlaubt
- Alle anderen Methoden erfordern Domain-Validierung
- Unbekannte Domains lösen User-Consent-Dialog aus

---

## Akzeptanzkriterien

- [ ] Key wird nur einmal generiert (bei erstem Aufruf)
- [ ] Backup-Dialog öffnet automatisch nach Key-Generierung
- [ ] Nsec wird AES-GCM verschlüsselt gespeichert (PBKDF2 600.000 Iterations)
- [ ] Nsec wird nie unverschlüsselt persistiert
- [ ] Passwort-Dialog fordert mindestens 8 Zeichen
- [ ] Passwort-Dialog verlangt Wiederholung bei Ersteinrichtung
- [ ] `getPublicKey()` gibt hex-String zurück (64 Zeichen)
- [ ] `signEvent()` gibt vollständiges Event zurück (id, pubkey, sig)
- [ ] Signatur-Requests zeigen Domain-Herkunft
- [ ] Domain Bootstrapping funktioniert (Approve/Deny)
- [ ] Memory wipe nach Key-Nutzung (`fill(0)`)
- [ ] Passwort-Cache wird bei Service Worker Neustart gelöscht

---

## Test-Anleitung

### 1. Key-Generierung Test
1. Extension neu installieren (Storage leeren)
2. Auf WordPress-Seite als eingeloggter User gehen
3. "Mit Nostr verknüpfen" klicken
4. Passwort festlegen (min. 8 Zeichen)
5. Backup-Dialog erscheint

### 2. Backup-Dialog Test
1. Nsec erst nach "Anzeigen" sichtbar
2. Checkbox required für Weiter-Button
3. Download funktioniert
4. Nach Schließen: nsec nicht mehr abrufbar

### 3. NIP-07 Konformität Test
```javascript
// In Browser Console:
const pubkey = await window.nostr.getPublicKey();
console.log(pubkey); // Sollte 64 hex chars sein
console.log(pubkey.match(/^[a-f0-9]{64}$/)); // Sollte Match sein

const event = {
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: "Test message"
};

const signed = await window.nostr.signEvent(event);
console.log(signed);
// Sollte enthalten: id, pubkey, created_at, kind, tags, content, sig
```

---

## Nächste Schritte

Nach Abschluss dieses Tasks:
1. **TASK-04: NIP-04 & NIP-44 Encryption** - Verschlüsselung implementieren
2. **TASK-08: Popup UI** - Extension Popup fertigstellen
