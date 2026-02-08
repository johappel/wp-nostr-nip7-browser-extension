# TASK-01: Extension Grundgerüst

## Ziel
Manifest V3 Extension mit Content Script Injection für NIP-07 API.

## Abhängigkeiten
- Keine (erster Task)

## Ergebnis
Nach Abschluss dieses Tasks ist die grundlegende Extension-Struktur vorhanden und `window.nostr` ist auf Webseiten verfügbar.

---

## Zu erstellende Dateien

### 1. manifest.json (Chrome MV3)

**Pfad:** `src/manifest.chrome.json`

```json
{
  "manifest_version": 3,
  "name": "WordPress NIP-07 Nostr Signer",
  "version": "0.0.1",
  "description": "NIP-07 Signer Browser Extension für WordPress Nostr Integration",
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

### 2. content.js (Bridge zwischen Webseite und Background)

**Pfad:** `src/content.js`

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

### 3. inpage.js (NIP-07 API im Webseiten-Kontext)

**Pfad:** `src/inpage.js`

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

### 4. background.js (Stub für spätere Tasks)

**Pfad:** `src/background.js`

```javascript
// Background Service Worker - Stub für TASK-01
// Wird in TASK-03 und TASK-04 erweitert

const CURRENT_VERSION = '1.0.0';

// Message Handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request, sender)
    .then(result => sendResponse({ result }))
    .catch(e => sendResponse({ error: e.message }));
  return true; // Async response
});

async function handleMessage(request, sender) {
  // PING erfordert keine Domain-Validierung (für Extension-Detection)
  if (request.type === 'NOSTR_PING') {
    return { pong: true, version: CURRENT_VERSION };
  }

  // NOSTR_CHECK_VERSION erfordert keine Domain-Validierung
  if (request.type === 'NOSTR_CHECK_VERSION') {
    return {
      version: CURRENT_VERSION,
      updateRequired: false // Stub - wird in TASK-06 implementiert
    };
  }

  // Alle anderen Methoden werden in TASK-03 implementiert
  throw new Error('Method not implemented yet: ' + request.type);
}
```

### 5. Placeholder-Dateien

**Pfad:** `src/popup.html`
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Nostr Signer</title>
</head>
<body>
  <p>Popup wird in TASK-08 implementiert</p>
</body>
</html>
```

**Pfad:** `src/dialog.html`
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Dialog</title>
</head>
<body>
  <p>Dialog wird in TASK-03 implementiert</p>
</body>
</html>
```

**Pfad:** `src/dialog.css`
```css
/* Dialog Styles - wird in TASK-03 implementiert */
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  margin: 0;
  padding: 16px;
}
```

### 6. Icons (Platzhalter)

Erstelle Platzhalter-Icons in `src/icons/`:
- `icon16.png` (16x16 Pixel)
- `icon48.png` (48x48 Pixel)
- `icon128.png` (128x128 Pixel)

**Hinweis:** Für die Entwicklung können einfache einfarbige PNGs verwendet werden. Die finalen Icons werden später erstellt.

---

## Sicherheitsregeln für diesen Task

### KOMMUNIKATION REGELN (relevant für TASK-01)
- Message-Bridge nutzt `_id`-Korrelation für Request/Response-Zuordnung
- Keine Inline-Scripts, nur externe JS-Files
- content.js läuft in ISOLATED world (nicht MAIN world)
- inpage.js wird als Web Accessible Resource injiziert

### DOMAIN REGELN (relevant für TASK-01)
- PING und VERSION_CHECK sind ohne Domain-Validierung erlaubt (Extension-Detection)

---

## Akzeptanzkriterien

- [ ] Extension lädt in Chrome ohne Fehler
- [ ] `window.nostr` ist auf jeder Webseite verfügbar
- [ ] `window.nostr` enthält alle NIP-07 Methoden (getPublicKey, signEvent, getRelays, nip04, nip44)
- [ ] Kommunikation mit Background Script funktioniert (PING-Test)
- [ ] Keine Fehler in DevTools Console
- [ ] `_id` Korrelation funktioniert für Request/Response

---

## Test-Anleitung

1. Extension in Chrome laden:
   - `chrome://extensions/` öffnen
   - "Developer mode" aktivieren
   - "Load unpacked" → `src/` Ordner auswählen

2. Test auf beliebiger Webseite:
   ```javascript
   // In Browser Console:
   console.log(window.nostr); // Sollte Objekt mit Methoden zeigen
   
   // PING Test:
   window.postMessage({ type: 'NOSTR_PING', _id: 'test-123' }, '*');
   // Sollte NOSTR_PING_RESPONSE zurückgeben
   ```

3. DevTools Console prüfen:
   - Keine Fehler beim Laden der Extension
   - Keine Fehler beim Aufruf von `window.nostr`

---

## Nächste Schritte

Nach Abschluss dieses Tasks:
1. **TASK-07: Build Pipeline** - Rollup-Konfiguration für nostr-tools Bundling
2. **TASK-03: Key-Management & UI** - Implementierung der NIP-07 Methoden
