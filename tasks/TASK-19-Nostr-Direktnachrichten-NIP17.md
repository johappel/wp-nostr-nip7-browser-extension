# TASK-19: Nostr-Direktnachrichten Backend (NIP-17 Gift-Wrapped DMs)

## Iststand (2026-02)

Diese Task-Datei enthält historische Plan-/Designanteile. Der tatsächlich aktive Message-Vertrag in `background.js` ist:

- `NOSTR_SEND_DM`
- `NOSTR_GET_DMS`
- `NOSTR_SUBSCRIBE_DMS`

Aus dieser Task entfernte/obsolet gewordene Handler:

- `NOSTR_GET_DM_RELAYS`
- `NOSTR_UNSUBSCRIBE_DMS`
- `NOSTR_GET_UNREAD_COUNT`
- `NOSTR_CLEAR_UNREAD`

## Ziel

Implementierung des vollständigen NIP-17 Messaging-Backends im Background Service Worker. Ermöglicht das Senden und Empfangen von verschlüsselten Direktnachrichten über das Gift-Wrap-Protokoll (Kind 14 → Kind 13 → Kind 1059).

## Abhängigkeiten

- TASK-04 (NIP-44 Encryption – Basis-Kryptografie)
- TASK-07 (Build Pipeline – nostr-tools im Service Worker)
- TASK-18 (Kontaktliste – Empfänger-Pubkeys)
- TASK-03 (Key-Management – Private Key Zugriff)

## Protokoll-Übersicht: NIP-17 Gift-Wrapped DMs

### 3-Schichten-Modell

```text
┌──────────────────────────────────────────────┐
│  Kind 1059: Gift Wrap                        │
│  Signiert mit: Wegwerf-Schlüssel (random)    │
│  created_at: randomisiert (±2 Tage)          │
│  p-Tag: Empfänger-Pubkey                     │
│  content: NIP-44 encrypt(Seal, Wegwerf→Empf.)│
├──────────────────────────────────────────────┤
│  Kind 13: Seal                               │
│  Signiert mit: echter Absender-Key           │
│  created_at: randomisiert (±2 Tage)          │
│  content: NIP-44 encrypt(Rumor, Abs.→Empf.)  │
├──────────────────────────────────────────────┤
│  Kind 14: Rumor (Direct Message)             │
│  NICHT signiert (Abstreitbarkeit)            │
│  created_at: echter Zeitstempel              │
│  p-Tag: Empfänger-Pubkey                     │
│  content: Klartext-Nachricht                 │
└──────────────────────────────────────────────┘
```

### Vorteile gegenüber NIP-04 (deprecated)

- **Kein Metadaten-Leak**: Absender ist im Gift Wrap versteckt
- **Abstreitbarkeit**: Rumor ist nicht signiert
- **Zeitstempel-Schutz**: `created_at` in Seal/Wrap randomisiert
- **Moderne Kryptografie**: NIP-44 v2 (ChaCha20 + HMAC-SHA256)

## Architektur

```text
popup.js                 background.js              Nostr Relay
   │                         │                         │
   │─NOSTR_SEND_DM──────────►│                         │
   │                         │─Kind 14 (Rumor) ────────│
   │                         │─Kind 13 (Seal) ─────────│
   │                         │─Kind 1059 (Gift Wrap)──►│
   │                         │  × 2 (Empf. + Selbst)   │
   │◄─result─────────────────│                         │
   │                         │                         │
   │─NOSTR_GET_DMS──────────►│                         │
   │                         │─sub {kinds:[1059]}─────►│
   │                         │◄─events────────────────│
   │                         │  decrypt Gift Wrap      │
   │                         │  verify Seal            │
   │                         │  extract Rumor          │
   │◄─messages───────────────│                         │
```

### Neue Message-Types (popup ↔ background)

```javascript
// DM senden
{ type: 'NOSTR_SEND_DM', payload: { 
  recipientPubkey: string,  // hex pubkey
  content: string,          // Klartext-Nachricht
  relayUrl: string          // Empfänger-Relay oder DM-Relay
}}
→ { result: { success: true, eventId: string } }

// DMs abrufen (aus Cache oder Relay)
{ type: 'NOSTR_GET_DMS', payload: {
  relayUrl: string,
  contactPubkey: string,    // optional: Konversation filtern
  since: number,            // Unix-Timestamp (optional)
  limit: number             // Max Nachrichten (default: 100)
}}
→ { result: { messages: [...], source: 'cache'|'merged'|'cache_only' } }

// Subscription starten (Hintergrund-Listener)
{ type: 'NOSTR_SUBSCRIBE_DMS', payload: {
  relayUrl: string
}}
→ { result: { subscriptionIds: [string], status: 'active', relays: [string] } }
```

### Nachricht-Datenstruktur

```javascript
{
  id: string,               // Event-ID des originalen Kind 14
  senderPubkey: string,     // hex pubkey des Absenders (aus Seal)
  recipientPubkey: string,  // hex pubkey des Empfängers
  content: string,          // Klartext-Nachricht
  createdAt: number,        // Unix-Timestamp (aus Rumor, nicht Wrap)
  direction: 'in'|'out',    // eingehend/ausgehend
  giftWrapId: string,       // Event-ID des Gift Wraps (für Deduplizierung)
  receivedAt: number        // Wann empfangen
}
```

## Implementierungsplan

### Schritt 1: NIP-44 Conversation Key

Die bestehende NIP-44 Implementierung (TASK-04) wird genutzt. Sicherstellen, dass `nip44.encrypt(pubkey, plaintext)` und `nip44.decrypt(pubkey, ciphertext)` im Background Worker verfügbar sind.

```javascript
// Bereits vorhanden via nostr-tools
import { nip44 } from 'nostr-tools';

function getConversationKey(privateKey, publicKey) {
  return nip44.v2.utils.getConversationKey(privateKey, publicKey);
}

function nip44Encrypt(conversationKey, plaintext) {
  return nip44.v2.encrypt(plaintext, conversationKey);
}

function nip44Decrypt(conversationKey, ciphertext) {
  return nip44.v2.decrypt(ciphertext, conversationKey);
}
```

### Schritt 2: Gift Wrap Erstellung (Senden)

```javascript
async function createGiftWrappedDM(privateKey, senderPubkey, recipientPubkey, content) {
  // 1. Rumor erstellen (Kind 14, NICHT signiert)
  const rumor = {
    kind: 14,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', recipientPubkey]],
    content: content,
    pubkey: senderPubkey
  };
  
  // 2. Seal erstellen (Kind 13, signiert mit Absender-Key)
  const sealContent = nip44Encrypt(
    getConversationKey(privateKey, recipientPubkey),
    JSON.stringify(rumor)
  );
  
  const seal = finalizeEvent({
    kind: 13,
    created_at: randomizeTimestamp(),  // ±2 Tage
    tags: [],
    content: sealContent
  }, privateKey);
  
  // 3. Gift Wrap für Empfänger (Kind 1059, Wegwerf-Key)
  const wrapKeyForRecipient = generateSecretKey();
  const wrapForRecipient = createGiftWrap(wrapKeyForRecipient, seal, recipientPubkey);
  
  // 4. Gift Wrap für Absender (Selbst-Kopie)
  const wrapKeyForSelf = generateSecretKey();
  const wrapForSelf = createGiftWrap(wrapKeyForSelf, seal, senderPubkey);
  
  return { wrapForRecipient, wrapForSelf };
}

function createGiftWrap(wrapperKey, seal, recipientPubkey) {
  const wrapContent = nip44Encrypt(
    getConversationKey(wrapperKey, recipientPubkey),
    JSON.stringify(seal)
  );
  
  return finalizeEvent({
    kind: 1059,
    created_at: randomizeTimestamp(),
    tags: [['p', recipientPubkey]],
    content: wrapContent
  }, wrapperKey);
}

function randomizeTimestamp() {
  // ±2 Tage Jitter
  const now = Math.floor(Date.now() / 1000);
  const jitter = Math.floor(Math.random() * 2 * 24 * 60 * 60) - (2 * 24 * 60 * 60);
  return now + jitter;
}
```

### Schritt 3: Gift Wrap Entschlüsselung (Empfangen)

```javascript
async function unwrapGiftWrap(privateKey, giftWrapEvent) {
  // 1. Gift Wrap entschlüsseln → Seal
  const conversationKey = getConversationKey(privateKey, giftWrapEvent.pubkey);
  const sealJson = nip44Decrypt(conversationKey, giftWrapEvent.content);
  const seal = JSON.parse(sealJson);
  
  // 2. Seal validieren (muss Kind 13 sein)
  if (seal.kind !== 13) throw new Error('Invalid seal kind');
  
  // 3. Seal entschlüsseln → Rumor
  const sealConvKey = getConversationKey(privateKey, seal.pubkey);
  const rumorJson = nip44Decrypt(sealConvKey, seal.content);
  const rumor = JSON.parse(rumorJson);
  
  // 4. Rumor validieren
  if (rumor.kind !== 14) throw new Error('Invalid rumor kind');
  if (rumor.pubkey !== seal.pubkey) throw new Error('Pubkey mismatch: seal vs rumor');
  
  return {
    id: rumor.id || giftWrapEvent.id,
    senderPubkey: rumor.pubkey,
    recipientPubkey: rumor.tags?.find(t => t[0] === 'p')?.[1] || '',
    content: rumor.content,
    createdAt: rumor.created_at,
    giftWrapId: giftWrapEvent.id
  };
}
```

### Schritt 4: Kind 10050 – DM Relay Discovery

```javascript
async function fetchDmRelays(pubkey, lookupRelay) {
  const events = await subscribeOnce(lookupRelay, [
    { kinds: [10050], authors: [pubkey], limit: 1 }
  ]);
  
  if (!events.length) return [];
  
  const latest = events.sort((a, b) => b.created_at - a.created_at)[0];
  return latest.tags
    .filter(t => t[0] === 'relay' && t[1])
    .map(t => normalizeRelayUrl(t[1]))
    .filter(Boolean);
}
```

### Schritt 5: Sende-Flow

```javascript
async function handleSendDM(request) {
  const { recipientPubkey, content, scope, relayUrl } = request.payload;
  
  // 1. Private Key holen (mit Unlock falls nötig)
  const mode = await keyManager.getProtectionMode();
  const password = await ensureUnlockForMode(mode);
  const privateKey = await keyManager.getKey(password);
  const senderPubkey = getPublicKey(privateKey);
  
  // 2. DM-Relays des Empfängers herausfinden
  let targetRelays = await fetchDmRelays(recipientPubkey, relayUrl);
  if (!targetRelays.length) {
    // Fallback: eigenes DM-Relay
    targetRelays = [relayUrl];
  }
  
  // 3. Gift Wraps erstellen
  const { wrapForRecipient, wrapForSelf } = await createGiftWrappedDM(
    privateKey, senderPubkey, recipientPubkey, content
  );
  
  // 4. An Relays publishen
  for (const relay of targetRelays) {
    await publishToRelay(relay, wrapForRecipient);
  }
  // Selbst-Kopie ans eigene Relay
  await publishToRelay(relayUrl, wrapForSelf);
  
  // 5. Lokal cachen
  await cacheMessage({
    id: wrapForRecipient.id,
    senderPubkey,
    recipientPubkey,
    content,
    createdAt: Math.floor(Date.now() / 1000),
    direction: 'out',
    giftWrapId: wrapForRecipient.id,
    receivedAt: Date.now()
  }, scope);
  
  return { success: true, eventId: wrapForRecipient.id };
}
```

### Schritt 6: Empfangs-Flow

```javascript
async function handleGetDMs(request) {
  const { scope, relayUrl, since, limit } = request.payload;
  
  // Private Key für Entschlüsselung
  const mode = await keyManager.getProtectionMode();
  const password = await ensureUnlockForMode(mode);
  const privateKey = await keyManager.getKey(password);
  const myPubkey = getPublicKey(privateKey);
  
  // Gift Wraps vom Relay holen
  const filters = [{
    kinds: [1059],
    '#p': [myPubkey],
    limit: limit || 100
  }];
  if (since) filters[0].since = since;
  
  const giftWraps = await subscribeOnce(relayUrl, filters);
  
  // Entschlüsseln und validieren
  const messages = [];
  for (const gw of giftWraps) {
    try {
      const msg = await unwrapGiftWrap(privateKey, gw);
      msg.direction = msg.senderPubkey === myPubkey ? 'out' : 'in';
      msg.receivedAt = Date.now();
      messages.push(msg);
    } catch {
      // Silently skip undecrytable wraps (nicht für uns)
    }
  }
  
  // Sortieren nach created_at
  messages.sort((a, b) => a.createdAt - b.createdAt);
  
  // Cachen
  await cacheMessages(messages, scope);
  
  return { messages, source: 'fresh' };
}
```

### Schritt 7: Nachrichten-Cache

```javascript
const DM_CACHE_KEY = 'nostrDmCacheV1';
const DM_CACHE_MAX_MESSAGES = 500;

async function cacheMessage(msg, scope) {
  const result = await chrome.storage.local.get([DM_CACHE_KEY]);
  const cache = result[DM_CACHE_KEY] || { scope, messages: [] };
  
  // Deduplizierung über giftWrapId
  if (cache.messages.some(m => m.giftWrapId === msg.giftWrapId)) return;
  
  cache.messages.push(msg);
  cache.messages.sort((a, b) => a.createdAt - b.createdAt);
  
  // Max-Größe begrenzen
  if (cache.messages.length > DM_CACHE_MAX_MESSAGES) {
    cache.messages = cache.messages.slice(-DM_CACHE_MAX_MESSAGES);
  }
  
  cache.scope = scope;
  cache.updatedAt = Date.now();
  await chrome.storage.local.set({ [DM_CACHE_KEY]: cache });
}

async function cacheMessages(messages, scope) {
  for (const msg of messages) {
    await cacheMessage(msg, scope);
  }
}

async function getCachedMessages(scope, contactPubkey = null) {
  const result = await chrome.storage.local.get([DM_CACHE_KEY]);
  const cache = result[DM_CACHE_KEY];
  if (!cache || cache.scope !== scope) return [];
  
  let messages = cache.messages || [];
  if (contactPubkey) {
    messages = messages.filter(m => 
      m.senderPubkey === contactPubkey || m.recipientPubkey === contactPubkey
    );
  }
  
  return messages;
}
```

### Schritt 8: Message Handler Registration

```javascript
// In der bestehenden chrome.runtime.onMessage Logik ergänzen:
case 'NOSTR_SEND_DM':
  return handleSendDM(request);

case 'NOSTR_GET_DMS':
  return handleGetDMs(request);

case 'NOSTR_SUBSCRIBE_DMS':
  return handleSubscribeDMs(request);
```

## Akzeptanzkriterien

### NIP-17 Protokoll
- [ ] DM senden: Kind 14 → Kind 13 → Kind 1059 korrekt verschachtelt
- [ ] Selbst-Kopie: Gift Wrap wird auch für den Absender erstellt
- [ ] DM empfangen: Gift Wrap → Seal → Rumor korrekt entschlüsselt
- [ ] Seal-Validierung: Pubkey im Seal muss mit Pubkey im Rumor übereinstimmen
- [ ] Zeitstempel-Randomisierung: Seal und Gift Wrap haben Jitter (±2 Tage)
- [ ] Kind 10050 DM-Relay Discovery funktioniert
- [ ] Fallback auf eigenes Relay wenn Empfänger kein Kind 10050 hat
- [ ] NIP-44 v2 Encryption wird korrekt verwendet

### Background Worker Relay-Architektur
- [ ] RelayConnectionManager Klasse implementiert
- [ ] Auto-Reconnect bei WebSocket-Verbindungsabbruch
- [ ] Keep-Alive Alarm alle 24 Sekunden (unter MV3 30s Grenze)
- [ ] Persistente Subscription für Kind 1059 Events
- [ ] Nachrichten werden im Background entschlüsselt und gecacht
- [ ] Desktop Notifications für neue DMs
- [ ] Badge-Counter für ungelesene Nachrichten
- [ ] Fallback-Polling alle 5 Minuten

### Cache & Storage
- [ ] Nachrichten-Cache in `chrome.storage.local` (max 500 Messages)
- [ ] Deduplizierung über `giftWrapId`
- [ ] Unread-Counter persistiert in Storage

### Sicherheit
- [ ] Private Key wird nur im Background Worker verarbeitet, nie im Popup
- [ ] Unlock-Flow (Passkey/Passwort) wird vor jeder Key-Operation durchlaufen
- [ ] WebSocket-Verbindungen nur `wss://`
- [ ] Private Key nach Nutzung aus Variablen gelöscht

## Sicherheitshinweise

- **Private Key Handling**: Nur im Service Worker, nie in popup.js
- **Wegwerf-Schlüssel**: Für jede Gift-Wrap-Erstellung ein neuer Random Key
- **Zeitstempel**: Echte Zeit nur im Rumor, Seal/Wrap randomisiert
- **Speicher-Bereinigung**: Private Key nach Nutzung aus Variablen löschen
- **Abstreitbarkeit**: Rumor wird NICHT signiert (nur Seal wird signiert)
- **NIP-04 Kompatibilität**: Wird NICHT implementiert (deprecated)

## Background-Worker Relay-Architektur

### Warum persistente Relay-Verbindungen im Background?

**Vorteile:**
1. **Persistente Relay-Verbindungen** - WebSocket bleibt erhalten auch wenn Popup/Tab geschlossen wird
2. **Echtzeit-Benachrichtigungen** - Neue Nachrichten können Desktop-Notifications triggern
3. **Zentrale Nachrichtenverwaltung** - Alle Chat-Nachrichten an einem Ort (`chrome.storage.local`)
4. **Badge-Counter** - Ungelesene Nachrichten anzeigen auch wenn Popup geschlossen

**Herausforderung MV3 Service Worker:**
- Service Worker werden nach ~30 Sekunden Inaktivität beendet
- WebSocket-Verbindungen werden dabei getrennt
- Lösung: Keep-Alive Strategie mit `chrome.alarms`

### Relay Connection Manager

```javascript
// background.js - Relay Connection Manager

class RelayConnectionManager {
  constructor() {
    this.connections = new Map(); // relayUrl -> WebSocket
    this.subscriptions = new Map(); // subId -> { filter, onMessage }
    this.reconnectInterval = 30000;
    this.keepAliveInterval = 25000; // < 30s für MV3
  }

  async connect(relayUrl) {
    const normalized = normalizeRelayUrl(relayUrl);
    if (!normalized) throw new Error('Invalid relay URL');

    if (this.connections.has(normalized)) {
      const existing = this.connections.get(normalized);
      if (existing.readyState === WebSocket.OPEN) {
        return existing;
      }
    }

    const ws = new WebSocket(normalized);
    
    ws.onopen = () => {
      console.log(`[Relay] Connected to ${normalized}`);
      // Re-subscribe to existing subscriptions
      this.resubscribeAll(normalized);
    };

    ws.onclose = () => {
      console.log(`[Relay] Disconnected from ${normalized}`);
      this.connections.delete(normalized);
      // Auto-Reconnect nach Verzögerung
      setTimeout(() => this.connect(normalized), this.reconnectInterval);
    };

    ws.onerror = (error) => {
      console.warn(`[Relay] Error on ${normalized}:`, error);
    };

    ws.onmessage = (event) => {
      this.handleMessage(normalized, event.data);
    };

    this.connections.set(normalized, ws);
    return ws;
  }

  handleMessage(relayUrl, data) {
    let parsed;
    try {
      parsed = JSON.parse(data);
    } catch {
      return;
    }

    if (!Array.isArray(parsed) || parsed.length < 2) return;

    // ["EVENT", subId, event]
    if (parsed[0] === 'EVENT' && parsed[2]) {
      const subId = parsed[1];
      const event = parsed[2];
      const sub = this.subscriptions.get(subId);
      if (sub?.onMessage) {
        sub.onMessage(event, relayUrl);
      }
    }

    // ["EOSE", subId]
    if (parsed[0] === 'EOSE') {
      const sub = this.subscriptions.get(parsed[1]);
      if (sub?.onEose) {
        sub.onEose();
      }
    }
  }

  async subscribe(relayUrl, filters, onMessage, onEose = null) {
    const ws = await this.connect(relayUrl);
    const subId = 'dm_' + Math.random().toString(36).slice(2);
    
    this.subscriptions.set(subId, { filters, onMessage, onEose });
    
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(['REQ', subId, ...filters]));
    }
    
    return subId;
  }

  unsubscribe(subId) {
    this.subscriptions.delete(subId);
    // Send CLOSE to all connected relays
    for (const [relayUrl, ws] of this.connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(['CLOSE', subId]));
      }
    }
  }

  resubscribeAll(relayUrl) {
    const ws = this.connections.get(relayUrl);
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    for (const [subId, sub] of this.subscriptions) {
      ws.send(JSON.stringify(['REQ', subId, ...sub.filters]));
    }
  }

  checkConnections() {
    for (const [relayUrl, ws] of this.connections) {
      if (ws.readyState !== WebSocket.OPEN) {
        this.connect(relayUrl);
      }
    }
  }

  disconnect(relayUrl) {
    const ws = this.connections.get(relayUrl);
    if (ws) {
      ws.close();
      this.connections.delete(relayUrl);
    }
  }

  disconnectAll() {
    for (const [relayUrl] of this.connections) {
      this.disconnect(relayUrl);
    }
  }
}

// Singleton Instance
const relayManager = new RelayConnectionManager();
```

### Keep-Alive Strategie für MV3

```javascript
// Service Worker am Leben halten mit Alarms
// MV3 Service Worker werden nach ~30s Inaktivität beendet

// Alarm alle 25 Sekunden (unter 30s Grenze)
chrome.alarms.create('relayKeepalive', { periodInMinutes: 0.4 }); // ~24s

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'relayKeepalive') {
    // Prüfe Relay-Verbindungen, reconnect falls nötig
    relayManager.checkConnections();
  }
});

// Zusätzlicher Alarm für DM-Polling (Fallback)
chrome.alarms.create('dmPolling', { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'dmPolling') {
    // Poll for new DMs in background
    pollForNewDMs().catch(console.error);
  }
});
```

### NIP-17 Gift Wrap Subscription

```javascript
// Background-Subscription für eingehende DMs
async function startDmSubscription(scope, relayUrl, myPubkey, privateKey) {
  const filters = [{
    kinds: [1059],  // Gift Wrap
    '#p': [myPubkey],
    limit: 100
  }];

  const subId = await relayManager.subscribe(
    relayUrl,
    filters,
    async (event, relayUrl) => {
      // Neue Gift Wrap Nachricht empfangen
      try {
        const msg = await unwrapGiftWrap(privateKey, event);
        msg.direction = 'in';
        msg.receivedAt = Date.now();
        
        // In Cache speichern
        await cacheMessage(msg, scope);
        
        // Notification auslösen
        await showDmNotification(msg);
        
        // Badge-Counter updaten
        await incrementUnreadCount();
        
      } catch (e) {
        // Nicht für uns - silently skip
        console.debug('[DM] Could not unwrap gift wrap:', e.message);
      }
    }
  );

  return subId;
}
```

### Notification System

```javascript
// Desktop Notifications für neue DMs
async function showDmNotification(msg) {
  // Prüfen ob Notifications erlaubt sind
  const settings = await chrome.storage.local.get(['dmNotifications']);
  if (settings.dmNotifications === false) return;

  // Absender-Profil laden für Anzeigename
  const profile = await getContactProfile(msg.senderPubkey);
  const displayName = profile?.displayName || formatShortHex(msg.senderPubkey);

  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon48.png'),
    title: `Neue Nachricht von ${displayName}`,
    message: msg.content.slice(0, 100) + (msg.content.length > 100 ? '...' : ''),
    priority: 2
  });
}

// Badge-Counter für ungelesene Nachrichten
async function incrementUnreadCount() {
  const result = await chrome.storage.local.get(['dmUnreadCount']);
  const count = (result.dmUnreadCount || 0) + 1;
  await chrome.storage.local.set({ dmUnreadCount: count });
  
  // Badge setzen
  if (count > 0) {
    chrome.action.setBadgeText({ text: count > 99 ? '99+' : String(count) });
    chrome.action.setBadgeBackgroundColor({ color: '#3b82f6' });
  }
}

async function clearUnreadCount() {
  await chrome.storage.local.set({ dmUnreadCount: 0 });
  chrome.action.setBadgeText({ text: '' });
}
```

### Message Handler für Subscription

```javascript
// In handleMessage() ergänzen:

case 'NOSTR_SUBSCRIBE_DMS': {
  const { scope, relayUrl } = request.payload;
  
  // Private Key holen
  const mode = await keyManager.getProtectionMode();
  const password = await ensureUnlockForMode(mode);
  const privateKey = await keyManager.getKey(mode === 'password' ? password : null);
  const myPubkey = getPublicKey(privateKey);
  
  // Subscription starten
  const subId = await startDmSubscription(scope, relayUrl, myPubkey, privateKey);
  
  // Private Key sicher löschen
  privateKey.fill(0);
  
  return { subscriptionId: subId, status: 'active' };
}

// Hinweis: Diese Commands wurden im Cleanup entfernt:
// - NOSTR_UNSUBSCRIBE_DMS
// - NOSTR_GET_UNREAD_COUNT
// - NOSTR_CLEAR_UNREAD
```

### Architektur-Diagramm

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Background Service Worker                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              Relay Connection Manager                        ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                   ││
│  │  │ Relay 1  │  │ Relay 2  │  │ Relay N  │  (WebSockets)     ││
│  │  │ wss://.. │  │ wss://.. │  │ wss://.. │                   ││
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘                   ││
│  └───────┼─────────────┼─────────────┼─────────────────────────┘│
│          │             │             │                           │
│  ┌───────▼─────────────▼─────────────▼─────────────────────────┐│
│  │              Gift Wrap Handler                               ││
│  │  • Unwrap Kind 1059 → Seal → Rumor                          ││
│  │  • Validate & Decrypt                                        ││
│  │  • Store in chrome.storage.local                            ││
│  └──────────────────────────┬──────────────────────────────────┘│
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────────┐│
│  │              Notification Manager                            ││
│  │  • Desktop Notifications                                     ││
│  │  • Badge Counter                                             ││
│  │  • Sound (optional)                                          ││
│  └──────────────────────────────────────────────────────────────┘│
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────────┐│
│  │              Keep-Alive (chrome.alarms)                      ││
│  │  • relayKeepalive: alle 24s                                  ││
│  │  • dmPolling: alle 5min (Fallback)                           ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
          ▲                                    │
          │ chrome.runtime.sendMessage         │ chrome.storage.local
          │                                    ▼
┌─────────────────┐                  ┌─────────────────┐
│    Popup UI     │                  │  Message Cache  │
│  (popup.js)     │◄─────────────────│  (DMs, Contacts)│
└─────────────────┘                  └─────────────────┘
```

## Entschiedene Fragen

- **Echtzeit-Subscription vs. Polling**: Beides implementieren
  - Persistente WebSocket-Subscription im Background Worker mit Keep-Alive
  - Fallback-Polling alle 5 Minuten falls Verbindung verloren
  - Popup liest aus Cache, Background managed Connections

## Offene Fragen

- Maximale Nachrichtenlänge begrenzen? (Vorschlag: 10.000 Zeichen)
- Sollen auch Gruppen-DMs unterstützt werden? (NIP-17 erlaubt mehrere p-Tags)
  - Empfehlung: Erst 1:1, Gruppen als spätere Erweiterung
- Sound-Benachrichtigung optional implementieren?
