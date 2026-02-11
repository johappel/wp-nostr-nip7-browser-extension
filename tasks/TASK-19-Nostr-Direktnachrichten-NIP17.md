# TASK-19: Nostr-Direktnachrichten Backend (NIP-17 Gift-Wrapped DMs)

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
  scope: string,
  relayUrl: string          // Empfänger-Relay oder DM-Relay
}}
→ { result: { success: true, eventId: string } }

// DMs abrufen (aus Cache oder Relay)
{ type: 'NOSTR_GET_DMS', payload: {
  scope: string,
  relayUrl: string,
  since: number,            // Unix-Timestamp (optional)
  limit: number             // Max Nachrichten (default: 100)
}}
→ { result: { messages: [...], source: 'cache'|'fresh' } }

// DM-Relays eines Pubkeys abfragen (Kind 10050)
{ type: 'NOSTR_GET_DM_RELAYS', payload: {
  pubkey: string,           // hex pubkey
  relayUrl: string          // Lookup-Relay
}}
→ { result: { relays: [string] } }

// Subscription starten (Hintergrund-Listener)
{ type: 'NOSTR_SUBSCRIBE_DMS', payload: {
  scope: string,
  relayUrl: string
}}
→ { result: { subscriptionId: string } }
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

case 'NOSTR_GET_DM_RELAYS':
  return handleGetDmRelays(request);

case 'NOSTR_SUBSCRIBE_DMS':
  return handleSubscribeDMs(request);
```

## Akzeptanzkriterien

- [ ] DM senden: Kind 14 → Kind 13 → Kind 1059 korrekt verschachtelt
- [ ] Selbst-Kopie: Gift Wrap wird auch für den Absender erstellt
- [ ] DM empfangen: Gift Wrap → Seal → Rumor korrekt entschlüsselt
- [ ] Seal-Validierung: Pubkey im Seal muss mit Pubkey im Rumor übereinstimmen
- [ ] Zeitstempel-Randomisierung: Seal und Gift Wrap haben Jitter (±2 Tage)
- [ ] Kind 10050 DM-Relay Discovery funktioniert
- [ ] Fallback auf eigenes Relay wenn Empfänger kein Kind 10050 hat
- [ ] Nachrichten-Cache in `chrome.storage.local` (max 500 Messages)
- [ ] Deduplizierung über `giftWrapId`
- [ ] Private Key wird nur im Background Worker verarbeitet, nie im Popup
- [ ] Unlock-Flow (Passkey/Passwort) wird vor jeder Key-Operation durchlaufen
- [ ] NIP-44 v2 Encryption wird korrekt verwendet
- [ ] WebSocket-Verbindungen nur `wss://`

## Sicherheitshinweise

- **Private Key Handling**: Nur im Service Worker, nie in popup.js
- **Wegwerf-Schlüssel**: Für jede Gift-Wrap-Erstellung ein neuer Random Key
- **Zeitstempel**: Echte Zeit nur im Rumor, Seal/Wrap randomisiert
- **Speicher-Bereinigung**: Private Key nach Nutzung aus Variablen löschen
- **Abstreitbarkeit**: Rumor wird NICHT signiert (nur Seal wird signiert)
- **NIP-04 Kompatibilität**: Wird NICHT implementiert (deprecated)

## Offene Fragen

- Soll eine Echtzeit-Subscription (persistente WebSocket) im Service Worker laufen, oder reicht Polling?
  - Empfehlung: Polling beim Öffnen des Popups + optionaler Background-Alarm (chrome.alarms) alle 5 Minuten
- Maximale Nachrichtenlänge begrenzen? (Vorschlag: 10.000 Zeichen)
- Sollen auch Gruppen-DMs unterstützt werden? (NIP-17 erlaubt mehrere p-Tags)
  - Empfehlung: Erst 1:1, Gruppen als spätere Erweiterung
