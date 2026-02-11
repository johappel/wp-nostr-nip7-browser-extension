# TASK-18: Nostr-Kontaktliste & Profil-Auflösung (Kind 3, Kind 0, WP-User)

## Ziel

Kontakte aus zwei Quellen zusammenführen und im Popup als durchsuchbare Liste anzeigen:

1. **Nostr-Kontaktliste** (Kind 3 Events) – die Follow-Liste des eigenen Pubkeys
2. **WordPress-Instanz-User** – Benutzer der Primary Domain WP-Installation, die ein Nostr-Profil haben

Für jeden Kontakt wird das Nostr-Profil (Kind 0) aufgelöst und gecacht.

## Abhängigkeiten

- TASK-16 (App-Shell → Home-View als Container)
- TASK-03 (Key-Management – eigener Pubkey muss verfügbar sein)
- TASK-04 (NIP-44 Encryption – für spätere DM-Integration)
- TASK-07 (Build Pipeline – nostr-tools im Background-Worker)

## Protokoll-Grundlagen

### Kind 3 – Contact List (Follow List)

- **Replaceable Event**: nur das neueste pro Pubkey gilt
- Enthält `p`-Tags: `["p", "<hex-pubkey>", "<relay-url>", "<petname>"]`
- Abruf: `{ kinds: [3], authors: [<eigener-pubkey>], limit: 1 }`
- Ergebnis: Liste von Hex-Pubkeys der Kontakte

### Kind 0 – Profile Metadata

- **Replaceable Event**: nur das neueste pro Pubkey gilt
- `content` ist JSON: `{ name, display_name, about, picture, nip05, ... }`
- Abruf: `{ kinds: [0], authors: [<pubkey1>, <pubkey2>, ...] }`
- Batch-Abruf für alle Kontakte auf einmal

### WordPress-User (REST API)

- Endpunkt: `{restUrl}/wp-nostr/v1/members` (oder ähnlich)
- Liefert: `{ userId, displayName, avatarUrl, npub, nip05 }`
- Nur User der Primary Domain werden abgerufen
- Merge-Logik: WP-User mit passendem Pubkey werden mit Nostr-Profil zusammengeführt

## Architektur

```text
┌──────────────┐    ┌────────────────────┐    ┌──────────────┐
│  popup.js    │───►│  background.js     │───►│  Nostr Relays│
│  (UI)        │    │  (Service Worker)  │    │  (WebSocket) │
│              │◄───│                    │◄───│              │
│  Kontaktliste│    │  Kind 3 fetch      │    │              │
│  rendern     │    │  Kind 0 batch      │    │              │
│              │    │  WP-User fetch     │    │              │
└──────────────┘    └────────────────────┘    └──────────────┘
```

### Neue Message-Types (popup ↔ background)

```javascript
// Kontaktliste abrufen
{ type: 'NOSTR_GET_CONTACTS', payload: { scope } }
→ { result: { contacts: [...], source: 'cache'|'fresh' } }

// Kontaktliste aktualisieren (Force-Refresh)
{ type: 'NOSTR_REFRESH_CONTACTS', payload: { scope, relayUrl } }
→ { result: { contacts: [...], source: 'fresh' } }

// WP-User der Primary Domain abrufen
{ type: 'NOSTR_GET_WP_MEMBERS', payload: { scope, wpApi } }
→ { result: { members: [...] } }
```

### Kontakt-Datenstruktur

```javascript
{
  pubkey: string,          // hex pubkey
  npub: string,            // bech32 npub
  displayName: string,     // aus Kind 0 oder WP-Profil
  name: string,            // username / handle
  picture: string,         // Avatar-URL
  nip05: string,           // NIP-05 Identität
  about: string,           // Bio
  relayUrl: string,        // bevorzugter Relay (aus Kind 3 p-tag)
  source: 'nostr'|'wp'|'both', // Herkunft
  wpUserId: number|null,   // WP User-ID falls aus WP
  lastSeen: number|null,   // Timestamp letzte Aktivität
  petname: string|null     // Petname aus Kind 3
}
```

## Implementierungsplan

### Schritt 1: Relay-Verbindung im Background Worker

```javascript
// background.js – Neue Funktion
async function connectToRelay(relayUrl) {
  // Nutzt nostr-tools SimplePool oder Relay
  // Verbindung wird gecacht und wiederverwendet
  // Timeout: 10s
  // Retry: 1x bei Fehler
}

async function subscribeOnce(relayUrl, filters, timeout = 8000) {
  // Einmalige Subscription, sammelt Events bis EOSE oder Timeout
  // Gibt Array von Events zurück
}
```

### Schritt 2: Kind 3 Fetch

```javascript
async function fetchContactList(pubkey, relayUrl) {
  const events = await subscribeOnce(relayUrl, [
    { kinds: [3], authors: [pubkey], limit: 1 }
  ]);
  
  if (!events.length) return [];
  
  // Neuestes Event (höchstes created_at)
  const latest = events.sort((a, b) => b.created_at - a.created_at)[0];
  
  // p-Tags extrahieren
  return latest.tags
    .filter(t => t[0] === 'p' && t[1])
    .map(t => ({
      pubkey: t[1],
      relayUrl: t[2] || null,
      petname: t[3] || null
    }));
}
```

### Schritt 3: Kind 0 Batch-Abruf

```javascript
async function fetchProfiles(pubkeys, relayUrl) {
  // Max 100 Pubkeys pro Request (Relay-Limit)
  const chunks = chunkArray(pubkeys, 100);
  const profiles = new Map();
  
  for (const chunk of chunks) {
    const events = await subscribeOnce(relayUrl, [
      { kinds: [0], authors: chunk }
    ]);
    
    for (const event of events) {
      try {
        const meta = JSON.parse(event.content);
        profiles.set(event.pubkey, {
          displayName: meta.display_name || meta.name || '',
          name: meta.name || '',
          picture: meta.picture || '',
          nip05: meta.nip05 || '',
          about: meta.about || '',
          fetchedAt: Date.now()
        });
      } catch { /* skip malformed */ }
    }
  }
  
  return profiles;
}
```

### Schritt 4: WP-User Abruf

```javascript
async function fetchWpMembers(wpApi) {
  const context = sanitizeWpApiContext(wpApi);
  if (!context) return [];
  
  const baseUrl = normalizeWpRestBaseUrl(context.restUrl);
  const endpoint = new URL('wp-nostr/v1/members', baseUrl).toString();
  
  const response = await fetch(endpoint, {
    headers: { 'X-WP-Nonce': context.nonce },
    credentials: 'include'
  });
  
  if (!response.ok) return [];
  const data = await response.json();
  
  return (data.members || data || []).map(m => ({
    pubkey: m.pubkey || m.npub_hex || '',
    npub: m.npub || '',
    displayName: m.display_name || m.displayName || '',
    picture: m.avatar_url || m.avatarUrl || '',
    nip05: m.nip05 || '',
    wpUserId: m.user_id || m.userId || null,
    source: 'wp'
  }));
}
```

### Schritt 5: Merge-Logik

```javascript
function mergeContacts(nostrContacts, wpMembers) {
  const merged = new Map();
  
  // Nostr-Kontakte zuerst
  for (const c of nostrContacts) {
    merged.set(c.pubkey, { ...c, source: 'nostr' });
  }
  
  // WP-User ergänzen/mergen
  for (const m of wpMembers) {
    if (!m.pubkey) continue;
    const existing = merged.get(m.pubkey);
    if (existing) {
      // Merge: WP-Daten ergänzen fehlende Felder
      merged.set(m.pubkey, {
        ...existing,
        ...m,
        source: 'both',
        displayName: existing.displayName || m.displayName,
        picture: existing.picture || m.picture
      });
    } else {
      merged.set(m.pubkey, { ...m, source: 'wp' });
    }
  }
  
  return Array.from(merged.values());
}
```

### Schritt 6: Caching

```javascript
const CONTACTS_CACHE_KEY = 'nostrContactsCacheV1';
const CONTACTS_CACHE_TTL = 15 * 60 * 1000; // 15 Minuten

async function getCachedContacts(scope) {
  const result = await chrome.storage.local.get([CONTACTS_CACHE_KEY]);
  const cache = result[CONTACTS_CACHE_KEY];
  if (!cache || cache.scope !== scope) return null;
  if (Date.now() - cache.fetchedAt > CONTACTS_CACHE_TTL) return null;
  return cache.contacts;
}

async function setCachedContacts(scope, contacts) {
  await chrome.storage.local.set({
    [CONTACTS_CACHE_KEY]: {
      scope,
      contacts,
      fetchedAt: Date.now()
    }
  });
}
```

## Akzeptanzkriterien

- [ ] Kind 3 Contact List wird vom konfigurierten Relay abgerufen
- [ ] Kind 0 Profile werden batch-weise für alle Kontakte geladen
- [ ] WP-User der Primary Domain werden per REST API abgerufen
- [ ] Nostr- und WP-Kontakte werden korrekt zusammengeführt (Deduplizierung über Pubkey)
- [ ] Kontaktdaten werden in `chrome.storage.local` gecacht (TTL: 15 min)
- [ ] Force-Refresh möglich (Cache invalidieren)
- [ ] Leerer Zustand wird graceful behandelt (kein Relay, kein Key, keine Kontakte)
- [ ] Fehlgeschlagene Relay-Verbindung zeigt Fehlermeldung, blockiert nicht die UI
- [ ] Max 100 Pubkeys pro Relay-Request (Chunking)
- [ ] Background-Worker nutzt nostr-tools `SimplePool` oder `Relay` für WebSocket

## Relay-Strategie

| Quelle | Relay |
|--------|-------|
| Eigene Kontaktliste (Kind 3) | Profil-Relay aus Viewer-Context oder DM-Relay aus Settings |
| Kontakt-Profile (Kind 0) | Gleicher Relay wie Kind 3 |
| DM-Relays der Kontakte (Kind 10050) | Wird in TASK-19 benötigt |

## Sicherheitshinweise

- Kein privater Schlüssel wird ans Relay gesendet
- WebSocket-Verbindungen nur zu `wss://` (kein `ws://`)
- Relay-URL wird validiert und normalisiert (`normalizeRelayUrl()`)
- WP REST API Anfragen nutzen Nonce-Validierung
