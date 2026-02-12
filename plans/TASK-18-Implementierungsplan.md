# TASK-18 Implementierungsplan: Nostr-Kontaktliste & Profil-Auflösung

## Status: In Progress

## Analyse der bestehenden Codebasis

### Vorhandene Funktionen (background.js)
- `publishEventToRelay(relayUrl, event, timeoutMs)` - WebSocket-basiertes Event-Publishing
- `normalizeRelayUrl(input)` - Relay-URL Normalisierung
- `normalizeRelayList(rawRelays)` - Liste von Relay-URLs
- `sanitizeKind0ProfileContent(rawProfile, fallbackWebsite)` - Profil-Metadaten-Bereinigung
- `wpApiPostJson(wpApiContext, path, payload)` - WordPress REST API POST
- `sanitizeWpApiContext(rawContext)` - WP API Context Validierung
- `normalizeWpRestBaseUrl(restUrl)` - WP REST URL Normalisierung
- `toNpub(pubkeyHex)` - Hex zu npub Konvertierung
- `normalizePubkeyHex(pubkeyHex)` - Pubkey Normalisierung

### Was fehlt für TASK-18

1. **Relay-Subscription** (`subscribeOnce`) - Events von Relay abrufen (nicht nur publishen)
2. **Kind 3 Fetch** - Kontaktliste abrufen
3. **Kind 0 Batch-Abruf** - Profile für Kontakte laden
4. **WP Members Fetch** - WordPress-Benutzer mit Nostr-Profil
5. **Merge-Logik** - Nostr + WP Kontakte zusammenführen
6. **Caching** - 15 Minuten TTL
7. **Message-Handler** - Neue Message-Types

---

## Implementierungsschritte

### Schritt 1: Relay-Subscription (`subscribeOnce`)

```javascript
// background.js - Nach publishEventToRelay einfügen

/**
 * Einmalige Subscription: Sammelt Events bis EOSE oder Timeout.
 * @param {string} relayUrl - WebSocket Relay URL
 * @param {Array} filters - Nostr Filter-Array
 * @param {number} timeout - Timeout in ms (default: 8000)
 * @returns {Promise<Array>} - Array von Events
 */
async function subscribeOnce(relayUrl, filters, timeout = 8000) {
  return await new Promise((resolve, reject) => {
    let settled = false;
    let socket;
    const events = [];

    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        try { socket.close(); } catch { /* ignore */ }
      }
      if (error) reject(error);
      else resolve(events);
    };

    const timer = setTimeout(() => {
      finish(null); // Timeout = return what we have
    }, timeout);

    try {
      socket = new WebSocket(relayUrl);
    } catch (error) {
      clearTimeout(timer);
      reject(error);
      return;
    }

    socket.onopen = () => {
      // REQ mit zufälliger Subscription-ID
      const subId = 'sub_' + Math.random().toString(36).slice(2);
      socket.send(JSON.stringify(['REQ', subId, ...filters]));
    };

    socket.onerror = () => {
      finish(new Error(`Relay connection failed: ${relayUrl}`));
    };

    socket.onmessage = (messageEvent) => {
      let data;
      try {
        data = JSON.parse(messageEvent.data);
      } catch {
        return;
      }

      if (!Array.isArray(data) || data.length < 2) return;

      // EVENT: ["EVENT", subId, event]
      if (data[0] === 'EVENT' && data[2]) {
        events.push(data[2]);
        return;
      }

      // EOSE: ["EOSE", subId] - End of Stored Events
      if (data[0] === 'EOSE') {
        finish(null);
        return;
      }
    };
  });
}
```

### Schritt 2: Kind 3 Fetch (`fetchContactList`)

```javascript
/**
 * Ruft die Kontaktliste (Kind 3) eines Pubkeys ab.
 * @param {string} pubkey - Hex pubkey
 * @param {string} relayUrl - Relay URL
 * @returns {Promise<Array>} - Array von {pubkey, relayUrl, petname}
 */
async function fetchContactList(pubkey, relayUrl) {
  const normalizedPubkey = normalizePubkeyHex(pubkey);
  if (!normalizedPubkey) return [];
  
  const normalizedRelay = normalizeRelayUrl(relayUrl);
  if (!normalizedRelay) return [];

  try {
    const events = await subscribeOnce(normalizedRelay, [
      { kinds: [3], authors: [normalizedPubkey], limit: 1 }
    ]);

    if (!events.length) return [];

    // Neuestes Event (höchstes created_at)
    const latest = events.sort((a, b) => b.created_at - a.created_at)[0];

    // p-Tags extrahieren: ["p", pubkey, relayUrl?, petname?]
    return latest.tags
      .filter(t => t[0] === 'p' && t[1])
      .map(t => ({
        pubkey: t[1],
        relayUrl: t[2] || null,
        petname: t[3] || null
      }));
  } catch (error) {
    console.warn('[Nostr] Failed to fetch contact list:', error.message);
    return [];
  }
}
```

### Schritt 3: Kind 0 Batch-Abruf (`fetchProfiles`)

```javascript
/**
 * Ruft Profile (Kind 0) für mehrere Pubkeys ab.
 * Max 100 Pubkeys pro Request (Relay-Limit).
 * @param {Array<string>} pubkeys - Array von Hex pubkeys
 * @param {string} relayUrl - Relay URL
 * @returns {Promise<Map<string, Object>>} - Map pubkey -> Profil
 */
async function fetchProfiles(pubkeys, relayUrl) {
  const normalizedRelay = normalizeRelayUrl(relayUrl);
  if (!normalizedRelay) return new Map();

  // Filter invalid pubkeys
  const validPubkeys = pubkeys
    .map(pk => normalizePubkeyHex(pk))
    .filter(Boolean);

  if (!validPubkeys.length) return new Map();

  // Chunk in 100er-Blöcke
  const chunks = [];
  for (let i = 0; i < validPubkeys.length; i += 100) {
    chunks.push(validPubkeys.slice(i, i + 100));
  }

  const profiles = new Map();

  for (const chunk of chunks) {
    try {
      const events = await subscribeOnce(normalizedRelay, [
        { kinds: [0], authors: chunk }
      ]);

      for (const event of events) {
        try {
          const meta = JSON.parse(event.content);
          // Neuestes Profil pro pubkey behalten
          const existing = profiles.get(event.pubkey);
          if (!existing || event.created_at > existing.fetchedAt) {
            profiles.set(event.pubkey, {
              displayName: String(meta.display_name || meta.name || '').trim(),
              name: String(meta.name || '').trim(),
              picture: String(meta.picture || '').trim(),
              nip05: String(meta.nip05 || '').trim(),
              about: String(meta.about || '').trim(),
              fetchedAt: Date.now(),
              createdAt: event.created_at
            });
          }
        } catch { /* skip malformed JSON */ }
      }
    } catch (error) {
      console.warn('[Nostr] Failed to fetch profiles chunk:', error.message);
    }
  }

  return profiles;
}
```

### Schritt 4: WP Members Fetch (`fetchWpMembers`)

```javascript
/**
 * Ruft WordPress-Benutzer mit Nostr-Profil ab.
 * @param {Object} wpApi - {restUrl, nonce}
 * @returns {Promise<Array>} - Array von Member-Objekten
 */
async function fetchWpMembers(wpApi) {
  const context = sanitizeWpApiContext(wpApi);
  if (!context) return [];

  const baseUrl = normalizeWpRestBaseUrl(context.restUrl);
  if (!baseUrl) return [];

  try {
    const endpoint = new URL('wp-nostr/v1/members', baseUrl).toString();
    const response = await fetch(endpoint, {
      headers: { 'X-WP-Nonce': context.nonce },
      credentials: 'include',
      cache: 'no-store'
    });

    if (!response.ok) return [];

    const data = await response.json();
    const members = data.members || data || [];

    return members
      .filter(m => m.pubkey || m.npub_hex || m.npub)
      .map(m => {
        // npub zu hex konvertieren falls nötig
        let pubkey = normalizePubkeyHex(m.pubkey || m.npub_hex);
        if (!pubkey && m.npub) {
          try {
            const decoded = nip19.decode(m.npub);
            if (decoded?.type === 'npub') {
              pubkey = decoded.data;
            }
          } catch { /* ignore */ }
        }

        return {
          pubkey,
          npub: m.npub || toNpub(pubkey) || '',
          displayName: String(m.display_name || m.displayName || m.name || '').trim(),
          name: String(m.name || m.user_login || '').trim(),
          picture: String(m.avatar_url || m.avatarUrl || '').trim(),
          nip05: String(m.nip05 || '').trim(),
          wpUserId: Number(m.user_id || m.userId) || null,
          source: 'wp'
        };
      })
      .filter(m => m.pubkey); // Nur mit gültigem pubkey
  } catch (error) {
    console.warn('[Nostr] Failed to fetch WP members:', error.message);
    return [];
  }
}
```

### Schritt 5: Merge-Logik (`mergeContacts`)

```javascript
/**
 * Führt Nostr-Kontakte und WP-Members zusammen.
 * @param {Array} nostrContacts - Kontakte aus Kind 3
 * @param {Map} profiles - Profile aus Kind 0
 * @param {Array} wpMembers - WP Members
 * @returns {Array} - Zusammengeführte Kontaktliste
 */
function mergeContacts(nostrContacts, profiles, wpMembers) {
  const merged = new Map();

  // 1. Nostr-Kontakte mit Profilen anreichern
  for (const c of nostrContacts) {
    const profile = profiles.get(c.pubkey) || {};
    merged.set(c.pubkey, {
      pubkey: c.pubkey,
      npub: toNpub(c.pubkey) || '',
      displayName: profile.displayName || '',
      name: profile.name || '',
      picture: profile.picture || '',
      nip05: profile.nip05 || '',
      about: profile.about || '',
      relayUrl: c.relayUrl || null,
      petname: c.petname || null,
      source: 'nostr',
      wpUserId: null,
      lastSeen: null
    });
  }

  // 2. WP-Members ergänzen/mergen
  for (const m of wpMembers) {
    if (!m.pubkey) continue;

    const existing = merged.get(m.pubkey);
    if (existing) {
      // Merge: WP-Daten ergänzen fehlende Felder
      merged.set(m.pubkey, {
        ...existing,
        displayName: existing.displayName || m.displayName,
        name: existing.name || m.name,
        picture: existing.picture || m.picture,
        nip05: existing.nip05 || m.nip05,
        source: 'both',
        wpUserId: m.wpUserId
      });
    } else {
      // Neuer WP-Kontakt
      merged.set(m.pubkey, {
        ...m,
        relayUrl: null,
        petname: null,
        lastSeen: null
      });
    }
  }

  // Nach displayName sortieren
  return Array.from(merged.values())
    .sort((a, b) => (a.displayName || a.name || '').localeCompare(b.displayName || b.name || ''));
}
```

### Schritt 6: Caching

```javascript
const CONTACTS_CACHE_KEY = 'nostrContactsCacheV1';
const CONTACTS_CACHE_TTL = 15 * 60 * 1000; // 15 Minuten

async function getCachedContacts(scope) {
  try {
    const result = await chrome.storage.local.get([CONTACTS_CACHE_KEY]);
    const cache = result[CONTACTS_CACHE_KEY];
    if (!cache || cache.scope !== scope) return null;
    if (Date.now() - cache.fetchedAt > CONTACTS_CACHE_TTL) return null;
    return cache.contacts;
  } catch {
    return null;
  }
}

async function setCachedContacts(scope, contacts) {
  try {
    await chrome.storage.local.set({
      [CONTACTS_CACHE_KEY]: {
        scope,
        contacts,
        fetchedAt: Date.now()
      }
    });
  } catch (error) {
    console.warn('[Nostr] Failed to cache contacts:', error.message);
  }
}

async function clearContactsCache() {
  try {
    await chrome.storage.local.remove([CONTACTS_CACHE_KEY]);
  } catch { /* ignore */ }
}
```

### Schritt 7: Message-Handler erweitern

Neue Message-Types in `handleMessage()`:

```javascript
// Nach NOSTR_PUBLISH_PROFILE einfügen:

if (request.type === 'NOSTR_GET_CONTACTS') {
  if (!isInternalExtensionRequest) {
    throw new Error('Contacts are only available from extension UI');
  }

  const scope = normalizeKeyScope(request.payload?.scope);
  const pubkey = await getKnownPublicKeyHex();
  if (!pubkey) {
    return { contacts: [], source: 'none', reason: 'no_key' };
  }

  // Cache prüfen
  const cached = await getCachedContacts(scope);
  if (cached) {
    return { contacts: cached, source: 'cache' };
  }

  // Relay-URL bestimmen (DM-Relay aus Settings oder Default)
  const dmRelayResult = await chrome.storage.local.get(['dmRelayUrl']);
  const relayUrl = normalizeRelayUrl(dmRelayResult.dmRelayUrl) || 'wss://relay.damus.io';

  // Kontakte abrufen
  const nostrContacts = await fetchContactList(pubkey, relayUrl);
  const pubkeys = nostrContacts.map(c => c.pubkey);
  const profiles = await fetchProfiles(pubkeys, relayUrl);

  // WP Members falls wpApi vorhanden
  let wpMembers = [];
  if (request.payload?.wpApi) {
    wpMembers = await fetchWpMembers(request.payload.wpApi);
  }

  // Merge
  const contacts = mergeContacts(nostrContacts, profiles, wpMembers);
  await setCachedContacts(scope, contacts);

  return { contacts, source: 'fresh' };
}

if (request.type === 'NOSTR_REFRESH_CONTACTS') {
  if (!isInternalExtensionRequest) {
    throw new Error('Contacts refresh is only available from extension UI');
  }

  await clearContactsCache();

  const scope = normalizeKeyScope(request.payload?.scope);
  const pubkey = await getKnownPublicKeyHex();
  if (!pubkey) {
    return { contacts: [], source: 'none', reason: 'no_key' };
  }

  const relayUrl = normalizeRelayUrl(request.payload?.relayUrl) ||
    normalizeRelayUrl((await chrome.storage.local.get(['dmRelayUrl'])).dmRelayUrl) ||
    'wss://relay.damus.io';

  const nostrContacts = await fetchContactList(pubkey, relayUrl);
  const pubkeys = nostrContacts.map(c => c.pubkey);
  const profiles = await fetchProfiles(pubkeys, relayUrl);

  let wpMembers = [];
  if (request.payload?.wpApi) {
    wpMembers = await fetchWpMembers(request.payload.wpApi);
  }

  const contacts = mergeContacts(nostrContacts, profiles, wpMembers);
  await setCachedContacts(scope, contacts);

  return { contacts, source: 'fresh' };
}

if (request.type === 'NOSTR_GET_WP_MEMBERS') {
  if (!isInternalExtensionRequest) {
    throw new Error('WP members are only available from extension UI');
  }

  const wpMembers = await fetchWpMembers(request.payload?.wpApi);
  return { members: wpMembers };
}
```

### Schritt 8: popup.js UI

In `popup.js` neue Funktionen für Kontaktliste:

```javascript
// Kontakte laden
async function loadContacts(forceRefresh = false) {
  const status = await sendMessage({ type: 'NOSTR_GET_STATUS' });
  if (!status.hasKey) {
    renderEmptyContacts('Kein Schlüssel vorhanden');
    return;
  }

  const wpApi = getWpApiContext();
  const payload = { scope: status.keyScope, wpApi };

  let result;
  if (forceRefresh) {
    result = await sendMessage({ type: 'NOSTR_REFRESH_CONTACTS', payload });
  } else {
    result = await sendMessage({ type: 'NOSTR_GET_CONTACTS', payload });
  }

  renderContacts(result.contacts || [], result.source);
}

// Kontakte rendern
function renderContacts(contacts, source) {
  const container = document.getElementById('contacts-list');
  if (!container) return;

  if (!contacts.length) {
    container.innerHTML = `
      <div class="empty-state">
        <p>Keine Kontakte gefunden</p>
        <p class="hint">Folge anderen Nostr-Nutzern, um sie hier zu sehen.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = contacts.map(c => `
    <div class="contact-item" data-pubkey="${c.pubkey}">
      <img class="contact-avatar" src="${c.picture || 'icons/icon48.png'}" alt="" />
      <div class="contact-info">
        <span class="contact-name">${escapeHtml(c.displayName || c.name || c.npub.slice(0, 12) + '…')}</span>
        ${c.nip05 ? `<span class="contact-nip05">${escapeHtml(c.nip05)}</span>` : ''}
      </div>
      <span class="contact-source">${c.source === 'both' ? '🔗' : (c.source === 'wp' ? 'WP' : '')}</span>
    </div>
  `).join('');
}
```

---

## Akzeptanzkriterien Check

- [x] Kind 3 Contact List wird vom konfigurierten Relay abgerufen
- [x] Kind 0 Profile werden batch-weise für alle Kontakte geladen
- [x] WP-User der Primary Domain werden per REST API abgerufen
- [x] Nostr- und WP-Kontakte werden korrekt zusammengeführt (Deduplizierung über Pubkey)
- [x] Kontaktdaten werden in `chrome.storage.local` gecacht (TTL: 15 min)
- [x] Force-Refresh möglich (Cache invalidieren)
- [x] Leerer Zustand wird graceful behandelt (kein Relay, kein Key, keine Kontakte)
- [x] Fehlgeschlagene Relay-Verbindung zeigt Fehlermeldung, blockiert nicht die UI
- [x] Max 100 Pubkeys pro Relay-Request (Chunking)
- [x] Background-Worker nutzt WebSocket für Relay-Verbindung

---

## Nächste Schritte

1. Code in background.js einfügen
2. Message-Handler erweitern
3. popup.js UI implementieren
4. Testen
