/**
 * NIP-17 Direct Messages (Gift-Wrapped DMs)
 * 
 * Protokoll-Funktionen, Cache-Verwaltung und Unread-Counter
 * für NIP-17 Direktnachrichten.
 * 
 * Struktur: Rumor (Kind 14) → Seal (Kind 13) → Gift Wrap (Kind 1059)
 */

import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools';
import { getNip44ConversationKey, nip44EncryptWithKey, nip44DecryptWithKey } from './crypto-handlers.js';

// ============================================================
// Konstanten
// ============================================================

export const DM_CACHE_KEY = 'nostrDmCacheV2';
export const DM_CACHE_KEY_V1 = 'nostrDmCacheV1';
export const DM_CACHE_MAX_PER_CONVERSATION = 200;
export const DM_UNREAD_COUNT_KEY = 'dmUnreadCount';
export const DM_NOTIFICATIONS_KEY = 'dmNotificationsEnabled';

// ============================================================
// Utility
// ============================================================

/**
 * Stellt sicher, dass ein Key immer ein valides Uint8Array ist.
 * Chrome storage serialisiert Uint8Array zu {0: x, 1: y, ...} Objekten.
 * @param {any} key - Key in beliebigem Format
 * @returns {Uint8Array|null} - Uint8Array oder null/undefined falls Input falsy
 */
export function ensureUint8(key) {
  if (!key) return key;
  if (key instanceof Uint8Array) return key;
  if (Array.isArray(key)) return new Uint8Array(key);
  if (typeof key === 'object') return new Uint8Array(Object.values(key));
  return key;
}

/**
 * Formatiert einen Pubkey kurz für Anzeige.
 * @param {string} pubkey - Hex pubkey
 * @returns {string} - Formatierter String (z.B. "ab12cd34…ef567890")
 */
export function formatShortHex(pubkey) {
  if (!pubkey || pubkey.length < 16) return pubkey || '';
  return `${pubkey.slice(0, 8)}…${pubkey.slice(-8)}`;
}

/**
 * Berechnet einen stabilen Content-Hash für Dedup.
 * @param {string} str - String
 * @returns {string} - Hex-Hash
 */
function contentHash(str) {
  return Array.from(str)
    .reduce((h, c) => Math.imul(31, h) + c.charCodeAt(0) | 0, 0)
    .toString(16);
}

/**
 * Berechnet eine stabile innere ID für eine DM.
 * Identisch für wrapForRecipient und wrapForSelf, da auf dem Rumor basierend.
 * @param {string} senderPubkey - Hex pubkey des Absenders
 * @param {number} createdAt - Unix Timestamp des Rumors
 * @param {string} content - Klartext-Inhalt
 * @returns {string} - Stabile innere ID
 */
export function computeInnerId(senderPubkey, createdAt, content) {
  return createdAt + ':' + senderPubkey.slice(0, 8) + ':' + contentHash(content);
}

// ============================================================
// NIP-17 Protokoll-Funktionen
// ============================================================

/**
 * Randomisiert einen Timestamp um ±5 Minuten für Gift Wrap/Seal.
 * NIP-17 verlangt randomisierte Timestamps für Metadaten-Schutz.
 * @returns {number} - Unix Timestamp mit Jitter
 */
export function randomizeTimestamp() {
  const now = Math.floor(Date.now() / 1000);
  // ±5 Minuten Jitter (300 Sekunden)
  // Viele Relays weisen Events ab, die zu weit in der Vergangenheit/Zukunft liegen.
  const jitter = Math.floor(Math.random() * 600) - 300;
  return now + jitter;
}

/**
 * Erstellt einen Rumor (Kind 14) - die eigentliche Nachricht.
 * NICHT signiert (Abstreitbarkeit gemäß NIP-17).
 * @param {string} senderPubkey - Hex pubkey des Absenders
 * @param {string} recipientPubkey - Hex pubkey des Empfängers
 * @param {string} content - Klartext-Nachricht
 * @returns {Object} - Rumor Event (nicht signiert)
 */
export function createRumor(senderPubkey, recipientPubkey, content) {
  return {
    kind: 14,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['p', recipientPubkey]],
    content: content,
    pubkey: senderPubkey
  };
}

/**
 * Erstellt einen Seal (Kind 13) - signiert mit Absender-Key.
 * Verschlüsselt den Rumor mit NIP-44 (SharedSecret zwischen Sender und Empfänger).
 * @param {Uint8Array} senderPrivateKey - Secret Key des Absenders
 * @param {string} senderPubkey - Hex pubkey des Absenders
 * @param {string} recipientPubkey - Hex pubkey des Empfängers
 * @param {Object} rumor - Der Rumor (Kind 14)
 * @returns {Object} - Signiertes Seal Event (Kind 13)
 */
export function createSeal(senderPrivateKey, senderPubkey, recipientPubkey, rumor) {
  const conversationKey = getNip44ConversationKey(senderPrivateKey, recipientPubkey);
  const sealContent = nip44EncryptWithKey(JSON.stringify(rumor), conversationKey);

  return finalizeEvent({
    kind: 13,
    created_at: randomizeTimestamp(),
    tags: [],
    content: sealContent
  }, senderPrivateKey);
}

/**
 * Erstellt einen Gift Wrap (Kind 1059) - signiert mit Wegwerf-Key.
 * Der Wegwerf-Key wird nach der Erstellung sicher gelöscht.
 * @param {Object} seal - Das signierte Seal Event (Kind 13)
 * @param {string} recipientPubkey - Hex pubkey des Empfängers
 * @returns {Object} - Signiertes Gift Wrap Event (Kind 1059)
 */
export function createGiftWrap(seal, recipientPubkey) {
  const wrapKey = generateSecretKey();
  const conversationKey = getNip44ConversationKey(wrapKey, recipientPubkey);
  const wrapContent = nip44EncryptWithKey(JSON.stringify(seal), conversationKey);

  const giftWrap = finalizeEvent({
    kind: 1059,
    created_at: randomizeTimestamp(),
    tags: [['p', recipientPubkey]],
    content: wrapContent
  }, wrapKey);

  // Wegwerf-Schlüssel sicher löschen
  wrapKey.fill(0);

  return giftWrap;
}

/**
 * Erstellt eine vollständige Gift-Wrapped DM (für Empfänger + Selbst-Kopie).
 * 
 * Erzeugt zwei Gift Wraps:
 * 1. wrapForRecipient: Verschlüsselt mit SharedSecret(Sender, Empfänger)
 * 2. wrapForSelf: Verschlüsselt mit SharedSecret(Sender, Sender) - Selbst-Kopie
 * 
 * @param {Uint8Array} senderPrivateKey - Secret Key des Absenders
 * @param {string} recipientPubkey - Hex pubkey des Empfängers
 * @param {string} content - Klartext-Nachricht
 * @returns {Object} - { wrapForRecipient, wrapForSelf, rumorId }
 */
export function createGiftWrappedDM(senderPrivateKey, recipientPubkey, content) {
  const senderPubkey = getPublicKey(senderPrivateKey);

  // 1. Rumor erstellen (Kind 14, nicht signiert)
  const rumor = createRumor(senderPubkey, recipientPubkey, content);

  // 2. Seal für Empfänger (SharedSecret: Sender ↔ Empfänger)
  const sealForRecipient = createSeal(senderPrivateKey, senderPubkey, recipientPubkey, rumor);

  // 3. Gift Wrap für Empfänger
  const wrapForRecipient = createGiftWrap(sealForRecipient, recipientPubkey);

  // 4. Seal für Selbst-Kopie (SharedSecret: Sender ↔ Sender)
  const sealForSelf = createSeal(senderPrivateKey, senderPubkey, senderPubkey, rumor);

  // 5. Gift Wrap für Selbst-Kopie
  const wrapForSelf = createGiftWrap(sealForSelf, senderPubkey);

  return {
    wrapForRecipient,
    wrapForSelf,
    innerId: computeInnerId(senderPubkey, rumor.created_at, content),
    rumorId: rumor.created_at + ':' + senderPubkey.slice(0, 8)
  };
}

/**
 * Entschlüsselt einen Gift Wrap und extrahiert die Nachricht.
 * 
 * Entschlüsselungs-Kette:
 * Gift Wrap (Kind 1059) → Seal (Kind 13) → Rumor (Kind 14)
 * 
 * @param {Uint8Array} recipientPrivateKey - Secret Key des Empfängers
 * @param {Object} giftWrapEvent - Das Gift Wrap Event (Kind 1059)
 * @returns {Object} - Entschlüsselte Nachricht mit id, content, senderPubkey, recipientPubkey, etc.
 * @throws {Error} - Bei Entschlüsselungsfehlern oder ungültiger Struktur
 */
export function unwrapGiftWrap(recipientPrivateKey, giftWrapEvent) {
  // Safety: Key muss Uint8Array sein (Chrome storage serialisiert zu Object)
  recipientPrivateKey = ensureUint8(recipientPrivateKey);

  // 1. Gift Wrap entschlüsseln → Seal
  const wrapConversationKey = getNip44ConversationKey(recipientPrivateKey, giftWrapEvent.pubkey);

  let seal;
  try {
    const sealJson = nip44DecryptWithKey(giftWrapEvent.content, wrapConversationKey);
    seal = JSON.parse(sealJson);
  } catch (e) {
    throw new Error('Failed to decrypt gift wrap: ' + e.message);
  }

  // 2. Seal validieren
  if (seal.kind !== 13) {
    throw new Error('Invalid seal kind: expected 13, got ' + seal.kind);
  }

  // 3. Seal entschlüsseln → Rumor
  // seal.pubkey ist der echte Absender
  const sealConversationKey = getNip44ConversationKey(recipientPrivateKey, seal.pubkey);

  let rumor;
  try {
    const rumorJson = nip44DecryptWithKey(seal.content, sealConversationKey);
    rumor = JSON.parse(rumorJson);
  } catch (e) {
    throw new Error('Failed to decrypt seal: ' + e.message);
  }

  // 4. Rumor validieren
  if (rumor.kind !== 14) {
    throw new Error('Invalid rumor kind: expected 14, got ' + rumor.kind);
  }

  // 5. Pubkey-Consistency: Seal.pubkey muss Rumor.pubkey entsprechen
  if (rumor.pubkey !== seal.pubkey) {
    throw new Error('Pubkey mismatch: seal pubkey does not match rumor pubkey');
  }

  // Empfänger aus p-Tag
  const recipientTag = rumor.tags?.find(t => t[0] === 'p');
  const recipientPubkey = recipientTag?.[1] || '';

  // Eindeutige innere ID (stabil über beide Gift Wraps)
  const innerId = computeInnerId(rumor.pubkey, rumor.created_at, rumor.content);

  return {
    id: giftWrapEvent.id,
    innerId,
    pubkey: rumor.pubkey,
    content: rumor.content,
    createdAt: rumor.created_at,
    kind: rumor.kind,
    tags: rumor.tags,
    senderPubkey: rumor.pubkey,
    recipientPubkey: recipientPubkey
  };
}

// ============================================================
// DM Cache Funktionen (Konversations-basiert)
// ============================================================
// Cache-Struktur V2:
// {
//   ownerPubkey: "hex...",
//   scope: "global",
//   conversations: {
//     "contactHexPubkey": [ { id, innerId, senderPubkey, recipientPubkey, content, createdAt, direction, giftWrapId, receivedAt }, ... ],
//     ...
//   },
//   updatedAt: 1234567890
// }
// Jede Konversation ist strikt an das Paar owner:contact gebunden.

/**
 * Ermittelt den Gesprächspartner-Key für eine Nachricht.
 * @param {Object} msg - Nachricht mit senderPubkey und recipientPubkey
 * @param {string} ownerPubkey - Eigener Pubkey
 * @returns {string|null} - Pubkey des Gesprächspartners
 */
function resolveConversationPartner(msg, ownerPubkey) {
  if (!msg.senderPubkey || !msg.recipientPubkey || !ownerPubkey) return null;
  if (msg.senderPubkey === ownerPubkey) return msg.recipientPubkey;
  if (msg.recipientPubkey === ownerPubkey) return msg.senderPubkey;
  // Nachricht gehört nicht zu diesem Owner
  return null;
}

/**
 * Lädt den Cache und migriert bei Bedarf vom V1-Format.
 * @returns {Promise<Object>} Cache-Objekt
 */
async function loadDmCache() {
  const result = await chrome.storage.local.get([DM_CACHE_KEY, DM_CACHE_KEY_V1]);

  // V2 vorhanden → direkt nutzen
  if (result[DM_CACHE_KEY]) {
    return result[DM_CACHE_KEY];
  }

  // V1 vorhanden → migrieren
  const v1 = result[DM_CACHE_KEY_V1];
  if (v1 && v1.messages?.length > 0 && v1.ownerPubkey) {
    console.log('[NIP-17] Migrating DM cache V1 → V2, messages:', v1.messages.length);
    const v2 = {
      ownerPubkey: v1.ownerPubkey,
      scope: v1.scope || 'global',
      conversations: {},
      updatedAt: Date.now()
    };
    for (const msg of v1.messages) {
      const partner = resolveConversationPartner(msg, v1.ownerPubkey);
      if (!partner) continue;
      if (!v2.conversations[partner]) v2.conversations[partner] = [];
      v2.conversations[partner].push(msg);
    }
    // Speichern und V1 löschen
    await chrome.storage.local.set({ [DM_CACHE_KEY]: v2 });
    await chrome.storage.local.remove([DM_CACHE_KEY_V1]);
    return v2;
  }

  // Kein Cache vorhanden
  return null;
}

/**
 * Speichert eine Nachricht im Cache.
 * Konversations-basierte Speicherung: owner:contact Paar als Key.
 * 
 * @param {Object} msg - Die Nachricht (muss senderPubkey + recipientPubkey haben)
 * @param {string} scope - Der Key Scope
 * @param {string} ownerPubkey - Eigener Pubkey (PFLICHT für korrekte Zuordnung)
 * @returns {Object} - Die gecachte Nachricht (mit receivedAt)
 */
export async function cacheDmMessage(msg, scope, ownerPubkey) {
  if (!ownerPubkey) {
    console.warn('[NIP-17] cacheDmMessage called without ownerPubkey, skipping');
    return msg;
  }
  try {
    let cache = await loadDmCache();

    // Neuer oder Key-gewechselter Cache
    if (!cache || (cache.ownerPubkey && cache.ownerPubkey !== ownerPubkey)) {
      if (cache?.ownerPubkey) {
        console.log('[NIP-17] Key changed, resetting DM cache. Old:', cache.ownerPubkey.slice(0, 8), 'New:', ownerPubkey.slice(0, 8));
      }
      cache = { ownerPubkey, scope, conversations: {}, updatedAt: Date.now() };
    }

    // Gesprächspartner ermitteln
    const partner = resolveConversationPartner(msg, ownerPubkey);
    if (!partner) {
      // Nachricht gehört nicht zu diesem Owner — überspringen
      return msg;
    }

    if (!cache.conversations[partner]) {
      cache.conversations[partner] = [];
    }
    const convo = cache.conversations[partner];

    // Deduplizierung: innerId (primär), dann giftWrapId/id (Fallback)
    const dedupInnerId = msg.innerId;
    if (dedupInnerId && convo.some(m => m.innerId === dedupInnerId)) return msg;

    const dedupId = msg.giftWrapId || msg.id;
    if (dedupId && convo.some(m => (m.giftWrapId || m.id) === dedupId)) return msg;

    const cachedMsg = { ...msg, receivedAt: msg.receivedAt || Date.now() };
    convo.push(cachedMsg);

    // Chronologisch sortieren
    convo.sort((a, b) => a.createdAt - b.createdAt);

    // Max-Größe pro Konversation begrenzen
    if (convo.length > DM_CACHE_MAX_PER_CONVERSATION) {
      cache.conversations[partner] = convo.slice(-DM_CACHE_MAX_PER_CONVERSATION);
    }

    cache.scope = scope;
    cache.ownerPubkey = ownerPubkey;
    cache.updatedAt = Date.now();

    await chrome.storage.local.set({ [DM_CACHE_KEY]: cache });
    return cachedMsg;
  } catch (error) {
    console.warn('[NIP-17] Failed to cache message:', error.message);
    return msg;
  }
}

/**
 * Speichert mehrere Nachrichten im Cache.
 * @param {Array} messages - Array von Nachrichten
 * @param {string} scope - Der Key Scope
 * @param {string} ownerPubkey - Eigener Pubkey
 */
export async function cacheDmMessages(messages, scope, ownerPubkey) {
  for (const msg of messages) {
    await cacheDmMessage(msg, scope, ownerPubkey);
  }
}

/**
 * Holt Nachrichten aus dem Cache für eine bestimmte Konversation.
 * 
 * @param {string} scope - Der Key Scope
 * @param {string|null} contactPubkey - Pubkey des Gesprächspartners (null = alle)
 * @param {string|null} ownerPubkey - Eigener Pubkey für Validierung
 * @returns {Promise<Array>} - Array von Nachrichten
 */
export async function getCachedDmMessages(scope, contactPubkey = null, ownerPubkey = null) {
  try {
    const cache = await loadDmCache();
    if (!cache || cache.scope !== scope) return [];

    // Pubkey-Validierung
    if (ownerPubkey && cache.ownerPubkey && cache.ownerPubkey !== ownerPubkey) {
      return [];
    }

    if (contactPubkey) {
      // Einzelne Konversation: direkt per Key zugreifen
      return cache.conversations[contactPubkey] || [];
    }

    // Alle Nachrichten aller Konversationen (flat + sortiert)
    const all = [];
    for (const convo of Object.values(cache.conversations)) {
      all.push(...convo);
    }
    all.sort((a, b) => a.createdAt - b.createdAt);
    return all;
  } catch {
    return [];
  }
}

/**
 * Gibt eine Liste aller Konversationspartner mit Metadaten zurück.
 * @param {string} scope - Der Key Scope
 * @returns {Promise<Array<{pubkey: string, messageCount: number, lastMessageAt: number, lastMessage: string}>>}
 */
export async function getConversationList(scope) {
  try {
    const cache = await loadDmCache();
    if (!cache || cache.scope !== scope) return [];

    const list = [];
    for (const [pubkey, messages] of Object.entries(cache.conversations)) {
      if (!messages.length) continue;
      const lastMsg = messages[messages.length - 1];
      list.push({
        pubkey,
        messageCount: messages.length,
        lastMessageAt: lastMsg.createdAt || 0,
        lastMessage: lastMsg.content?.slice(0, 80) || '',
        lastDirection: lastMsg.direction || 'in'
      });
    }
    // Nach letzter Nachricht sortieren (neueste zuerst)
    list.sort((a, b) => b.lastMessageAt - a.lastMessageAt);
    return list;
  } catch {
    return [];
  }
}

/**
 * Löscht den gesamten DM Cache (V1 + V2).
 */
export async function clearDmCache() {
  try {
    await chrome.storage.local.remove([DM_CACHE_KEY, DM_CACHE_KEY_V1]);
  } catch { /* ignore */ }
}

// ============================================================
// Unread Counter
// ============================================================

/**
 * Inkrementiert den Unread-Counter und aktualisiert das Badge.
 */
export async function incrementUnreadCount() {
  try {
    const result = await chrome.storage.local.get([DM_UNREAD_COUNT_KEY]);
    const count = (result[DM_UNREAD_COUNT_KEY] || 0) + 1;
    await chrome.storage.local.set({ [DM_UNREAD_COUNT_KEY]: count });

    if (count > 0) {
      chrome.action.setBadgeText({ text: count > 99 ? '99+' : String(count) });
      chrome.action.setBadgeBackgroundColor({ color: '#3b82f6' });
    }
  } catch (error) {
    console.warn('[NIP-17] Failed to increment unread count:', error.message);
  }
}

/**
 * Setzt den Unread-Counter zurück und entfernt das Badge.
 */
export async function clearUnreadCount() {
  try {
    await chrome.storage.local.set({ [DM_UNREAD_COUNT_KEY]: 0 });
    chrome.action.setBadgeText({ text: '' });
  } catch (error) {
    console.warn('[NIP-17] Failed to clear unread count:', error.message);
  }
}

/**
 * Holt den aktuellen Unread-Counter.
 * @returns {Promise<number>}
 */
export async function getUnreadCount() {
  try {
    const result = await chrome.storage.local.get([DM_UNREAD_COUNT_KEY]);
    return result[DM_UNREAD_COUNT_KEY] || 0;
  } catch {
    return 0;
  }
}
