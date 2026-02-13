// Background Service Worker
// Importiert nostr-tools via Rollup Bundle

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { KeyManager } from './lib/key-manager.js';
import { checkDomainAccess, DOMAIN_STATUS, allowDomain, verifyWhitelistSignature } from './lib/domain-access.js';
import { 
  handleNIP04Encrypt, handleNIP04Decrypt, handleNIP44Encrypt, handleNIP44Decrypt,
} from './lib/crypto-handlers.js';
import {
  ensureUint8,
  createGiftWrappedDM,
  unwrapGiftWrap,
  DM_NOTIFICATIONS_KEY,
  cacheDmMessage, cacheDmMessages, getCachedDmMessages, clearDmCache,
  incrementUnreadCount,
  formatShortHex
} from './lib/nip17-chat.js';

const CURRENT_VERSION = '1.0.0';
const DOMAIN_SYNC_CONFIGS_KEY = 'domainSyncConfigs';
const UNLOCK_CACHE_POLICY_KEY = 'unlockCachePolicy';
const UNLOCK_PASSWORD_SESSION_KEY = 'unlockPasswordSession';
const UNLOCK_PASSKEY_SESSION_KEY = 'unlockPasskeySession';
const UNLOCK_CACHE_POLICY_DEFAULT = '15m';
const UNLOCK_CACHE_ALLOWED_POLICY_LIST = ['off', '5m', '15m', '30m', '60m', 'session'];
const UNLOCK_CACHE_ALLOWED_POLICIES = new Set(UNLOCK_CACHE_ALLOWED_POLICY_LIST);
const KEY_SCOPE_DEFAULT = 'global';
const LAST_ACTIVE_SCOPE_KEY = 'lastActiveKeyScope';

// Global KeyManager Instance
const keyManager = new KeyManager();

// Passwort-Cache (nur f????r laufende Session, wird bei SW-Stop gel????scht)
let cachedPassword = null;
let cachedPasswordExpiresAt = null;
let cachedPasskeyVerified = false;
let cachedPasskeyExpiresAt = null;
let activeKeyScope = KEY_SCOPE_DEFAULT;
let activeDmSubscriptionIds = [];
let activeScopeRestored = false;
const DIALOG_TIMEOUT_MS = 25000;
const PASSKEY_DIALOG_TIMEOUT_MS = 180000;

/**
 * Restore the last active key scope from storage on service worker cold start.
 * This ensures that the scope set on the primary domain survives SW restarts
 * and propagates correctly to other domains via the fallback in getKeyScopeFromRequest.
 */
async function restoreActiveScope() {
  if (activeScopeRestored) return;
  activeScopeRestored = true;
  try {
    const stored = await chrome.storage.local.get([LAST_ACTIVE_SCOPE_KEY]);
    const lastScope = normalizeKeyScope(stored[LAST_ACTIVE_SCOPE_KEY]);
    if (lastScope !== KEY_SCOPE_DEFAULT && lastScope !== activeKeyScope) {
      activeKeyScope = lastScope;
      keyManager.setNamespace(lastScope);
    }
  } catch {
    // ignore – keep default scope
  }
}

function extractPasswordFromDialogResult(result) {
  if (!result) return null;
  if (typeof result === 'string') return result; // backward compatibility
  if (result.noPassword === true) return null;
  return typeof result.password === 'string' ? result.password : null;
}

function normalizeUnlockCachePolicy(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (UNLOCK_CACHE_ALLOWED_POLICIES.has(raw)) return raw;
  return UNLOCK_CACHE_POLICY_DEFAULT;
}

function getUnlockCacheTtlMs(policy) {
  if (policy === 'off') return 0;
  if (policy === 'session') return null;
  if (/^\d+m$/.test(policy)) {
    return Number(policy.slice(0, -1)) * 60 * 1000;
  }
  return 15 * 60 * 1000;
}

function isCacheExpired(expiresAt) {
  return typeof expiresAt === 'number' && Date.now() >= expiresAt;
}

async function getUnlockCachePolicy() {
  const result = await chrome.storage.local.get([UNLOCK_CACHE_POLICY_KEY]);
  const normalized = normalizeUnlockCachePolicy(result[UNLOCK_CACHE_POLICY_KEY]);
  if (normalized !== result[UNLOCK_CACHE_POLICY_KEY]) {
    await chrome.storage.local.set({ [UNLOCK_CACHE_POLICY_KEY]: normalized });
  }
  return normalized;
}

async function clearCachedPassword() {
  cachedPassword = null;
  cachedPasswordExpiresAt = null;
  await chrome.storage.session.remove(UNLOCK_PASSWORD_SESSION_KEY);
}

async function clearCachedPasskeyAuth() {
  cachedPasskeyVerified = false;
  cachedPasskeyExpiresAt = null;
  await chrome.storage.session.remove(UNLOCK_PASSKEY_SESSION_KEY);
}

async function clearUnlockCaches() {
  await Promise.all([
    clearCachedPassword(),
    clearCachedPasskeyAuth()
  ]);
}

async function getCachedPassword() {
  if (typeof cachedPassword === 'string' && cachedPassword.length > 0) {
    if (!isCacheExpired(cachedPasswordExpiresAt)) {
      return cachedPassword;
    }
    await clearCachedPassword();
    return null;
  }

  const result = await chrome.storage.session.get([UNLOCK_PASSWORD_SESSION_KEY]);
  const sessionCache = result[UNLOCK_PASSWORD_SESSION_KEY];
  if (!sessionCache || typeof sessionCache.password !== 'string' || sessionCache.password.length === 0) {
    return null;
  }

  const expiresAt = typeof sessionCache.expiresAt === 'number' ? sessionCache.expiresAt : null;
  if (isCacheExpired(expiresAt)) {
    await clearCachedPassword();
    return null;
  }

  cachedPassword = sessionCache.password;
  cachedPasswordExpiresAt = expiresAt;
  return cachedPassword;
}

async function cachePasswordWithPolicy(password) {
  if (!password) {
    await clearCachedPassword();
    return;
  }

  const policy = await getUnlockCachePolicy();
  if (policy === 'off') {
    await clearCachedPassword();
    return;
  }

  const ttlMs = getUnlockCacheTtlMs(policy);
  const expiresAt = ttlMs === null ? null : (Date.now() + ttlMs);
  cachedPassword = password;
  cachedPasswordExpiresAt = expiresAt;

  await chrome.storage.session.set({
    [UNLOCK_PASSWORD_SESSION_KEY]: {
      password,
      expiresAt,
      policy,
      cachedAt: Date.now()
    }
  });
}

async function getCachedPasskeyAuth() {
  if (cachedPasskeyVerified) {
    if (!isCacheExpired(cachedPasskeyExpiresAt)) {
      return true;
    }
    await clearCachedPasskeyAuth();
    return false;
  }

  const result = await chrome.storage.session.get([UNLOCK_PASSKEY_SESSION_KEY]);
  const sessionCache = result[UNLOCK_PASSKEY_SESSION_KEY];
  if (!sessionCache || sessionCache.verified !== true) {
    return false;
  }

  const expiresAt = typeof sessionCache.expiresAt === 'number' ? sessionCache.expiresAt : null;
  if (isCacheExpired(expiresAt)) {
    await clearCachedPasskeyAuth();
    return false;
  }

  cachedPasskeyVerified = true;
  cachedPasskeyExpiresAt = expiresAt;
  return true;
}

async function cachePasskeyAuthWithPolicy() {
  const policy = await getUnlockCachePolicy();
  if (policy === 'off') {
    await clearCachedPasskeyAuth();
    return;
  }

  const ttlMs = getUnlockCacheTtlMs(policy);
  const expiresAt = ttlMs === null ? null : (Date.now() + ttlMs);
  cachedPasskeyVerified = true;
  cachedPasskeyExpiresAt = expiresAt;

  await chrome.storage.session.set({
    [UNLOCK_PASSKEY_SESSION_KEY]: {
      verified: true,
      expiresAt,
      policy,
      cachedAt: Date.now()
    }
  });
}

async function ensurePasswordIfNeeded(passwordProtected) {
  if (!passwordProtected) return null;

  const cached = await getCachedPassword();
  if (cached) {
    try {
      const testKey = await keyManager.getKey(cached);
      if (testKey) {
        testKey.fill(0);
        return cached;
      }
    } catch {
      // Cache invalid/outdated - continue to interactive unlock.
    }
    await clearCachedPassword();
  }

  const unlockResult = await promptPassword('unlock');
  const password = extractPasswordFromDialogResult(unlockResult);
  if (!password) throw new Error('Password required');

  await cachePasswordWithPolicy(password);
  return password;
}

async function ensurePasskeyIfNeeded(passkeyAuthOptions = null) {
  const cached = await getCachedPasskeyAuth();
  if (cached) return true;

  const unlockResult = await promptPassword('unlock-passkey', passkeyAuthOptions);
  if (!unlockResult || unlockResult.passkey !== true) {
    throw new Error('Passkey required');
  }

  await cachePasskeyAuthWithPolicy();
  return true;
}

async function ensureUnlockForMode(mode, passkeyAuthOptions = null) {
  if (mode === KeyManager.MODE_PASSWORD) {
    return await ensurePasswordIfNeeded(true);
  }
  if (mode === KeyManager.MODE_PASSKEY) {
    await ensurePasskeyIfNeeded(passkeyAuthOptions);
    return null;
  }
  return null;
}

function normalizeKeyScope(scope) {
  const value = String(scope || '').trim();
  if (!value) return KEY_SCOPE_DEFAULT;
  if (value === KEY_SCOPE_DEFAULT) return KEY_SCOPE_DEFAULT;
  if (!/^[a-zA-Z0-9:._-]{1,120}$/.test(value)) return KEY_SCOPE_DEFAULT;
  return value;
}

function getKeyScopeFromRequest(request, { isWebRequest = false } = {}) {
  const explicit = typeof request?.scope === 'string'
    ? request.scope
    : (typeof request?.payload?.scope === 'string' ? request.payload.scope : '');
  const normalized = normalizeKeyScope(explicit);

  // If scope resolves to 'global' but we have an active non-global scope,
  // inherit it for web requests (non-WP pages without nostrConfig).
  if (isWebRequest && normalized === KEY_SCOPE_DEFAULT && activeKeyScope !== KEY_SCOPE_DEFAULT) {
    return activeKeyScope;
  }

  return normalized;
}

async function ensureKeyScope(scope) {
  const nextScope = normalizeKeyScope(scope);
  if (nextScope === activeKeyScope) {
    return nextScope;
  }

  activeKeyScope = nextScope;
  await chrome.storage.local.set({ [LAST_ACTIVE_SCOPE_KEY]: activeKeyScope });
  keyManager.setNamespace(nextScope === KEY_SCOPE_DEFAULT ? '' : nextScope);
  await keyManager.migrateFromLegacyGlobalIfNeeded();
  await clearUnlockCaches();
  return nextScope;
}

async function listStoredKeyScopes() {
  const all = await chrome.storage.local.get(null);
  const scopes = new Set();

  if (all[KeyManager.STORAGE_KEY] || all[KeyManager.PLAIN_KEY]) {
    scopes.add(KEY_SCOPE_DEFAULT);
  }

  for (const key of Object.keys(all)) {
    const match = key.match(/^(.+?)::(encrypted_nsec|plain_nsec)$/);
    if (match && match[1]) {
      scopes.add(normalizeKeyScope(match[1]));
    }
  }

  return Array.from(scopes).sort((a, b) => a.localeCompare(b));
}

function resolvePreferredScope(requestedScope, scopes, lastActiveScope) {
  const scopeSet = new Set(scopes);
  const requested = normalizeKeyScope(requestedScope);
  const lastActive = normalizeKeyScope(lastActiveScope);

  if (scopeSet.has(requested)) return requested;
  if (scopeSet.has(lastActive)) return lastActive;
  if (scopeSet.has(KEY_SCOPE_DEFAULT)) return KEY_SCOPE_DEFAULT;
  return scopes[0] || KEY_SCOPE_DEFAULT;
}

function sanitizeWpApiContext(rawContext) {
  if (!rawContext || typeof rawContext !== 'object') return null;
  const restUrl = String(rawContext.restUrl || '').trim();
  const nonce = String(rawContext.nonce || '').trim();
  if (!restUrl || !nonce) return null;
  return { restUrl, nonce };
}

function sanitizePasskeyAuthBroker(rawBroker) {
  if (!rawBroker || typeof rawBroker !== 'object') return null;

  const enabled = rawBroker.enabled === true || rawBroker.enabled === 1 || rawBroker.enabled === '1';
  const rawUrl = String(rawBroker.url || rawBroker.authBrokerUrl || '').trim();
  if (!enabled && !rawUrl) return null;
  if (!rawUrl) return null;

  try {
    const parsed = new URL(rawUrl);
    if (!/^https?:$/i.test(parsed.protocol)) return null;

    const origin = String(rawBroker.origin || rawBroker.authBrokerOrigin || '').trim();
    const rpIdRaw = String(rawBroker.rpId || rawBroker.authBrokerRpId || '').trim().toLowerCase();

    return {
      enabled,
      url: parsed.href,
      origin: origin || parsed.origin,
      rpId: rpIdRaw || parsed.hostname.toLowerCase()
    };
  } catch {
    return null;
  }
}

function normalizeWpRestBaseUrl(restUrl) {
  const value = String(restUrl || '').trim();
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!/^https?:$/i.test(url.protocol)) return null;
    return url.href.endsWith('/') ? url.href : `${url.href}/`;
  } catch {
    return null;
  }
}

async function wpApiPostJson(wpApiContext, path, payload = null) {
  const context = sanitizeWpApiContext(wpApiContext);
  if (!context) {
    throw new Error('WordPress API context missing (restUrl/nonce).');
  }
  const baseUrl = normalizeWpRestBaseUrl(context.restUrl);
  if (!baseUrl) {
    throw new Error('Invalid WordPress REST URL.');
  }
  const endpoint = new URL(path.replace(/^\//, ''), baseUrl).toString();
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-WP-Nonce': context.nonce
    },
    credentials: 'include',
    cache: 'no-store',
    body: payload === null ? '{}' : JSON.stringify(payload)
  });

  let result = {};
  try {
    result = await response.json();
  } catch {
    result = {};
  }

  if (!response.ok) {
    const message = String(result?.message || `HTTP ${response.status}`);
    const error = new Error(message);
    error.code = String(result?.code || '');
    error.status = Number(response.status || 0);
    throw error;
  }

  return result;
}

function bytesToBase64(bytes) {
  const value = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < value.length; i += chunkSize) {
    const chunk = value.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(input) {
  const normalized = String(input || '').replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + (arr?.length || 0), 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    if (!arr) continue;
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

async function derivePasskeyWrapKey(credentialId, scope) {
  const id = String(credentialId || '').trim();
  if (!id) {
    throw new Error('Passkey credential id missing.');
  }
  const encoder = new TextEncoder();
  const secretMaterial = encoder.encode(`wp-nostr-passkey-wrap-v1|${id}`);
  const salt = encoder.encode(`wp-nostr-backup-scope|${normalizeKeyScope(scope)}`);
  const baseKey = await crypto.subtle.importKey('raw', secretMaterial, 'PBKDF2', false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptAesGcmBytes(key, plaintextBytes, aadBytes = null) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const algorithm = { name: 'AES-GCM', iv };
  if (aadBytes) algorithm.additionalData = aadBytes;
  const ciphertext = await crypto.subtle.encrypt(algorithm, key, plaintextBytes);
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

async function decryptAesGcmBytes(key, iv, ciphertextBytes, aadBytes = null) {
  const algorithm = { name: 'AES-GCM', iv };
  if (aadBytes) algorithm.additionalData = aadBytes;
  const plaintext = await crypto.subtle.decrypt(algorithm, key, ciphertextBytes);
  return new Uint8Array(plaintext);
}

async function computeKeyFingerprint(pubkeyHex) {
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(String(pubkeyHex || '').toLowerCase()));
  return bytesToBase64(new Uint8Array(digest));
}

async function computePasskeyCredentialFingerprint(credentialId) {
  const id = String(credentialId || '').trim();
  if (!id) return null;
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(id));
  return bytesToBase64(new Uint8Array(digest));
}

function normalizePubkeyHex(pubkeyHex) {
  const value = String(pubkeyHex || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(value)) return null;
  return value;
}

function toNpub(pubkeyHex) {
  const normalized = normalizePubkeyHex(pubkeyHex);
  if (!normalized) return null;
  try {
    return nip19.npubEncode(normalized);
  } catch {
    return null;
  }
}

function normalizeContactInputPubkey(input) {
  const value = String(input || '').trim();
  if (!value) return null;

  const direct = normalizePubkeyHex(value);
  if (direct) return direct;

  try {
    const decoded = nip19.decode(value);
    if (decoded?.type === 'npub') {
      return normalizePubkeyHex(decoded.data);
    }
  } catch {
    // ignore decoding errors
  }

  return null;
}

async function getKnownPublicKeyHex(password = null) {
  const storedPubkey = await keyManager.getStoredPublicKey();
  if (storedPubkey) return storedPubkey;

  if (!await keyManager.hasKey()) return null;

  const protectionMode = await keyManager.getProtectionMode();
  if (protectionMode === KeyManager.MODE_PASSWORD && !password) {
    return null;
  }

  try {
    const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
    if (!secretKey) return null;
    const pubkey = getPublicKey(secretKey);
    secretKey.fill(0);
    return await keyManager.setStoredPublicKey(pubkey);
  } catch {
    return null;
  }
}

function normalizeRelayUrl(input) {
  const value = String(input || '').trim();
  if (!value) return null;

  let candidate = value;
  if (/^https?:\/\//i.test(candidate)) {
    candidate = candidate.replace(/^http:\/\//i, 'ws://').replace(/^https:\/\//i, 'wss://');
  }

  if (!/^wss?:\/\//i.test(candidate)) {
    candidate = `wss://${candidate.replace(/^\/+/, '')}`;
  }

  try {
    const url = new URL(candidate);
    if (!/^wss?:$/i.test(url.protocol)) return null;
    return `${url.protocol}//${url.host}${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

function normalizeRelayList(rawRelays) {
  const list = Array.isArray(rawRelays)
    ? rawRelays
    : String(rawRelays || '').split(/[\s,;]+/g);

  const normalized = list
    .map((entry) => normalizeRelayUrl(entry))
    .filter(Boolean);

  return Array.from(new Set(normalized));
}

function sanitizeKind0ProfileContent(rawProfile, fallbackWebsite = null) {
  const profile = (rawProfile && typeof rawProfile === 'object') ? rawProfile : {};
  const result = {};

  const name = String(profile.name || '').trim();
  const displayName = String(profile.display_name || profile.displayName || '').trim();
  const picture = String(profile.picture || profile.avatarUrl || '').trim();
  const nip05 = String(profile.nip05 || '').trim();
  const website = String(profile.website || fallbackWebsite || '').trim();

  if (name) result.name = name;
  if (displayName) result.display_name = displayName;
  if (picture) result.picture = picture;
  if (nip05) result.nip05 = nip05;
  if (website) result.website = website;

  return result;
}

async function publishEventToRelay(relayUrl, event, timeoutMs = 9000) {
  return await new Promise((resolve, reject) => {
    let settled = false;
    let socket;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        try {
          socket.close();
        } catch {
          // ignore close errors
        }
      }
      if (error) reject(error);
      else resolve(true);
    };

    const timer = setTimeout(() => {
      finish(new Error('Relay timeout while publishing profile event'));
    }, timeoutMs);

    try {
      socket = new WebSocket(relayUrl);
    } catch (error) {
      clearTimeout(timer);
      reject(error);
      return;
    }

    socket.onopen = () => {
      socket.send(JSON.stringify(['EVENT', event]));
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
      if (data[0] !== 'OK') return;
      if (data[1] !== event.id) return;

      const accepted = data[2] === true;
      if (accepted) {
        finish(null);
        return;
      }

      const reason = String(data[3] || 'Relay rejected event');
      finish(new Error(reason));
    };
  });
}

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

// ============================================================
// Kontaktliste & Profile (TASK-18)
// ============================================================

const CONTACTS_CACHE_KEY = 'nostrContactsCacheV1';
const CONTACTS_CACHE_TTL = 15 * 60 * 1000; // 15 Minuten

// WP-Members Cache (separat, 3 Tage TTL)
const WP_MEMBERS_CACHE_KEY = 'nostrWpMembersCacheV1';
const WP_MEMBERS_CACHE_TTL = 3 * 24 * 60 * 60 * 1000; // 3 Tage

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

async function fetchLatestContactListEvent(pubkey, relayUrl) {
  const normalizedPubkey = normalizePubkeyHex(pubkey);
  if (!normalizedPubkey) return null;

  const normalizedRelay = normalizeRelayUrl(relayUrl);
  if (!normalizedRelay) return null;

  try {
    const events = await subscribeOnce(normalizedRelay, [
      { kinds: [3], authors: [normalizedPubkey], limit: 1 }
    ]);

    if (!events.length) return null;
    return events.sort((a, b) => b.created_at - a.created_at)[0] || null;
  } catch {
    return null;
  }
}

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
          if (!existing || event.created_at > existing.createdAt) {
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
    const endpoint = new URL('members', baseUrl).toString();
    const response = await fetch(endpoint, {
      headers: { 'X-WP-Nonce': context.nonce },
      credentials: 'include',
      cache: 'no-store'
    });

    if (!response.ok) return [];

    const data = await response.json();
    const members = Array.isArray(data?.members)
      ? data.members
      : (Array.isArray(data) ? data : []);

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

// ============================================================
// WP-Members Cache Funktionen (3 Tage TTL)
// ============================================================

/**
 * Generiert einen Cache-Key basierend auf der WP REST URL.
 * @param {Object} wpApi - {restUrl, nonce}
 * @returns {string} - Cache-Key
 */
function getWpMembersCacheKey(wpApi) {
  const baseUrl = normalizeWpRestBaseUrl(wpApi?.restUrl);
  if (!baseUrl) return null;
  // Hash der URL für eindeutigen Key
  return `${WP_MEMBERS_CACHE_KEY}_${baseUrl.replace(/[^a-zA-Z0-9]/g, '_')}`;
}

/**
 * Holt WP-Members aus dem Cache.
 * @param {Object} wpApi - {restUrl, nonce}
 * @returns {Promise<Object|null>} - { members, fetchedAt, isStale } oder null
 */
async function getCachedWpMembers(wpApi) {
  try {
    const cacheKey = getWpMembersCacheKey(wpApi);
    if (cacheKey) {
      const result = await chrome.storage.local.get([cacheKey]);
      const cache = result[cacheKey];

      if (cache && Array.isArray(cache.members)) {
        const fetchedAt = cache.fetchedAt || 0;
        const isStale = Date.now() - fetchedAt > WP_MEMBERS_CACHE_TTL;
        return {
          members: cache.members,
          fetchedAt,
          isStale,
          cacheKey
        };
      }
    }

    const all = await chrome.storage.local.get(null);
    const cacheKeys = Object.keys(all).filter((key) => key.startsWith(`${WP_MEMBERS_CACHE_KEY}_`));
    if (!cacheKeys.length) return null;

    let freshest = null;
    for (const key of cacheKeys) {
      const entry = all[key];
      if (!entry || !Array.isArray(entry.members)) continue;
      const fetchedAt = Number(entry.fetchedAt) || 0;
      if (!freshest || fetchedAt > freshest.fetchedAt) {
        freshest = {
          members: entry.members,
          fetchedAt,
          cacheKey: key
        };
      }
    }

    if (!freshest) return null;

    return {
      members: freshest.members,
      fetchedAt: freshest.fetchedAt,
      isStale: Date.now() - freshest.fetchedAt > WP_MEMBERS_CACHE_TTL,
      cacheKey: freshest.cacheKey
    };
  } catch {
    return null;
  }
}

/**
 * Speichert WP-Members im Cache.
 * @param {Object} wpApi - {restUrl, nonce}
 * @param {Array} members - Array von Member-Objekten
 */
async function setCachedWpMembers(wpApi, members) {
  try {
    const cacheKey = getWpMembersCacheKey(wpApi);
    if (!cacheKey) return;
    
    await chrome.storage.local.set({
      [cacheKey]: {
        members,
        fetchedAt: Date.now(),
        count: members.length
      }
    });
  } catch (error) {
    console.warn('[Nostr] Failed to cache WP members:', error.message);
  }
}

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

async function clearContactsCache() {
  try {
    await chrome.storage.local.remove([CONTACTS_CACHE_KEY]);
  } catch { /* ignore */ }
}

// NIP-17 Protokoll-Funktionen → importiert aus ./lib/nip17-chat.js

/**
 * Ruft DM-Relays eines Pubkeys ab (Kind 10050).
 * @param {string} pubkey - Hex pubkey
 * @param {string|string[]} lookupRelays - Relay URL(s) für Lookup (String oder Array)
 * @returns {Promise<Array<string>>} - Array von Relay URLs
 */
function extractRelayTagsFromKind10050(event) {
  const relaysFromTags = Array.isArray(event?.tags)
    ? event.tags
      .filter((tag) => Array.isArray(tag) && (tag[0] === 'relay' || tag[0] === 'r') && tag[1])
      .map((tag) => normalizeRelayUrl(tag[1]))
      .filter(Boolean)
    : [];
  if (relaysFromTags.length > 0) {
    return relaysFromTags;
  }

  // Some clients may serialize relay URLs in content (JSON array fallback).
  try {
    const parsed = JSON.parse(String(event?.content || ''));
    if (Array.isArray(parsed)) {
      return parsed
        .map((value) => normalizeRelayUrl(value))
        .filter(Boolean);
    }
  } catch {
    // ignore malformed content fallback
  }
  return [];
}

const DM_RELAY_LOOKUP_TIMEOUT_MS = 2200;
const DM_RELAY_CACHE_HIT_TTL_MS = 10 * 60 * 1000;
const DM_RELAY_CACHE_MISS_TTL_MS = 2 * 60 * 1000;
const DM_RELAY_CACHE_MAX_ENTRIES = 200;
const dmRelayLookupCache = new Map(); // key -> { relays, expiresAt }
const dmRelayLookupInFlight = new Map(); // key -> Promise<Array<string>>

function getDmRelayLookupCacheKey(pubkey, relays) {
  return `${pubkey}|${[...relays].sort().join(',')}`;
}

function pruneDmRelayLookupCache() {
  while (dmRelayLookupCache.size > DM_RELAY_CACHE_MAX_ENTRIES) {
    const firstKey = dmRelayLookupCache.keys().next().value;
    if (!firstKey) break;
    dmRelayLookupCache.delete(firstKey);
  }
}

function getCachedDmRelayLookup(cacheKey) {
  const cached = dmRelayLookupCache.get(cacheKey);
  if (!cached) return null;
  if (Date.now() >= cached.expiresAt) {
    dmRelayLookupCache.delete(cacheKey);
    return null;
  }
  return Array.isArray(cached.relays) ? [...cached.relays] : [];
}

function setCachedDmRelayLookup(cacheKey, relays) {
  const ttl = relays.length > 0 ? DM_RELAY_CACHE_HIT_TTL_MS : DM_RELAY_CACHE_MISS_TTL_MS;
  dmRelayLookupCache.set(cacheKey, {
    relays: [...relays],
    expiresAt: Date.now() + ttl
  });
  pruneDmRelayLookupCache();
}

async function fetchDmRelays(pubkey, lookupRelays, options = {}) {
  const normalizedPubkey = normalizePubkeyHex(pubkey);
  if (!normalizedPubkey) return [];

  // Immer als Array behandeln
  const relayList = Array.isArray(lookupRelays) ? lookupRelays : [lookupRelays];
  const normalizedRelays = [...new Set(relayList
    .map(r => normalizeRelayUrl(r))
    .filter(Boolean))];
  if (!normalizedRelays.length) return [];

  const timeoutMs = Number(options.timeoutMs) > 0
    ? Number(options.timeoutMs)
    : DM_RELAY_LOOKUP_TIMEOUT_MS;
  const useCache = options.useCache !== false;
  const cacheKey = getDmRelayLookupCacheKey(normalizedPubkey, normalizedRelays);

  if (useCache) {
    const cached = getCachedDmRelayLookup(cacheKey);
    if (cached !== null) {
      return cached;
    }
    if (dmRelayLookupInFlight.has(cacheKey)) {
      return await dmRelayLookupInFlight.get(cacheKey);
    }
  }

  const lookupPromise = (async () => {
  const foundRelays = new Set();
  await Promise.all(normalizedRelays.map(async (relay) => {
    try {
      const events = await subscribeOnce(relay, [
        { kinds: [10050], authors: [normalizedPubkey], limit: 2 }
      ], timeoutMs);

      if (!events.length) return;

      const latest = events.sort((a, b) => (b.created_at || 0) - (a.created_at || 0))[0];
      const relays = extractRelayTagsFromKind10050(latest);
      if (!relays.length) return;

      relays.forEach((r) => foundRelays.add(r));
      console.log('[NIP-17] Found Kind 10050 for', normalizedPubkey.slice(0, 8), 'on', relay, '→', relays);
    } catch (error) {
      console.warn('[NIP-17] Failed to fetch Kind 10050 from', relay, ':', error.message);
    }
  }));

  const discovered = [...foundRelays];
    if (useCache) {
      setCachedDmRelayLookup(cacheKey, discovered);
    }
  if (discovered.length > 0) {
    return discovered;
  }

  console.log('[NIP-17] No Kind 10050 found for', normalizedPubkey.slice(0, 8), 'on any of', normalizedRelays);
  return [];
  })();

  if (useCache) {
    dmRelayLookupInFlight.set(cacheKey, lookupPromise);
  }

  try {
    return await lookupPromise;
  } finally {
    if (useCache) {
      dmRelayLookupInFlight.delete(cacheKey);
    }
  }
}

// ============================================================
// Relay Connection Manager für persistente Verbindungen
// ============================================================

class RelayConnectionManager {
  constructor() {
    this.connections = new Map(); // relayUrl -> WebSocket
    this.subscriptions = new Map(); // subId -> { filters, onMessage, onEose }
    this._failCount = new Map(); // relayUrl -> consecutive failure count
    this.reconnectInterval = 30000;
    this.keepAliveInterval = 25000; // < 30s für MV3 Service Worker
  }
  
  /**
   * Stellt eine Verbindung zu einem Relay her.
   * @param {string} relayUrl - WebSocket Relay URL
   * @returns {Promise<WebSocket>} - Die WebSocket-Verbindung
   */
  async connect(relayUrl) {
    const normalized = normalizeRelayUrl(relayUrl);
    if (!normalized) throw new Error('Invalid relay URL');
    
    // Bestehende Verbindung prüfen
    if (this.connections.has(normalized)) {
      const existing = this.connections.get(normalized);
      if (existing.readyState === WebSocket.OPEN) {
        return existing;
      }
    }
    
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(normalized);
      
      // Connection Timeout: 10 Sekunden
      const connectTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.warn(`[Relay] Connection timeout for ${normalized}`);
          ws._manualClose = true;
          ws.close();
          reject(new Error(`Connection timeout for ${normalized}`));
        }
      }, 10000);
      
      ws.onopen = () => {
        clearTimeout(connectTimeout);
        console.log(`[Relay] Connected to ${normalized}`);
        this.connections.set(normalized, ws);
        this._failCount.delete(normalized);
        // Re-subscribe to existing subscriptions
        this.resubscribeAll(normalized);
        resolve(ws);
      };
      
      ws.onclose = () => {
        clearTimeout(connectTimeout);
        console.log(`[Relay] Disconnected from ${normalized}`);
        this.connections.delete(normalized);
        // Kein Auto-Reconnect wenn manuell geschlossen
        if (ws._manualClose) return;
        // Exponential Backoff bei wiederholten Fehlern
        const fails = (this._failCount.get(normalized) || 0) + 1;
        this._failCount.set(normalized, fails);
        if (fails > 5) {
          console.warn(`[Relay] Too many failures for ${normalized}, stopping reconnect`);
          return;
        }
        const delay = Math.min(this.reconnectInterval * Math.pow(2, fails - 1), 300000);
        setTimeout(() => {
          this.connect(normalized).catch(() => {});
        }, delay);
      };
      
      ws.onerror = (error) => {
        clearTimeout(connectTimeout);
        console.warn(`[Relay] Error on ${normalized}:`, error);
        if (ws.readyState === WebSocket.CONNECTING) {
          reject(new Error(`Failed to connect to ${normalized}`));
        }
      };
      
      ws.onmessage = (event) => {
        this.handleMessage(normalized, event.data);
      };
    });
  }
  
  /**
   * Verarbeitet eingehende Nachrichten vom Relay.
   */
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
        try {
          sub.onMessage(event, relayUrl);
        } catch (e) {
          console.warn('[Relay] Error in message handler:', e);
        }
      }
    }
    
    // ["EOSE", subId]
    if (parsed[0] === 'EOSE') {
      const sub = this.subscriptions.get(parsed[1]);
      if (sub?.onEose) {
        try {
          sub.onEose();
        } catch (e) {
          console.warn('[Relay] Error in EOSE handler:', e);
        }
      }
    }
    
    // ["OK", eventId, accepted, message]
    if (parsed[0] === 'OK') {
      // Wird von publishEvent verwendet
    }
    
    // ["NOTICE", message]
    if (parsed[0] === 'NOTICE') {
      console.warn(`[Relay] NOTICE from ${relayUrl}:`, parsed[1]);
    }
  }
  
  /**
   * Abonniert Events von einem Relay.
   * @param {string} relayUrl - Relay URL
   * @param {Array} filters - Nostr Filter-Array
   * @param {Function} onMessage - Callback für eingehende Events
   * @param {Function} onEose - Callback für EOSE (optional)
   * @returns {Promise<string>} - Subscription ID
   */
  async subscribe(relayUrl, filters, onMessage, onEose = null) {
    const ws = await this.connect(relayUrl);
    const subId = 'dm_' + Math.random().toString(36).slice(2);
    
    this.subscriptions.set(subId, { filters, onMessage, onEose });
    
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(['REQ', subId, ...filters]));
    }
    
    return subId;
  }
  
  /**
   * Beendet eine Subscription.
   */
  unsubscribe(subId) {
    this.subscriptions.delete(subId);
    // Send CLOSE to all connected relays
    for (const [relayUrl, ws] of this.connections) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(['CLOSE', subId]));
      }
    }
  }
  
  /**
   * Re-subscribed alle aktiven Subscriptions nach Reconnect.
   */
  resubscribeAll(relayUrl) {
    const ws = this.connections.get(relayUrl);
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    
    for (const [subId, sub] of this.subscriptions) {
      ws.send(JSON.stringify(['REQ', subId, ...sub.filters]));
    }
  }
  
  /**
   * Prüft alle Verbindungen und reconnectet falls nötig.
   */
  checkConnections() {
    for (const [relayUrl, ws] of this.connections) {
      if (ws.readyState !== WebSocket.OPEN) {
        this.connect(relayUrl).catch(() => {});
      }
    }
  }
  
  /**
   * Publiziert ein Event an ein Relay.
   * @param {string} relayUrl - Relay URL
   * @param {Object} event - Das zu publizierende Event
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<boolean>} - true wenn akzeptiert
   */
  async publishEvent(relayUrl, event, timeout = 10000) {
    const ws = await this.connect(relayUrl);
    
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.removeEventListener('message', handleResponse);
        console.warn(`[Relay] Timeout waiting for OK from ${relayUrl} for event ${event.id}`);
        reject(new Error('Publish timeout'));
      }, timeout);
      
      const handleResponse = (msgEvent) => {
        try {
          const data = msgEvent.data;
          const parsed = JSON.parse(data);
          
          // Debug Logging für alle Antworten während des Publish-Vorgangs
          // console.log(`[Relay Debug] Response from ${relayUrl}:`, data);

          if (!Array.isArray(parsed)) return;

          // OK Check
          if (parsed[0] === 'OK' && parsed[1] === event.id) {
            clearTimeout(timer);
            ws.removeEventListener('message', handleResponse);
            if (parsed[2] === true) {
              console.log(`[Relay] OK from ${relayUrl} for event ${event.id}`);
              resolve(true);
            } else {
              console.warn(`[Relay] REJECTED by ${relayUrl}:`, parsed[3]);
              reject(new Error(parsed[3] || 'Relay rejected event'));
            }
          }
          
          // NOTICE Check (Fehlermeldungen vom Relay)
          if (parsed[0] === 'NOTICE') {
            console.warn(`[Relay] NOTICE from ${relayUrl} during publish:`, parsed[1]);
          }
           
          // CLOSED Check (NIP-01)
          if (parsed[0] === 'CLOSED' && parsed[1] === event.id) {
             clearTimeout(timer);
             ws.removeEventListener('message', handleResponse);
             reject(new Error(`Subscription/Event CLOSED: ${parsed[2]}`));
          }

        } catch (e) {
            console.error('[Relay] Error parsing response:', e);
        }
      };
      
      ws.addEventListener('message', handleResponse);
      
      console.log(`[Relay] Publishing event ${event.id} (kind: ${event.kind}) to ${relayUrl}...`);
      ws.send(JSON.stringify(['EVENT', event]));
    });
  }
}

// Singleton Instance
const relayManager = new RelayConnectionManager();

// DM Cache, Unread Counter, formatShortHex → importiert aus ./lib/nip17-chat.js

// ============================================================
// Notification System (bleibt in background.js wegen getContactProfile)
// ============================================================

/**
 * Zeigt eine Desktop-Notification für eine neue DM.
 * @param {Object} msg - Die Nachricht
 */
async function showDmNotification(msg) {
  try {
    // Prüfen ob Notifications erlaubt sind
    const settings = await chrome.storage.local.get([DM_NOTIFICATIONS_KEY]);
    if (settings[DM_NOTIFICATIONS_KEY] === false) return;
    
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
  } catch (error) {
    console.warn('[NIP-17] Failed to show notification:', error.message);
  }
}

/**
 * Holt das Profil eines Kontakts aus dem Cache oder von Relays.
 * @param {string} pubkey - Hex pubkey
 * @returns {Promise<Object|null>} - Profil oder null
 */
async function getContactProfile(pubkey) {
  try {
    const result = await chrome.storage.local.get([CONTACTS_CACHE_KEY]);
    const cache = result[CONTACTS_CACHE_KEY];
    if (cache?.contacts) {
      const contact = cache.contacts.find(c => c.pubkey === pubkey);
      if (contact) {
        return {
          displayName: contact.displayName || contact.name,
          picture: contact.picture,
          nip05: contact.nip05
        };
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ============================================================
// DM Relay Discovery (Multi-Relay, NIP-17 Kind 10050)
// ============================================================

const DEFAULT_DM_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'];
const DM_RELAY_DISCOVERY_RELAYS = [
  ...DEFAULT_DM_RELAYS,
  'wss://relay.0xchat.com',
  'wss://relay.oxchat.com',
  'wss://inbox.nostr.wine',
];

function parseRelayInputList(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(',');
  return raw
    .map((entry) => normalizeRelayUrl(String(entry || '').trim()))
    .filter(Boolean);
}

async function getConfiguredDmRelayList() {
  try {
    const stored = await chrome.storage.local.get(['dmRelayUrl']);
    return parseRelayInputList(stored.dmRelayUrl);
  } catch {
    return [];
  }
}

async function resolveRecipientLookupRelays(clientRelayUrl = null) {
  const explicit = parseRelayInputList(clientRelayUrl);
  const configured = await getConfiguredDmRelayList();
  return [...new Set([
    ...explicit,
    ...configured,
    ...DM_RELAY_DISCOVERY_RELAYS
  ])];
}

/**
 * Ermittelt alle Inbox-Relays für DM-Operationen.
 * Priorisierung:
 *   1. Explizit vom Client übergebene Relays (kommagetrennt oder Array)
 *   2. Gespeichertes DM-Relay aus Settings (dmRelayUrl)
 *   3. Kind 10050 (NIP-17 Inbox Relays) des eigenen Pubkeys
 *   4. Fallback-Relays (damus, nos.lol, nostr.band)
 * 
 * WICHTIG: Diese Relays haben NICHTS mit dem Profil-Relay zu tun!
 * Profil → Kind 0 via configures relay in Settings
 * DMs    → Kind 1059 via NIP-17 Inbox Relays (Kind 10050)
 * 
 * @param {string|string[]|null} clientRelayUrl - Vom Client übergebene Relay-URL(s)
 * @param {string|null} myPubkey - Eigener Pubkey für Kind 10050 Lookup (optional)
 * @returns {Promise<string[]>} - Array von normalisierten Relay-URLs
 */
async function resolveDmInboxRelays(clientRelayUrl = null, myPubkey = null) {
  let relays = [];

  // 1. Explizit vom Client
  if (clientRelayUrl) {
    relays = parseRelayInputList(clientRelayUrl);
  }

  // 2. Gespeichertes DM-Relay aus Settings
  if (relays.length === 0) {
    relays = await getConfiguredDmRelayList();
  }

  // 3. Kind 10050 (NIP-17 Inbox Relays)
  if (relays.length === 0 && myPubkey) {
    try {
      const discovered = await fetchDmRelays(myPubkey, DM_RELAY_DISCOVERY_RELAYS, {
        timeoutMs: DM_RELAY_LOOKUP_TIMEOUT_MS
      });
      if (discovered.length > 0) {
        relays = discovered;
      }
    } catch { /* ignore */ }
  }

  // 4. Fallback
  if (relays.length === 0) {
    relays = [...DEFAULT_DM_RELAYS];
  }

  // Deduplizieren
  return [...new Set(relays)];
}

// ============================================================
// DM Key Helper (Race-Condition-sicher, Scope-agnostisch)
// ============================================================

/**
 * Findet einen nutzbaren Key für DM-Operationen, unabhängig vom aktuellen Scope.
 * Erstellt einen scope-lokalen KeyManager, der immun gegen konkurrierende Scope-Wechsel ist.
 * Prüft zuerst den aktuellen Scope, dann alle verfügbaren Scopes.
 * 
 * WARUM: chrome.runtime.onMessage verarbeitet Nachrichten konkurrierend.
 * Wenn GET_STATUS und GET_DMS gleichzeitig ankommen, kann ensureKeyScope()
 * den globalen keyManager.namespace zwischen den async-Aufrufen wechseln.
 * Ein scope-lokaler KeyManager verhindert dieses Problem.
 * 
 * @returns {Promise<{km: KeyManager, scope: string, protectionMode: string}|null>}
 */
async function findDmKey() {
  const check = async (scope) => {
    const ns = scope === KEY_SCOPE_DEFAULT ? '' : scope;
    const km = new KeyManager(chrome.storage.local, ns);
    const has = await km.hasKey();
    if (!has) return null;
    const mode = await km.getProtectionMode();
    if (mode === null) return null;
    return { km, scope, protectionMode: mode };
  };

  // 1. Aktuellen Scope prüfen (scope-lokaler Snapshot)
  const currentScope = activeKeyScope;
  const current = await check(currentScope);
  if (current) return current;

  // 2. Alle Scopes durchsuchen
  const scopes = await listStoredKeyScopes();
  for (const scope of scopes) {
    if (scope === currentScope) continue;
    const found = await check(scope);
    if (found) {
      console.log('[NIP-17] Key gefunden in alternativem Scope:', scope, 'mode:', found.protectionMode);
      return found;
    }
  }

  console.warn('[NIP-17] Kein nutzbarer Key in irgendeinem Scope gefunden. Scopes geprüft:', [currentScope, ...scopes.filter(s => s !== currentScope)]);
  return null;
}

// ============================================================
// DM Subscription Handler
// ============================================================

/**
 * Startet eine Subscription für eingehende DMs.
 * @param {string} scope - Der Key Scope
 * @param {string} relayUrl - Relay URL
 * @param {string} myPubkey - Eigener Pubkey
 * @param {Uint8Array} privateKey - Private Key für Entschlüsselung
 * @returns {Promise<string>} - Subscription ID
 */
async function startDmSubscription(scope, relayUrl, myPubkey, privateKey) {
  const filters = [{
    kinds: [1059], // Gift Wrap
    '#p': [myPubkey],
    limit: 100
  }];
  
  const subId = await relayManager.subscribe(
    relayUrl,
    filters,
    async (event, relayUrl) => {
      // Neue Gift Wrap Nachricht empfangen
      try {
        const msg = unwrapGiftWrap(privateKey, event);
        msg.giftWrapId = msg.id; // Sicherstellen, dass dedup in cacheDmMessage funktioniert
        msg.direction = msg.senderPubkey === myPubkey ? 'out' : 'in';
        msg.receivedAt = Date.now();
        
        // In Cache speichern (null = Duplikat)
        const cachedMsg = await cacheDmMessage(msg, scope, myPubkey);
        if (!cachedMsg) return; // Duplikat überspringen
        
        // Notify any active frontend listeners (popup/chat UI) about the new message
        try {
          chrome.runtime.sendMessage({
            type: 'NOSTR_NEW_DM',
            payload: cachedMsg
          }).catch(() => {
             // Suppress error if no receiver is listening (popup closed)
          });
        } catch (err) {
           console.warn('[Nostr] Failed to broadcast new DM to UI:', err);
        }
        
        // Notification auslösen (nur für eingehende Nachrichten)
        if (msg.direction === 'in') {
          try {
             await showDmNotification(msg);
             await incrementUnreadCount();
          } catch (notifErr) {
             console.warn('[NIP-17] Failed to show notification:', notifErr.message);
          }
        }
      } catch (e) {
        // Erwarteter Fehler bei fremden Gift Wraps (andere Keys, Spam, ältere Events)
        // Nur loggen wenn keine MAC-Fehler (die kommen häufig auf öffentlichen Relays)
        if (!e.message?.includes('invalid MAC') && !e.message?.includes('Failed to decrypt')) {
          console.debug('[NIP-17] Could not unwrap gift wrap:', e.message);
        }
      }
    }
  );
  
  return subId;
}

/**
 * Pollt nach neuen DMs (Fallback).
 * @param {string} scope - Der Key Scope
 * @param {string} relayUrl - Relay URL
 * @param {string} myPubkey - Eigener Pubkey
 * @param {Uint8Array} privateKey - Private Key
 */
async function pollForNewDms(scope, relayUrl, myPubkey, privateKey) {
  try {
    // Letzten Check aus Storage holen
    const lastCheckKey = 'dmLastPoll_' + scope;
    const result = await chrome.storage.local.get([lastCheckKey]);
    const since = result[lastCheckKey] || Math.floor(Date.now() / 1000) - 3600; // Default: 1h
    
    const filters = [{
      kinds: [1059],
      '#p': [myPubkey],
      since: since,
      limit: 50
    }];
    
    const events = await subscribeOnce(relayUrl, filters, 10000);
    
    for (const event of events) {
      try {
        const msg = unwrapGiftWrap(privateKey, event);
        msg.giftWrapId = msg.id; // Sicherstellen, dass dedup in cacheDmMessage funktioniert
        msg.direction = msg.senderPubkey === myPubkey ? 'out' : 'in';
        msg.receivedAt = Date.now();
        
        const cached = await cacheDmMessage(msg, scope, myPubkey);
        if (!cached) continue; // Duplikat überspringen
        
        if (msg.direction === 'in') {
          await showDmNotification(msg);
          await incrementUnreadCount();
        }
      } catch {
        // Nicht für uns
      }
    }
    
    // Letzten Check aktualisieren
    await chrome.storage.local.set({ [lastCheckKey]: Math.floor(Date.now() / 1000) });
  } catch (error) {
    console.warn('[NIP-17] Poll failed:', error.message);
  }
}

async function getStoredPasskeyCredentialIdForActiveScope() {
  const credentialStorageKey = keyManager.keyName(KeyManager.PASSKEY_ID_KEY);
  const storage = await chrome.storage.local.get([credentialStorageKey]);
  return String(storage[credentialStorageKey] || '').trim() || null;
}

async function configureProtectionAndStoreSecretKey(secretKey, passkeyAuthOptions = null) {
  // If user already has a preference from another scope, inherit silently.
  const existingPref = await getExistingProtectionPreference();

  if (existingPref.hasOtherScopes && existingPref.preferredProtection) {
    const inheritedMode = existingPref.preferredProtection;

    if (inheritedMode === KeyManager.MODE_NONE) {
      await keyManager.storeKey(secretKey, null);
      await clearUnlockCaches();
      const pubkey = getPublicKey(secretKey);
      return {
        pubkey,
        npub: nip19.npubEncode(pubkey),
        protectionMode: KeyManager.MODE_NONE
      };
    }

    if (inheritedMode === KeyManager.MODE_PASSWORD) {
      const password = await ensurePasswordIfNeeded(true);
      await keyManager.storeKey(secretKey, password);
      await cachePasswordWithPolicy(password);
      const pubkey = getPublicKey(secretKey);
      return {
        pubkey,
        npub: nip19.npubEncode(pubkey),
        protectionMode: KeyManager.MODE_PASSWORD
      };
    }

    if (inheritedMode === KeyManager.MODE_PASSKEY) {
      const srcCredKey = new KeyManager(chrome.storage.local, existingPref.sourceScope)
        .keyName(KeyManager.PASSKEY_ID_KEY);
      const srcStorage = await chrome.storage.local.get([srcCredKey]);
      const existingCredentialId = String(srcStorage[srcCredKey] || '').trim();
      if (existingCredentialId) {
        await ensurePasskeyIfNeeded(passkeyAuthOptions);
        await keyManager.storeKey(secretKey, null, {
          mode: KeyManager.MODE_PASSKEY,
          passkeyCredentialId: existingCredentialId
        });
        await cachePasskeyAuthWithPolicy();
        const pubkey = getPublicKey(secretKey);
        return {
          pubkey,
          npub: nip19.npubEncode(pubkey),
          protectionMode: KeyManager.MODE_PASSKEY
        };
      }
    }
  }

  // First-time: show full setup dialog
  const setupResult = await promptPassword('create');
  if (!setupResult) {
    throw new Error('Key import canceled');
  }

  const setupMode = typeof setupResult === 'object' ? setupResult.protection : null;
  const usePasskey = setupMode === KeyManager.MODE_PASSKEY;
  const useNoPassword = !usePasskey && typeof setupResult === 'object' && setupResult.noPassword === true;
  const password = usePasskey ? null : extractPasswordFromDialogResult(setupResult);

  if (!useNoPassword && !usePasskey && !password) {
    throw new Error('Password required');
  }

  await keyManager.storeKey(
    secretKey,
    useNoPassword ? null : password,
    usePasskey
      ? {
        mode: KeyManager.MODE_PASSKEY,
        passkeyCredentialId: setupResult.credentialId
      }
      : undefined
  );

  await clearUnlockCaches();
  if (usePasskey) {
    await cachePasskeyAuthWithPolicy();
  } else if (!useNoPassword && password) {
    await cachePasswordWithPolicy(password);
  }

  const pubkey = getPublicKey(secretKey);
  return {
    pubkey,
    npub: nip19.npubEncode(pubkey),
    protectionMode: usePasskey ? KeyManager.MODE_PASSKEY : (useNoPassword ? KeyManager.MODE_NONE : KeyManager.MODE_PASSWORD)
  };
}

async function resolvePasskeyAuthOptions(request, domain, isInternalExtensionRequest) {
  const useAuthBroker =
    request?.payload?.useAuthBroker === true
    || request?.payload?.useAuthBroker === 1
    || request?.payload?.useAuthBroker === '1'
    || request?.useAuthBroker === true
    || request?.useAuthBroker === 1
    || request?.useAuthBroker === '1';

  // Safety default:
  // Keep local passkey unlock as default path until broker credential enrollment
  // is fully implemented end-to-end.
  if (!useAuthBroker) {
    return null;
  }

  const topLevelBroker = sanitizePasskeyAuthBroker(request?.authBroker);
  if (topLevelBroker) {
    return topLevelBroker;
  }

  const payloadBroker = sanitizePasskeyAuthBroker(request?.payload?.authBroker);
  if (payloadBroker) {
    return payloadBroker;
  }

  if (isInternalExtensionRequest) {
    return null;
  }

  const normalizedDomain = normalizeDomainEntry(domain);
  if (!normalizedDomain) {
    return null;
  }

  const configs = await getDomainSyncConfigs();
  return sanitizePasskeyAuthBroker(configs[normalizedDomain]?.authBroker);
}

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
  await restoreActiveScope();
  const domain = sender.tab?.url ? new URL(sender.tab.url).hostname : null;
  const isInternalExtensionRequest = sender?.id === chrome.runtime.id && !sender?.tab?.url;
  const requestType = String(request?.type || '');
  const scopedTypes = new Set([
    'NOSTR_SET_UNLOCK_CACHE_POLICY',
    'NOSTR_CHANGE_PROTECTION',
    'NOSTR_GET_STATUS',
    'NOSTR_BACKUP_STATUS',
    'NOSTR_BACKUP_ENABLE',
    'NOSTR_BACKUP_RESTORE',
    'NOSTR_BACKUP_DELETE',
    'NOSTR_EXPORT_NSEC',
    'NOSTR_CREATE_NEW_KEY',
    'NOSTR_IMPORT_NSEC',
    'NOSTR_PUBLISH_PROFILE',
    'NOSTR_GET_PUBLIC_KEY',
    'NOSTR_SIGN_EVENT',
    'NOSTR_NIP04_ENCRYPT',
    'NOSTR_NIP04_DECRYPT',
    'NOSTR_NIP44_ENCRYPT',
    'NOSTR_NIP44_DECRYPT',
    'NOSTR_ADD_CONTACT'
    // NIP-17 Direktnachrichten: NICHT in scopedTypes!
    // DM-Handler nutzen findDmKey() das alle Scopes eigenständig durchsucht.
    // ensureKeyScope() würde sonst den Scope auf 'global' resetten (Popup sendet
    // keinen scope), clearUnlockCaches() triggern und unnötige Passkey/Passwort-Prompts
    // auslösen, obwohl der User z.B. 'ohne Schutz' gewählt hat.
  ]);

  if (scopedTypes.has(requestType)) {
    const isWebRequest = !isInternalExtensionRequest && Boolean(domain);
    await ensureKeyScope(getKeyScopeFromRequest(request, { isWebRequest }));
  }

  let cachedPasskeyAuthOptions;
  let passkeyAuthOptionsResolved = false;
  const getPasskeyAuthOptions = async () => {
    if (passkeyAuthOptionsResolved) return cachedPasskeyAuthOptions;
    cachedPasskeyAuthOptions = await resolvePasskeyAuthOptions(request, domain, isInternalExtensionRequest);
    passkeyAuthOptionsResolved = true;
    return cachedPasskeyAuthOptions;
  };

  // PING erfordert keine Domain-Validierung (f????r Extension-Detection)
  if (request.type === 'NOSTR_PING') {
    return { pong: true, version: CURRENT_VERSION };
  }

  if (request.type === 'NOSTR_SET_UNLOCK_CACHE_POLICY') {
    if (!isInternalExtensionRequest) {
      throw new Error('Unlock cache policy can only be set from extension UI');
    }
    const policy = normalizeUnlockCachePolicy(request.payload?.policy);
    await chrome.storage.local.set({ [UNLOCK_CACHE_POLICY_KEY]: policy });

    const currentCachedPassword = await getCachedPassword();
    if (currentCachedPassword) {
      await cachePasswordWithPolicy(currentCachedPassword);
    }
    const currentPasskeyAuth = await getCachedPasskeyAuth();
    if (currentPasskeyAuth) {
      await cachePasskeyAuthWithPolicy();
    }

    const refreshedCachedPassword = await getCachedPassword();
    const refreshedPasskeyAuth = await getCachedPasskeyAuth();
    return {
      success: true,
      policy,
      allowedPolicies: UNLOCK_CACHE_ALLOWED_POLICY_LIST,
      hasCachedPassword: Boolean(refreshedCachedPassword),
      hasCachedPasskeyAuth: Boolean(refreshedPasskeyAuth),
      cacheExpiresAt: cachedPasswordExpiresAt ?? cachedPasskeyExpiresAt
    };
  }

  // NOSTR_CHANGE_PROTECTION - Schutzart im Popup ändern
  if (request.type === 'NOSTR_CHANGE_PROTECTION') {
    if (!isInternalExtensionRequest) {
      throw new Error('Protection mode can only be changed from extension UI');
    }
    const hasKey = await keyManager.hasKey();
    if (!hasKey) {
      throw new Error('No key found for this scope.');
    }

    const newMode = String(request.payload?.mode || '').trim();
    if (![KeyManager.MODE_NONE, KeyManager.MODE_PASSWORD, KeyManager.MODE_PASSKEY].includes(newMode)) {
      throw new Error(`Invalid protection mode: ${newMode}`);
    }

    const currentMode = await keyManager.getProtectionMode();
    if (currentMode === newMode) {
      return { success: true, protectionMode: newMode, unchanged: true };
    }

    // Unlock with current mode to get secret key
    const unlockPassword = await ensureUnlockForMode(currentMode, await getPasskeyAuthOptions());
    const secretKey = await keyManager.getKey(
      currentMode === KeyManager.MODE_PASSWORD ? unlockPassword : null
    );
    if (!secretKey) {
      throw new Error('Failed to unlock current key.');
    }

    try {
      if (newMode === KeyManager.MODE_NONE) {
        await keyManager.storeKey(secretKey, null);
        await clearUnlockCaches();
      } else if (newMode === KeyManager.MODE_PASSWORD) {
        const setupResult = await promptPassword('create-password');
        if (!setupResult) throw new Error('Password setup canceled');
        const password = extractPasswordFromDialogResult(setupResult);
        if (!password) throw new Error('Password required');
        await keyManager.storeKey(secretKey, password);
        await clearUnlockCaches();
        await cachePasswordWithPolicy(password);
      } else if (newMode === KeyManager.MODE_PASSKEY) {
        const setupResult = await promptPassword('create-passkey');
        if (!setupResult || setupResult.protection !== KeyManager.MODE_PASSKEY) {
          throw new Error('Passkey setup canceled');
        }
        await keyManager.storeKey(secretKey, null, {
          mode: KeyManager.MODE_PASSKEY,
          passkeyCredentialId: setupResult.credentialId
        });
        await clearUnlockCaches();
        await cachePasskeyAuthWithPolicy();
      }
    } finally {
      secretKey.fill(0);
    }

    return { success: true, protectionMode: newMode };
  }

  // NOSTR_GET_STATUS - Status f????r Popup (ben????tigt keine Domain)
  if (request.type === 'NOSTR_GET_STATUS') {
    const unlockCachePolicy = await getUnlockCachePolicy();
    const currentCachedPassword = await getCachedPassword();
    const currentPasskeyAuth = await getCachedPasskeyAuth();
    const hasKey = await keyManager.hasKey();
    const protectionMode = hasKey ? await keyManager.getProtectionMode() : null;
    const passwordProtected = protectionMode === KeyManager.MODE_PASSWORD;
    const passkeyProtected = protectionMode === KeyManager.MODE_PASSKEY;
    const unlockedByPolicy = hasKey && (
      protectionMode === KeyManager.MODE_NONE ||
      (passwordProtected && currentCachedPassword) ||
      (passkeyProtected && currentPasskeyAuth)
    );
    let unlocked = unlockedByPolicy;
    let pubkeyHex = null;
    let npub = null;

    if (unlocked && passwordProtected && currentCachedPassword) {
      try {
        const testKey = await keyManager.getKey(currentCachedPassword);
        if (!testKey) throw new Error('Unlock validation failed');
        testKey.fill(0);
      } catch {
        await clearUnlockCaches();
        unlocked = false;
      }
    }

    pubkeyHex = await getKnownPublicKeyHex(passwordProtected ? currentCachedPassword : null);
    npub = toNpub(pubkeyHex);

    return {
      hasKey,
      locked: hasKey && !unlocked,
      passwordProtected,
      passkeyProtected,
      protectionMode,
      pubkeyHex,
      npub,
      noPasswordMode: protectionMode === KeyManager.MODE_NONE,
      unlockCachePolicy,
      unlockCacheAllowedPolicies: UNLOCK_CACHE_ALLOWED_POLICY_LIST,
      cacheExpiresAt: cachedPasswordExpiresAt ?? cachedPasskeyExpiresAt,
      keyScope: activeKeyScope,
      cacheMode: unlockCachePolicy === 'session'
        ? 'session'
        : (unlockCachePolicy === 'off' ? 'off' : 'timed')
    };
  }

  if (request.type === 'NOSTR_GET_KEY_SCOPE_INFO') {
    if (!isInternalExtensionRequest) {
      throw new Error('Key scope info is only available in extension UI');
    }
    const scopes = await listStoredKeyScopes();
    const stored = await chrome.storage.local.get([LAST_ACTIVE_SCOPE_KEY]);
    const lastActiveScope = normalizeKeyScope(stored[LAST_ACTIVE_SCOPE_KEY]);
    const preferredScope = resolvePreferredScope(request.payload?.requestedScope, scopes, lastActiveScope);
    return {
      scopes,
      preferredScope,
      lastActiveScope,
      activeScope: activeKeyScope
    };
  }

  if (request.type === 'NOSTR_BACKUP_STATUS') {
    if (!isInternalExtensionRequest) {
      throw new Error('Backup status is only available from extension UI');
    }
    const metadata = await wpApiPostJson(request.payload?.wpApi, 'backup/metadata', {});
    if (!metadata?.hasBackup) {
      return metadata;
    }

    const backupFingerprint = String(metadata?.passkeyCredentialFingerprint || '').trim() || null;
    const localCredentialId = await getStoredPasskeyCredentialIdForActiveScope();
    const localFingerprint = await computePasskeyCredentialFingerprint(localCredentialId);

    let restoreLikelyAvailable = true;
    let restoreUnavailableReason = null;
    if (backupFingerprint && localFingerprint && backupFingerprint !== localFingerprint) {
      restoreLikelyAvailable = false;
      restoreUnavailableReason = 'credential_mismatch';
    }

    return {
      ...metadata,
      passkeyCredentialFingerprint: backupFingerprint,
      localPasskeyCredentialFingerprint: localFingerprint,
      restoreLikelyAvailable,
      restoreUnavailableReason
    };
  }

  if (request.type === 'NOSTR_BACKUP_ENABLE') {
    if (!isInternalExtensionRequest) {
      throw new Error('Backup upload is only allowed from extension UI');
    }

    const hasKey = await keyManager.hasKey();
    if (!hasKey) {
      throw new Error('No local key found for this scope.');
    }

    const protectionMode = await keyManager.getProtectionMode();
    const unlockPassword = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? unlockPassword : null);
    if (!secretKey) {
      throw new Error('Key unlock failed.');
    }

    try {
      const pubkey = getPublicKey(secretKey);
      const passkeyUnlock = await promptPassword('unlock-passkey', {
        ...(await getPasskeyAuthOptions() || {}),
        intent: 'backup-enable'
      });
      if (!passkeyUnlock?.passkey) {
        throw new Error('Passkey confirmation is required for cloud backup.');
      }
      const credentialId = String(passkeyUnlock.credentialId || '').trim();
      if (!credentialId) {
        throw new Error('No passkey credential available for wrapping backup key.');
      }

      const wrapKey = await derivePasskeyWrapKey(credentialId, activeKeyScope);
      const dek = crypto.getRandomValues(new Uint8Array(32));
      const aadBytes = new TextEncoder().encode(JSON.stringify({
        version: 1,
        scope: activeKeyScope,
        pubkey
      }));
      const blobEncrypted = await encryptAesGcmBytes(
        await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['encrypt']),
        secretKey,
        aadBytes
      );
      const wrappedDekEncrypted = await encryptAesGcmBytes(wrapKey, dek, null);
      dek.fill(0);

      const wrappedDekPack = concatBytes(wrappedDekEncrypted.iv, wrappedDekEncrypted.ciphertext);
      const passkeyCredentialFingerprint = await computePasskeyCredentialFingerprint(credentialId);

      return await wpApiPostJson(request.payload?.wpApi, 'backup/upload', {
        version: 1,
        pubkey,
        backupBlob: bytesToBase64(blobEncrypted.ciphertext),
        blobIv: bytesToBase64(blobEncrypted.iv),
        blobAad: bytesToBase64(aadBytes),
        wrappedDekPasskey: bytesToBase64(wrappedDekPack),
        wrappedDekRecovery: null,
        keyFingerprint: await computeKeyFingerprint(pubkey),
        passkeyCredentialFingerprint
      });
    } finally {
      secretKey.fill(0);
    }
  }

  if (request.type === 'NOSTR_BACKUP_RESTORE') {
    if (!isInternalExtensionRequest) {
      throw new Error('Backup restore is only allowed from extension UI');
    }

    const metadata = await wpApiPostJson(request.payload?.wpApi, 'backup/metadata', {});
    if (!metadata?.hasBackup) {
      throw new Error('No cloud backup found for this account.');
    }

    const expectedPubkey = String(metadata?.pubkey || '').trim().toLowerCase();
    const downloaded = await wpApiPostJson(request.payload?.wpApi, 'backup/download', {
      expectedPubkey: expectedPubkey || undefined
    });

    const wrappedPack = base64ToBytes(downloaded?.wrappedDekPasskey);
    if (wrappedPack.length <= 12) {
      throw new Error('Backup payload is invalid (wrapped key).');
    }
    const wrapIv = wrappedPack.subarray(0, 12);
    const wrappedDekCiphertext = wrappedPack.subarray(12);

    const passkeyUnlock = await promptPassword('unlock-passkey', {
      ...(await getPasskeyAuthOptions() || {}),
      intent: 'backup-restore'
    });
    if (!passkeyUnlock?.passkey) {
      throw new Error('Passkey confirmation is required for restore.');
    }
    const credentialId = String(passkeyUnlock.credentialId || '').trim();
    if (!credentialId) {
      throw new Error('No passkey credential available for restore.');
    }

    let restoredSecret;
    try {
      const wrapKey = await derivePasskeyWrapKey(credentialId, activeKeyScope);
      const dek = await decryptAesGcmBytes(wrapKey, wrapIv, wrappedDekCiphertext, null);

      const blobIv = base64ToBytes(downloaded?.blobIv);
      const blobCiphertext = base64ToBytes(downloaded?.backupBlob);
      const blobAad = base64ToBytes(downloaded?.blobAad);
      const dekKey = await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['decrypt']);
      dek.fill(0);

      restoredSecret = await decryptAesGcmBytes(dekKey, blobIv, blobCiphertext, blobAad);
    } catch (restoreError) {
      const isCryptoFailure = String(restoreError?.name || '') === 'OperationError';
      if (isCryptoFailure) {
        throw new Error(
          'Cloud-Restore konnte nicht entschluesselt werden. ' +
          'Der Backup-Wrap ist an die damals verwendete Passkey-Credential gebunden ' +
          '(Firefox/Chrome koennen unterschiedliche Credential-Stores nutzen). ' +
          'Loesung: Key im Quell-Browser als nsec exportieren, im Ziel-Browser importieren, ' +
          'danach dort ein neues Cloud-Backup speichern.'
        );
      }
      throw restoreError;
    }
    if (restoredSecret.length !== 32) {
      restoredSecret.fill(0);
      throw new Error('Backup payload has invalid key length.');
    }

    try {
      const restoredPubkey = getPublicKey(restoredSecret);
      const expected = String(downloaded?.pubkey || '').trim().toLowerCase();
      if (expected && restoredPubkey !== expected) {
        throw new Error('Restored key does not match backup pubkey metadata.');
      }

      return await configureProtectionAndStoreSecretKey(restoredSecret, await getPasskeyAuthOptions());
    } finally {
      restoredSecret.fill(0);
    }
  }

  if (request.type === 'NOSTR_BACKUP_DELETE') {
    if (!isInternalExtensionRequest) {
      throw new Error('Backup deletion is only allowed from extension UI');
    }
    return await wpApiPostJson(request.payload?.wpApi, 'backup/delete', {});
  }

  if (request.type === 'NOSTR_EXPORT_NSEC') {
    if (!isInternalExtensionRequest) {
      throw new Error('Key export is only allowed from extension UI');
    }
    const hasKey = await keyManager.hasKey();
    if (!hasKey) {
      throw new Error('No key available for export');
    }
    const protectionMode = await keyManager.getProtectionMode();
    const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
    if (!secretKey) {
      throw new Error(protectionMode === KeyManager.MODE_PASSWORD ? 'Invalid password' : 'No key found');
    }
    try {
      const pubkey = getPublicKey(secretKey);
      const npub = nip19.npubEncode(pubkey);
      const nsec = nip19.nsecEncode(secretKey);
      return { pubkey, npub, nsec };
    } finally {
      secretKey.fill(0);
    }
  }

  if (request.type === 'NOSTR_CREATE_NEW_KEY') {
    if (!isInternalExtensionRequest) {
      throw new Error('Key creation is only allowed from extension UI');
    }
    const secretKey = generateSecretKey();
    try {
      const result = await configureProtectionAndStoreSecretKey(secretKey, await getPasskeyAuthOptions());

      // Neuer Key = alte DM-Nachrichten gehören nicht mehr dazu
      await clearDmCache();
      console.log('[NIP-17] DM cache cleared after new key creation');

      // Register new pubkey in WordPress if wpApi context available
      const wpApi = sanitizeWpApiContext(request.payload?.wpApi);
      if (wpApi && result.pubkey) {
        try {
          await wpApiPostJson(wpApi, 'register/replace', {
            pubkey: result.pubkey,
            expectedCurrentPubkey: ''
          });
        } catch (regErr) {
          console.warn('[Nostr] WP pubkey registration after key creation failed:', regErr.message);
        }
      }

      return {
        success: true,
        pubkey: result.pubkey,
        npub: result.npub,
        protectionMode: result.protectionMode
      };
    } finally {
      secretKey.fill(0);
    }
  }

  if (request.type === 'NOSTR_IMPORT_NSEC') {
    if (!isInternalExtensionRequest) {
      throw new Error('Key import is only allowed from extension UI');
    }
    const nsecInput = String(request.payload?.nsec || '').trim();
    if (!nsecInput) {
      throw new Error('nsec is required');
    }

    let decoded;
    try {
      decoded = nip19.decode(nsecInput);
    } catch {
      throw new Error('Invalid nsec format');
    }
    if (decoded?.type !== 'nsec' || !(decoded.data instanceof Uint8Array)) {
      throw new Error('Invalid nsec payload');
    }
    const importedSecret = new Uint8Array(decoded.data);
    if (importedSecret.length !== 32) {
      importedSecret.fill(0);
      throw new Error('Invalid nsec length');
    }
    try {
      const result = await configureProtectionAndStoreSecretKey(importedSecret, await getPasskeyAuthOptions());

      // Key-Wechsel: alte DM-Nachrichten gehören nicht mehr dazu
      await clearDmCache();
      console.log('[NIP-17] DM cache cleared after key import');

      // Register imported pubkey in WordPress if wpApi context available
      const wpApi = sanitizeWpApiContext(request.payload?.wpApi);
      if (wpApi && result.pubkey) {
        try {
          await wpApiPostJson(wpApi, 'register/replace', {
            pubkey: result.pubkey,
            expectedCurrentPubkey: ''
          });
        } catch (regErr) {
          console.warn('[Nostr] WP pubkey registration after import failed:', regErr.message);
        }
      }

      return {
        success: true,
        pubkey: result.pubkey,
        npub: result.npub
      };
    } finally {
      importedSecret.fill(0);
    }
  }

  if (request.type === 'NOSTR_PUBLISH_PROFILE') {
    if (!isInternalExtensionRequest) {
      throw new Error('Profile publish is only allowed from extension UI');
    }

    const hasKey = await keyManager.hasKey();
    if (!hasKey) {
      throw new Error('No local key found for this scope.');
    }

    const relays = normalizeRelayList(request.payload?.relays);
    if (!relays.length) {
      throw new Error('No valid relay URL configured for profile publish.');
    }

    const content = sanitizeKind0ProfileContent(request.payload?.profile, request.payload?.origin);
    if (!Object.keys(content).length) {
      throw new Error('Profile payload is empty.');
    }

    const protectionMode = await keyManager.getProtectionMode();
    const unlockPassword = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const signedEvent = await keyManager.signEvent(
      {
        kind: 0,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: JSON.stringify(content)
      },
      protectionMode === KeyManager.MODE_PASSWORD ? unlockPassword : null
    );
    await keyManager.setStoredPublicKey(signedEvent.pubkey);

    const expectedPubkey = normalizePubkeyHex(request.payload?.expectedPubkey);
    const signerPubkey = normalizePubkeyHex(signedEvent.pubkey);
    if (expectedPubkey && signerPubkey && expectedPubkey !== signerPubkey) {
      throw new Error('Signer key does not match expected profile key.');
    }

    let publishedRelay = null;
    let lastError = null;
    for (const relayUrl of relays) {
      try {
        await publishEventToRelay(relayUrl, signedEvent, 9000);
        publishedRelay = relayUrl;
        break;
      } catch (error) {
        lastError = error;
      }
    }

    if (!publishedRelay) {
      throw (lastError || new Error('Profile publish failed on all relays.'));
    }

    return {
      success: true,
      relay: publishedRelay,
      eventId: signedEvent.id,
      pubkey: signerPubkey,
      npub: toNpub(signerPubkey),
      createdAt: signedEvent.created_at
    };
  }

  // NOSTR_GET_CONTACTS - Kontaktliste abrufen (TASK-18)
  if (request.type === 'NOSTR_GET_CONTACTS') {
    if (!isInternalExtensionRequest) {
      throw new Error('Contacts are only available from extension UI');
    }

    // Versuche zuerst den pubkey aus dem existierenden Cache zu holen
    // Das funktioniert auch wenn der Key in einem anderen Scope gespeichert ist
    const cacheResult = await chrome.storage.local.get([CONTACTS_CACHE_KEY]);
    const existingCache = cacheResult[CONTACTS_CACHE_KEY];
    let pubkey = existingCache?.pubkey || null;
    
    // Falls kein pubkey im Cache, aus Key Manager holen
    if (!pubkey) {
      pubkey = await getKnownPublicKeyHex();
    }
    
    if (!pubkey) {
      return { contacts: [], source: 'none', reason: 'no_key' };
    }
    const wpApi = sanitizeWpApiContext(request.payload?.wpApi);
    const cachedWpMembers = await getCachedWpMembers(wpApi);
    const includeWpMembers = Boolean(wpApi) || Boolean(cachedWpMembers?.members?.length);

    // Cache prüfen - an pubkey gebunden, nicht scope
    const cached = await getCachedContacts(pubkey, includeWpMembers);
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

    // WP Members falls wpApi vorhanden - mit Cache nutzen
    let wpMembers = [];
    let wpMembersStale = false;
    if (cachedWpMembers) {
      wpMembers = cachedWpMembers.members;
      wpMembersStale = cachedWpMembers.isStale;
    }
      
    if (wpApi) {
      // Wenn kein Cache oder stale, neu laden
      if (!cachedWpMembers || cachedWpMembers.isStale) {
        const freshWpMembers = await fetchWpMembers(wpApi);
        if (freshWpMembers.length > 0) {
          wpMembers = freshWpMembers;
          await setCachedWpMembers(wpApi, freshWpMembers);
          wpMembersStale = false;
        }
      }
    }

    // Merge
    const contacts = mergeContacts(nostrContacts, profiles, wpMembers);
    await setCachedContacts(pubkey, contacts, includeWpMembers);

    return { 
      contacts, 
      source: 'fresh',
      wpMembersStale 
    };
  }

  // NOSTR_REFRESH_CONTACTS - Kontaktliste aktualisieren (Force-Refresh)
  if (request.type === 'NOSTR_REFRESH_CONTACTS') {
    if (!isInternalExtensionRequest) {
      throw new Error('Contacts refresh is only available from extension UI');
    }

    await clearContactsCache();

    const pubkey = await getKnownPublicKeyHex();
    if (!pubkey) {
      return { contacts: [], source: 'none', reason: 'no_key' };
    }
    const wpApi = sanitizeWpApiContext(request.payload?.wpApi);
    const includeWpMembers = Boolean(wpApi);

    const relayUrl = normalizeRelayUrl(request.payload?.relayUrl) ||
      normalizeRelayUrl((await chrome.storage.local.get(['dmRelayUrl'])).dmRelayUrl) ||
      'wss://relay.damus.io';

    const nostrContacts = await fetchContactList(pubkey, relayUrl);
    const pubkeys = nostrContacts.map(c => c.pubkey);
    const profiles = await fetchProfiles(pubkeys, relayUrl);

    let wpMembers = [];
    if (wpApi) {
      // WP Members neu laden (Force-Refresh)
      wpMembers = await fetchWpMembers(wpApi);
      if (wpMembers.length > 0) {
        await setCachedWpMembers(wpApi, wpMembers);
      }
    }

    const contacts = mergeContacts(nostrContacts, profiles, wpMembers);
    await setCachedContacts(pubkey, contacts, includeWpMembers);

    return { contacts, source: 'fresh' };
  }

  if (request.type === 'NOSTR_ADD_CONTACT') {
    if (!isInternalExtensionRequest) {
      throw new Error('Adding contacts is only available from extension UI');
    }

    const contactPubkey = normalizeContactInputPubkey(request.payload?.contact || request.payload?.pubkey || request.payload?.npub);
    if (!contactPubkey) {
      throw new Error('Ungültiger Kontakt-Pubkey (erwarte hex oder npub).');
    }

    const hasKey = await keyManager.hasKey();
    if (!hasKey) {
      throw new Error('No local key found for this scope.');
    }

    const relayUrl = normalizeRelayUrl(request.payload?.relayUrl) ||
      normalizeRelayUrl((await chrome.storage.local.get(['dmRelayUrl'])).dmRelayUrl) ||
      'wss://relay.damus.io';

    const protectionMode = await keyManager.getProtectionMode();
    const unlockPassword = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? unlockPassword : null);
    if (!secretKey) {
      throw new Error('Failed to unlock key for contact update.');
    }

    try {
      const ownPubkey = getPublicKey(secretKey);
      if (ownPubkey === contactPubkey) {
        throw new Error('Du kannst dich nicht selbst hinzufügen.');
      }

      const latestContactEvent = await fetchLatestContactListEvent(ownPubkey, relayUrl);
      const baseTags = Array.isArray(latestContactEvent?.tags) ? latestContactEvent.tags : [];
      const nonContactTags = baseTags.filter((tag) => !(Array.isArray(tag) && tag[0] === 'p'));
      const existingContactTags = baseTags.filter((tag) => Array.isArray(tag) && tag[0] === 'p' && normalizePubkeyHex(tag[1]));

      const contactMap = new Map();
      for (const tag of existingContactTags) {
        const pk = normalizePubkeyHex(tag[1]);
        if (!pk || contactMap.has(pk)) continue;
        contactMap.set(pk, {
          relayUrl: String(tag[2] || '').trim() || null,
          petname: String(tag[3] || '').trim() || null
        });
      }

      if (contactMap.has(contactPubkey)) {
        return {
          success: true,
          alreadyExists: true,
          pubkey: contactPubkey,
          npub: toNpub(contactPubkey),
          relay: relayUrl,
          totalContacts: contactMap.size
        };
      }

      contactMap.set(contactPubkey, { relayUrl: null, petname: null });

      const updatedContactTags = [];
      for (const [pk, meta] of contactMap.entries()) {
        const tag = ['p', pk];
        if (meta.relayUrl || meta.petname) {
          tag.push(meta.relayUrl || '');
          if (meta.petname) {
            tag.push(meta.petname);
          }
        }
        updatedContactTags.push(tag);
      }

      const signedEvent = await keyManager.signEvent(
        {
          kind: 3,
          created_at: Math.floor(Date.now() / 1000),
          tags: [...nonContactTags, ...updatedContactTags],
          content: typeof latestContactEvent?.content === 'string' ? latestContactEvent.content : ''
        },
        protectionMode === KeyManager.MODE_PASSWORD ? unlockPassword : null
      );

      await publishEventToRelay(relayUrl, signedEvent, 10000);
      await clearContactsCache();

      return {
        success: true,
        alreadyExists: false,
        pubkey: contactPubkey,
        npub: toNpub(contactPubkey),
        relay: relayUrl,
        eventId: signedEvent.id,
        totalContacts: contactMap.size
      };
    } finally {
      secretKey.fill(0);
    }
  }

  // ============================================================
  // NIP-17 Direktnachrichten Message Handler
  // ============================================================

  // NOSTR_SEND_DM - Direktnachricht senden
  if (request.type === 'NOSTR_SEND_DM') {
    if (!isInternalExtensionRequest) {
      throw new Error('DM sending is only available from extension UI');
    }

    const { recipientPubkey, content, relayUrl } = request.payload || {};
    const normalizedRecipient = normalizePubkeyHex(recipientPubkey);
    if (!normalizedRecipient) {
      throw new Error('Invalid recipient pubkey');
    }
    if (!content || typeof content !== 'string') {
      throw new Error('Message content is required');
    }
    if (content.length > 10000) {
      throw new Error('Message too long (max 10000 characters)');
    }

    // Private Key holen (scope-unabhängig, Race-Condition-sicher)
    const dmKeyInfo = await findDmKey();
    if (!dmKeyInfo) {
      throw new Error('No local key found for DM operations.');
    }
    const { km: dmKm, scope: dmScope, protectionMode } = dmKeyInfo;

    const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const privateKeyRaw = await dmKm.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
    if (!privateKeyRaw) {
      throw new Error('Failed to unlock key');
    }
    const privateKey = ensureUint8(privateKeyRaw);

    try {
      const senderPubkey = getPublicKey(privateKey);

      // Eigene Inbox-Relays ermitteln (für Self-Copy)
      const myInboxRelays = await resolveDmInboxRelays(relayUrl, senderPubkey);

      // DM-Relays des Empfängers herausfinden (Kind 10050)
      // WICHTIG: Lookup über allgemeine Relays, NICHT über eigene Inbox-Relays!
      // Eigene Inbox-Relays haben das Kind 10050 des Empfängers i.d.R. nicht.
      const recipientLookupRelays = await resolveRecipientLookupRelays(relayUrl);
      let targetRelays = await fetchDmRelays(normalizedRecipient, recipientLookupRelays, {
        timeoutMs: 3500
      });
      if (!targetRelays.length) {
        // Fallback: send to lookup relays to maximize interoperability.
        console.log('[NIP-17] No recipient relays found, using lookup relays as fallback');
        targetRelays = [...new Set([...recipientLookupRelays, ...DEFAULT_DM_RELAYS])];
      }

      // Gift Wraps erstellen
      // Force Uint8Array conversion for crypto ops
      const secureKey = ensureUint8(privateKey);
      const { wrapForRecipient, wrapForSelf, innerId } = createGiftWrappedDM(
        secureKey, normalizedRecipient, content
      );

      console.log('[NIP-17] Sending DM via relays:', targetRelays);

      // Parallel an Empfänger-Relays publishen
      const publishPromises = targetRelays.map(async (relay) => {
        try {
          await relayManager.publishEvent(relay, wrapForRecipient, 10000);
          console.log('[NIP-17] Published to recipient relay:', relay);
          return { relay, success: true };
        } catch (e) {
          console.warn('[NIP-17] Failed to publish to recipient relay:', relay, e.message);
          return { relay, success: false, error: e.message };
        }
      });

      // Selbst-Kopie im Hintergrund auf alle eigenen Inbox-Relays (Fire & Forget)
      // Damit wir die Nachricht auch auf allen unseren Relays wiederfinden.
      for (const selfRelay of myInboxRelays) {
        relayManager.publishEvent(selfRelay, wrapForSelf, 15000)
          .catch(e => console.warn('[NIP-17] Failed to publish self-copy to', selfRelay, ':', e.message));
      }

      // Nur auf Empfänger-Bestätigungen warten (kritisch)
      const recipientResults = await Promise.all(publishPromises);
      
      const publishErrors = recipientResults
        .filter(r => !r.success)
        .map(r => ({ relay: r.relay, error: r.error }));

      // Lokal cachen
      await cacheDmMessage({
        id: wrapForRecipient.id,
        innerId,
        senderPubkey,
        recipientPubkey: normalizedRecipient,
        content,
        createdAt: Math.floor(Date.now() / 1000),
        direction: 'out',
        giftWrapId: wrapForRecipient.id,
        receivedAt: Date.now()
      }, dmScope, senderPubkey);

      return {
        success: true,
        eventId: wrapForRecipient.id,
        innerId,
        publishedTo: targetRelays,
        errors: publishErrors.length > 0 ? publishErrors : undefined
      };
    } finally {
      privateKey.fill(0);
    }
  }

  // NOSTR_GET_DMS - Direktnachrichten abrufen
  if (request.type === 'NOSTR_GET_DMS') {
    if (!isInternalExtensionRequest) {
      throw new Error('DMs are only available from extension UI');
    }

    const { relayUrl, since, limit, contactPubkey } = request.payload || {};

    // Scope-unabhängig Key suchen (Race-Condition-sicher)
    const dmKeyInfo = await findDmKey();
    const scope = dmKeyInfo ? dmKeyInfo.scope : activeKeyScope;

    // Kein Key → nur Cache zurückgeben (ohne ownerPubkey-Validierung)
    if (!dmKeyInfo) {
      const cachedMessages = await getCachedDmMessages(scope, contactPubkey);
      return { messages: cachedMessages, source: 'cache_only', reason: 'no_key' };
    }

    // Key unlocking
    const { km: dmKm, protectionMode } = dmKeyInfo;
    let privateKey;

    try {
      const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
      const rawKey = await dmKm.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
      privateKey = ensureUint8(rawKey);
    } catch (e) {
      console.warn('[NIP-17] Key unlock exception:', e.message, 'protectionMode:', protectionMode, 'scope:', scope);
      const cachedMessages = await getCachedDmMessages(scope, contactPubkey);
      if (cachedMessages.length > 0) {
        return { messages: cachedMessages, source: 'cache_strict', reason: 'unlock_cancelled' };
      }
      throw e;
    }

    if (!privateKey || privateKey.length !== 32) {
      console.error('[NIP-17] Key unlock failed. protectionMode:', protectionMode, 'scope:', scope,
        'key:', privateKey ? `length=${privateKey.length}` : 'null');
      const cachedMessages = await getCachedDmMessages(scope, contactPubkey);
      if (cachedMessages.length > 0) {
        return { messages: cachedMessages, source: 'cache_fallback', reason: 'key_unlock_failed' };
      }
      throw new Error('Failed to unlock key for DM decryption');
    }

    const myPubkey = getPublicKey(privateKey);

    // Cache mit ownerPubkey-Validierung lesen (Konversations-basiert)
    const cachedMessages = await getCachedDmMessages(scope, contactPubkey, myPubkey);

    // since-Filter: Letzten bekannten Zeitstempel als Basis
    let fetchSince = since;
    if (!fetchSince && cachedMessages.length > 0) {
      fetchSince = Math.max(0, cachedMessages[cachedMessages.length - 1].createdAt - 3600);
    }

    try {
      // Multi-Relay: Alle DM-Inbox-Relays ermitteln (NIP-17)
      const inboxRelays = await resolveDmInboxRelays(relayUrl, myPubkey);

      const filters = [{
        kinds: [1059],
        '#p': [myPubkey],
        limit: limit || 100
      }];
      if (fetchSince) filters[0].since = fetchSince;

      // Parallel Fetch: mit Cache schneller (kürzerer Timeout), ohne Cache etwas großzügiger.
      const dmFetchTimeoutMs = cachedMessages.length > 0 ? 2200 : 3500;
      const fetchPromises = inboxRelays.map(r => subscribeOnce(r, filters, dmFetchTimeoutMs).catch(() => []));
      const results = await Promise.all(fetchPromises);
      const giftWraps = results.flat();

      // Deduplizieren der GiftWraps
      const uniqueWraps = new Map();
      giftWraps.forEach(gw => uniqueWraps.set(gw.id, gw));

      // Entschlüsseln und validieren
      const newMessages = [];
      for (const gw of uniqueWraps.values()) {
        try {
          const msg = unwrapGiftWrap(privateKey, gw);
          msg.giftWrapId = msg.id;
          msg.direction = msg.senderPubkey === myPubkey ? 'out' : 'in';
          msg.receivedAt = Date.now();
          newMessages.push(msg);
        } catch(e) {
          // Silently skip (fremde Gift Wraps)
        }
      }
      
      privateKey.fill(0);

      // Alle neuen Nachrichten cachen (Konversations-Zuordnung passiert automatisch
      // in cacheDmMessage über resolveConversationPartner)
      if (newMessages.length > 0) {
        await cacheDmMessages(newMessages, scope, myPubkey);
      }

      // Finalen Konversations-Cache lesen (enthält jetzt alte + neue, dedupliziert)
      const allMessages = await getCachedDmMessages(scope, contactPubkey, myPubkey);

      return { messages: allMessages, source: newMessages.length > 0 ? 'merged' : 'cache', relays: inboxRelays };
      
    } catch (error) {
       console.error('Failed to fetch/decrypt DMs:', error);
       privateKey.fill(0);
       return { messages: cachedMessages, source: 'cache_fallback', error: error.message }; 
    }
  }

  // NOSTR_SUBSCRIBE_DMS - Subscription für eingehende DMs starten
  if (request.type === 'NOSTR_SUBSCRIBE_DMS') {
    if (!isInternalExtensionRequest) {
      throw new Error('DM subscription is only available from extension UI');
    }

    const { relayUrl } = request.payload || {};

    // Private Key holen (scope-unabhängig, Race-Condition-sicher)
    const dmKeyInfo = await findDmKey();
    if (!dmKeyInfo) {
      throw new Error('No local key found for DM operations.');
    }
    const { km: dmKm, scope: dmScope, protectionMode } = dmKeyInfo;

    const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
    const rawKey = await dmKm.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
    if (!rawKey) {
      throw new Error('Failed to unlock key');
    }
    const privateKey = ensureUint8(rawKey);

    try {
      const myPubkey = getPublicKey(privateKey);

      // Multi-Relay: Alle DM-Inbox-Relays ermitteln (NIP-17)
      const inboxRelays = await resolveDmInboxRelays(relayUrl, myPubkey);

      // WICHTIG: Kopie des Keys für die Subscription erstellen!
      // Die Subscription läuft weiter und braucht den Key für jeden eingehenden Gift Wrap.
      // Das Original wird im finally-Block sicher gelöscht.
      const subscriptionKey = new Uint8Array(privateKey);

      // Alte Subscriptions beenden
      for (const oldSubId of activeDmSubscriptionIds) {
        relayManager.unsubscribe(oldSubId);
      }
      activeDmSubscriptionIds = [];

      // Auf allen Inbox-Relays subscriben
      const newSubIds = [];
      for (const relay of inboxRelays) {
        try {
          const subId = await startDmSubscription(dmScope, relay, myPubkey, subscriptionKey);
          newSubIds.push(subId);
          console.log('[NIP-17] Subscription gestartet auf:', relay, 'subId:', subId);
        } catch (e) {
          console.warn('[NIP-17] Subscription fehlgeschlagen auf:', relay, e.message);
        }
      }
      activeDmSubscriptionIds = newSubIds;

      return { subscriptionIds: newSubIds, status: 'active', relays: inboxRelays };
    } finally {
      privateKey.fill(0); // Original sicher löschen - Subscription hat eigene Kopie
    }
  }

  // NOSTR_SET_DOMAIN_CONFIG - Konfiguration f????r Domain-Sync setzen
  if (request.type === 'NOSTR_SET_DOMAIN_CONFIG') {
    const { primaryDomain, domainSecret, authBroker } = request.payload || {};
    if (!primaryDomain || !domainSecret) {
      throw new Error('Invalid domain sync config');
    }
    // Domain-Config darf nur von der Primary Domain selbst gesetzt werden.
    const primaryHost = extractHostFromPrimaryDomain(primaryDomain);
    if (!domain || !primaryHost || domain.toLowerCase() !== primaryHost.toLowerCase()) {
      throw new Error('Domain config can only be set from primary domain');
    }
    const result = await upsertDomainSyncConfig(primaryDomain, domainSecret, authBroker);
    // Domain-Sync im Hintergrund starten, damit der Message-Channel sofort antwortet.
    updateDomainWhitelist().catch((e) => {
      console.error('Failed to update domains after config:', e);
    });
    return { success: true, configCount: result.configCount, primaryHost: result.primaryHost };
  }

  if (request.type === 'NOSTR_GET_DOMAIN_SYNC_STATE') {
    return await getDomainSyncState();
  }

  // Domain-Validierung nur fuer Website-Requests (Content-Script mit sender.tab).
  // Interne Extension-Requests (Popup/Options) duerfen ohne Domain arbeiten.
  if (!isInternalExtensionRequest) {
    const domainStatus = await checkDomainAccess(domain);
    if (domainStatus === DOMAIN_STATUS.BLOCKED) {
      throw new Error('Domain not authorized');
    }
    if (domainStatus === DOMAIN_STATUS.PENDING) {
      const isPrimaryDomain = await isConfiguredPrimaryDomain(domain);

      if (isPrimaryDomain) {
        await allowDomain(domain);
      } else {
        // User muss Domain erst bestaetigen
        const allowed = await promptDomainApproval(domain);
        if (!allowed) throw new Error('Domain rejected by user');
      }
    }
  }

  switch (request.type) {
    case 'NOSTR_GET_PUBLIC_KEY': {
      const allowCreateIfMissing = request?.payload?.createIfMissing !== false;

      // forceNew: discard any existing key in this scope and generate a fresh one.
      // Used by performRegistration() to recover from pubkey_in_use conflicts
      // (e.g. a key wrongly copied from another WP user's scope).
      if (request?.payload?.forceNew === true) {
        console.log('[Nostr] forceNew requested for scope', activeKeyScope, '– discarding existing key');
        await keyManager.clearScopeKeys();
        await clearUnlockCaches();
      }

      if (!await keyManager.hasKey()) {
        if (!allowCreateIfMissing) {
          throw new Error('No local key found for this scope.');
        }

        // Check if user already has keys in other scopes.
        // If so, silently inherit protection mode instead of showing the full wizard.
        const existingPref = await getExistingProtectionPreference();

        if (existingPref.hasOtherScopes && existingPref.preferredProtection) {
          // Copy existing key from source scope to new scope (same identity!)
          const srcKm = new KeyManager(chrome.storage.local, existingPref.sourceScope);
          const inheritedMode = existingPref.preferredProtection;

          if (inheritedMode === KeyManager.MODE_NONE) {
            // Silent key copy: reuse same identity across scopes
            const srcKey = await srcKm.getKey(null);
            if (srcKey) {
              await keyManager.storeKey(srcKey, null);
              const pubkey = getPublicKey(srcKey);
              await keyManager.setStoredPublicKey(pubkey);
              srcKey.fill(0);
              await clearUnlockCaches();
              return pubkey;
            }
          }

          if (inheritedMode === KeyManager.MODE_PASSWORD) {
            const password = await ensurePasswordIfNeeded(true);
            const srcKey = await srcKm.getKey(password);
            if (srcKey) {
              await keyManager.storeKey(srcKey, password);
              const pubkey = getPublicKey(srcKey);
              await keyManager.setStoredPublicKey(pubkey);
              srcKey.fill(0);
              await cachePasswordWithPolicy(password);
              return pubkey;
            }
          }

          if (inheritedMode === KeyManager.MODE_PASSKEY) {
            await ensurePasskeyIfNeeded(await getPasskeyAuthOptions());
            const srcCredKey = new KeyManager(chrome.storage.local, existingPref.sourceScope)
              .keyName(KeyManager.PASSKEY_ID_KEY);
            const srcStorage = await chrome.storage.local.get([srcCredKey]);
            const existingCredentialId = String(srcStorage[srcCredKey] || '').trim();
            if (existingCredentialId) {
              const srcKey = await srcKm.getKey(null);
              if (srcKey) {
                await keyManager.storeKey(srcKey, null, {
                  mode: KeyManager.MODE_PASSKEY,
                  passkeyCredentialId: existingCredentialId
                });
                const pubkey = getPublicKey(srcKey);
                await keyManager.setStoredPublicKey(pubkey);
                srcKey.fill(0);
                await cachePasskeyAuthWithPolicy();
                return pubkey;
              }
            }
            // Fall through to full dialog if credential not found
          }
        }

        // First-time user: full setup dialog
        const createResult = await promptPassword('create');
        if (!createResult) throw new Error('Password setup canceled');

        const setupMode = typeof createResult === 'object' ? createResult.protection : null;
        const usePasskey = setupMode === KeyManager.MODE_PASSKEY;
        const useNoPassword = !usePasskey && typeof createResult === 'object' && createResult.noPassword === true;
        const password = usePasskey ? null : extractPasswordFromDialogResult(createResult);
        if (!useNoPassword && !usePasskey && !password) throw new Error('Password required');

        if (useNoPassword) {
          await clearUnlockCaches();
        } else {
          await cachePasswordWithPolicy(password);
        }

        const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(
          useNoPassword ? null : password,
          usePasskey ? {
            mode: KeyManager.MODE_PASSKEY,
            passkeyCredentialId: createResult.credentialId
          } : undefined
        );

        if (usePasskey) {
          await cachePasskeyAuthWithPolicy();
        }

        await openBackupDialog(npub, nsecBech32);
        return pubkey;
      }
      const storedPubkey = await keyManager.getStoredPublicKey();
      if (storedPubkey) {
        return storedPubkey;
      }

      const protectionMode = await keyManager.getProtectionMode();
      const password = protectionMode === KeyManager.MODE_PASSWORD
        ? await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions())
        : null;
      const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
      if (!secretKey) throw new Error(protectionMode === KeyManager.MODE_PASSWORD ? 'Invalid password' : 'No key found');
      const pubkey = getPublicKey(secretKey);
      secretKey.fill(0);
      await keyManager.setStoredPublicKey(pubkey);
      return pubkey;
    }

    case 'NOSTR_SIGN_EVENT': {
      const protectionMode = await keyManager.getProtectionMode();
      const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
      const sensitiveKinds = [0, 3, 4];
      if (sensitiveKinds.includes(request.payload?.kind)) {
        const confirmed = await promptSignConfirmation(request.payload, domain);
        if (!confirmed) throw new Error('Signing rejected by user');
      }
      return await keyManager.signEvent(
        request.payload,
        protectionMode === KeyManager.MODE_PASSWORD ? password : null
      );
    }

    case 'NOSTR_GET_RELAYS': {
      const { relays = {} } = await chrome.storage.local.get('relays');
      return relays;
    }

    case 'NOSTR_NIP04_ENCRYPT':
    case 'NOSTR_NIP04_DECRYPT': {
      const protectionMode = await keyManager.getProtectionMode();
      const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
      const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
      if (!secretKey) throw new Error(protectionMode === KeyManager.MODE_PASSWORD ? 'Invalid password' : 'No key found');
      try {
        const { pubkey, plaintext, ciphertext } = request.payload;
        if (request.type === 'NOSTR_NIP04_ENCRYPT') return await handleNIP04Encrypt(secretKey, pubkey, plaintext);
        else return await handleNIP04Decrypt(secretKey, pubkey, ciphertext);
      } finally { secretKey.fill(0); }
    }

    case 'NOSTR_NIP44_ENCRYPT':
    case 'NOSTR_NIP44_DECRYPT': {
      const protectionMode = await keyManager.getProtectionMode();
      const password = await ensureUnlockForMode(protectionMode, await getPasskeyAuthOptions());
      const secretKey = await keyManager.getKey(protectionMode === KeyManager.MODE_PASSWORD ? password : null);
      if (!secretKey) throw new Error(protectionMode === KeyManager.MODE_PASSWORD ? 'Invalid password' : 'No key found');
      try {
        const { pubkey, plaintext, ciphertext } = request.payload;
        if (request.type === 'NOSTR_NIP44_ENCRYPT') return handleNIP44Encrypt(secretKey, pubkey, plaintext);
        else return handleNIP44Decrypt(secretKey, pubkey, ciphertext);
      } finally { secretKey.fill(0); }
    }

    default:
      throw new Error('Unknown method: ' + request.type);
  }
}

// ============================================================
// UI-Dialoge Helper
// ============================================================

async function getExistingProtectionPreference() {
  const scopes = await listStoredKeyScopes();
  if (!scopes.length) return { hasOtherScopes: false, preferredProtection: null };

  // When the active scope is user-specific (wp:host:u:N), prefer a source scope
  // with the same user-id so the same identity is inherited across domains.
  const currentUserIdMatch = activeKeyScope.match(/:u:(\d+)$/);
  const preferredUserId = currentUserIdMatch ? currentUserIdMatch[1] : null;

  let bestMatch = null;
  let fallbackMatch = null;

  for (const scope of scopes) {
    if (scope === activeKeyScope) continue; // skip the scope we are trying to populate
    try {
      const tmpKm = new KeyManager(chrome.storage.local, scope);
      const mode = await tmpKm.getProtectionMode();
      if (!mode) continue;

      const candidate = { hasOtherScopes: true, preferredProtection: mode, sourceScope: scope };

      if (preferredUserId) {
        const candidateUserIdMatch = scope.match(/:u:(\d+)$/);
        if (candidateUserIdMatch && candidateUserIdMatch[1] === preferredUserId) {
          // Exact user-id match (same identity across domains) – use immediately
          return candidate;
        }
        // IMPORTANT: When the active scope is user-specific (wp:host:u:N),
        // never inherit keys from a DIFFERENT user (wp:host:u:M where M≠N).
        // This prevents the same private key being shared between distinct
        // WordPress accounts, which would cause "pubkey_in_use" errors.
        if (candidateUserIdMatch && candidateUserIdMatch[1] !== preferredUserId) {
          continue; // skip scopes belonging to a different WP user
        }
      }

      // Remember first valid scope as fallback (only global or non-user scopes reach here
      // when preferredUserId is set, since cross-user scopes are skipped above)
      if (!fallbackMatch) {
        fallbackMatch = candidate;
      }
    } catch {
      // skip broken scopes
    }
  }

  if (fallbackMatch) return fallbackMatch;
  return { hasOtherScopes: scopes.length > 0, preferredProtection: null };
}

async function promptPassword(mode, passkeyAuthOptions = null) {
  await chrome.storage.session.remove('passwordResult');

  // Pre-fetch cached WP display name so the passkey label is human-readable.
  let wpDisplayName = '';
  try {
    const vc = await chrome.storage.local.get(['nostrViewerProfileCacheV1']);
    wpDisplayName = String(vc?.nostrViewerProfileCacheV1?.displayName || vc?.nostrViewerProfileCacheV1?.userLogin || '').trim();
  } catch { /* best-effort */ }

  return new Promise((resolve) => {
    let timeoutId = null;
    const normalizedMode = String(mode || '').trim();
    const isPasskeyMode = normalizedMode === 'unlock-passkey';
    const timeoutMs = isPasskeyMode ? PASSKEY_DIALOG_TIMEOUT_MS : DIALOG_TIMEOUT_MS;
    const dialogWindowSize = getPasswordDialogWindowSize(normalizedMode);

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      chrome.storage.onChanged.removeListener(listener);
    };

    const listener = (changes, areaName) => {
      if (areaName !== 'session') return;
      if (!changes.passwordResult) return;
      cleanup();
      resolve(changes.passwordResult.newValue);
      chrome.storage.session.remove('passwordResult');
    };

    chrome.storage.onChanged.addListener(listener);

    timeoutId = setTimeout(() => {
      cleanup();
      resolve(null);
    }, timeoutMs);

    const query = new URLSearchParams({
      type: 'password',
      mode: String(mode || ''),
      scope: activeKeyScope || KEY_SCOPE_DEFAULT
    });

    if (wpDisplayName) query.set('wpDisplayName', wpDisplayName);

    const broker = sanitizePasskeyAuthBroker(passkeyAuthOptions);
    if (broker?.enabled && broker.url) {
      query.set('passkeyBrokerUrl', broker.url);
      if (broker.origin) query.set('passkeyBrokerOrigin', broker.origin);
      if (broker.rpId) query.set('passkeyBrokerRpId', broker.rpId);
    }
    const intent = String(passkeyAuthOptions?.intent || '').trim();
    if (intent) {
      query.set('passkeyIntent', intent);
    }

    chrome.windows.create({
      url: `dialog.html?${query.toString()}`,
      type: 'popup',
      width: dialogWindowSize.width,
      height: dialogWindowSize.height,
      focused: true
    });
  });
}

function getPasswordDialogWindowSize(mode) {
  switch (mode) {
    case 'create':
      return { width: 520, height: 720 };
    case 'unlock-passkey':
    case 'create-passkey':
      return { width: 560, height: 760 };
    case 'create-password':
      return { width: 420, height: 480 };
    case 'unlock':
    default:
      return { width: 420, height: 420 };
  }
}

async function promptSignConfirmation(event, domain) {
  await chrome.storage.local.remove('signConfirmResult');
  return new Promise((resolve) => {
    let timeoutId = null;

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      chrome.storage.onChanged.removeListener(listener);
    };

    const listener = (changes, areaName) => {
      if (areaName !== 'local') return;
      if (!changes.signConfirmResult) return;
      cleanup();
      resolve(Boolean(changes.signConfirmResult.newValue));
      chrome.storage.local.remove('signConfirmResult');
    };

    chrome.storage.onChanged.addListener(listener);

    timeoutId = setTimeout(() => {
      cleanup();
      resolve(false);
    }, DIALOG_TIMEOUT_MS);

    chrome.windows.create({
      url: `dialog.html?type=confirm&domain=${encodeURIComponent(domain)}&kind=${event.kind}`,
      type: 'popup', width: 500, height: 400, focused: true
    });
  });
}

async function openBackupDialog(npub, nsecBech32) {
  let wpDisplayName = '';
  try {
    const vc = await chrome.storage.local.get(['nostrViewerProfileCacheV1']);
    wpDisplayName = String(vc?.nostrViewerProfileCacheV1?.displayName || vc?.nostrViewerProfileCacheV1?.userLogin || '').trim();
  } catch { /* best-effort */ }
  const qs = new URLSearchParams({
    type: 'backup',
    npub: npub || '',
    nsec: nsecBech32 || ''
  });
  if (wpDisplayName) qs.set('wpDisplayName', wpDisplayName);
  await chrome.windows.create({
    url: `dialog.html?${qs.toString()}`,
    type: 'popup', width: 500, height: 650, focused: true
  });
}

async function promptDomainApproval(domain) {
  await chrome.storage.local.remove('domainApprovalResult');
  return new Promise((resolve) => {
    let timeoutId = null;

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      chrome.storage.onChanged.removeListener(listener);
    };

    const listener = (changes, areaName) => {
      if (areaName !== 'local') return;
      if (!changes.domainApprovalResult) return;
      const result = changes.domainApprovalResult.newValue;
      if (!result || result.domain !== domain) return;
      cleanup();
      resolve(Boolean(result.allowed));
      chrome.storage.local.remove('domainApprovalResult');
    };

    chrome.storage.onChanged.addListener(listener);

    timeoutId = setTimeout(() => {
      cleanup();
      resolve(false);
    }, DIALOG_TIMEOUT_MS);

    chrome.windows.create({
      url: `dialog.html?type=domain&domain=${encodeURIComponent(domain)}`,
      type: 'popup', width: 450, height: 350, focused: true
    });
  });
}

// ============================================================
// Domain Sync
// ============================================================
function getPrimaryDomainBaseUrl(primaryDomain) {
  const value = String(primaryDomain || '').trim();
  if (!value) return null;

  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      return `${url.protocol}//${url.host}`;
    } catch {
      return null;
    }
  }

  const host = value
    .replace(/^\/\//, '')
    .replace(/\/.*$/, '');
  if (!host) return null;

  const hostnameOnly = host.replace(/:\d+$/, '').toLowerCase();
  const isLocalDev =
    /^(localhost|127\.0\.0\.1)$/i.test(hostnameOnly) ||
    /^10\./.test(hostnameOnly) ||
    /^192\.168\./.test(hostnameOnly) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostnameOnly) ||
    /\.(test|local|localhost)$/i.test(hostnameOnly);

  const protocol = isLocalDev ? 'http' : 'https';
  return `${protocol}://${host}`;
}

function getPrimaryDomainBaseUrlCandidates(primaryDomain) {
  const baseUrl = getPrimaryDomainBaseUrl(primaryDomain);
  if (!baseUrl) return [];

  const candidates = [baseUrl];
  try {
    const url = new URL(baseUrl);
    const altProtocol = url.protocol === 'https:' ? 'http:' : 'https:';
    candidates.push(`${altProtocol}//${url.host}`);
  } catch {
    // ignore invalid URL
  }

  return Array.from(new Set(candidates));
}
function extractHostFromPrimaryDomain(primaryDomain) {
  const baseUrl = getPrimaryDomainBaseUrl(primaryDomain);
  if (!baseUrl) return null;
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return null;
  }
}

function normalizeDomainEntry(value) {
  const input = String(value || '').trim();
  if (!input) return null;

  if (/^https?:\/\//i.test(input)) {
    try {
      return new URL(input).hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  const host = input
    .replace(/^\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .toLowerCase();
  return host || null;
}

function normalizeDomainList(domains) {
  if (!Array.isArray(domains)) return [];
  return Array.from(new Set(domains.map(normalizeDomainEntry).filter(Boolean)));
}

function normalizeDomainSyncConfigEntry(value) {
  if (!value || typeof value !== 'object') return null;
  const primaryDomain = getPrimaryDomainBaseUrl(value.primaryDomain);
  const domainSecret = String(value.domainSecret || '').trim();
  const primaryHost = extractHostFromPrimaryDomain(primaryDomain);
  if (!primaryDomain || !primaryHost || !domainSecret) return null;
  const authBroker = sanitizePasskeyAuthBroker(value.authBroker);

  return {
    primaryDomain,
    domainSecret,
    updatedAt: Number(value.updatedAt) || null,
    lastSyncAt: Number(value.lastSyncAt) || null,
    lastSyncBaseUrl: typeof value.lastSyncBaseUrl === 'string' ? value.lastSyncBaseUrl : null,
    lastSyncError: typeof value.lastSyncError === 'string' ? value.lastSyncError : null,
    syncedDomains: normalizeDomainList(value.syncedDomains || []),
    authBroker
  };
}

function normalizeDomainSyncConfigs(configs) {
  if (!configs || typeof configs !== 'object') return {};
  const normalized = {};

  for (const [rawHost, rawConfig] of Object.entries(configs)) {
    const normalizedHost = normalizeDomainEntry(rawHost);
    const normalizedConfig = normalizeDomainSyncConfigEntry(rawConfig);
    if (!normalizedHost || !normalizedConfig) continue;
    normalized[normalizedHost] = normalizedConfig;
  }

  return normalized;
}

async function getDomainSyncState() {
  const configs = await getDomainSyncConfigs();
  const { allowedDomains = [], lastDomainUpdate = null } = await chrome.storage.local.get([
    'allowedDomains',
    'lastDomainUpdate'
  ]);

  const items = Object.entries(configs)
    .map(([host, config]) => ({
      host,
      primaryDomain: config.primaryDomain,
      updatedAt: config.updatedAt || null,
      lastSyncAt: config.lastSyncAt || null,
      lastSyncBaseUrl: config.lastSyncBaseUrl || null,
      lastSyncError: config.lastSyncError || null,
      syncedDomains: normalizeDomainList(config.syncedDomains || []),
      authBroker: sanitizePasskeyAuthBroker(config.authBroker)
    }))
    .sort((a, b) => a.host.localeCompare(b.host));

  return {
    configs: items,
    allowedDomains: normalizeDomainList(allowedDomains),
    lastDomainUpdate: Number(lastDomainUpdate) || null
  };
}

async function getDomainSyncConfigs() {
  const storage = await chrome.storage.local.get([DOMAIN_SYNC_CONFIGS_KEY]);
  return normalizeDomainSyncConfigs(storage[DOMAIN_SYNC_CONFIGS_KEY]);
}

async function isConfiguredPrimaryDomain(domain) {
  const normalizedDomain = normalizeDomainEntry(domain);
  if (!normalizedDomain) return false;
  const configs = await getDomainSyncConfigs();
  return Boolean(configs[normalizedDomain]);
}

async function upsertDomainSyncConfig(primaryDomain, domainSecret, authBroker = null) {
  const normalizedPrimaryDomain = getPrimaryDomainBaseUrl(primaryDomain);
  const primaryHost = extractHostFromPrimaryDomain(normalizedPrimaryDomain);
  const normalizedSecret = String(domainSecret || '').trim();
  const normalizedBroker = sanitizePasskeyAuthBroker(authBroker);

  if (!normalizedPrimaryDomain || !primaryHost || !normalizedSecret) {
    throw new Error('Invalid domain sync config');
  }

  const domainSyncConfigs = await getDomainSyncConfigs();
  domainSyncConfigs[primaryHost] = {
    primaryDomain: normalizedPrimaryDomain,
    domainSecret: normalizedSecret,
    updatedAt: Date.now(),
    lastSyncAt: domainSyncConfigs[primaryHost]?.lastSyncAt || null,
    lastSyncBaseUrl: domainSyncConfigs[primaryHost]?.lastSyncBaseUrl || null,
    lastSyncError: null,
    syncedDomains: domainSyncConfigs[primaryHost]?.syncedDomains || [],
    authBroker: normalizedBroker || sanitizePasskeyAuthBroker(domainSyncConfigs[primaryHost]?.authBroker)
  };

  await chrome.storage.local.set({
    [DOMAIN_SYNC_CONFIGS_KEY]: domainSyncConfigs
  });

  return {
    primaryHost,
    configCount: Object.keys(domainSyncConfigs).length
  };
}

async function updateDomainWhitelist() {
  const configs = await getDomainSyncConfigs();
  const entries = Object.entries(configs);
  if (!entries.length) return;

  const { allowedDomains = [] } = await chrome.storage.local.get(['allowedDomains']);
  const mergedAllowedDomains = new Set(normalizeDomainList(allowedDomains));
  const syncedDomains = new Set();
  let hasSuccessfulSync = false;
  let lastError = null;

  for (const [primaryHost, config] of entries) {
    mergedAllowedDomains.add(primaryHost);

    const candidates = getPrimaryDomainBaseUrlCandidates(config.primaryDomain);
    if (!candidates.length) {
      config.lastSyncError = 'Invalid primary domain URL';
      continue;
    }

    let syncSuccessForConfig = false;

    for (const baseUrl of candidates) {
      try {
        const response = await fetch(`${baseUrl}/wp-json/nostr/v1/domains`, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const signatureValid = data.signature &&
          await verifyWhitelistSignature(data.domains, data.updated, data.signature, config.domainSecret);

        if (!signatureValid) throw new Error('Domain list signature invalid');

        const normalizedDomains = normalizeDomainList(data.domains);
        normalizedDomains.forEach((domain) => syncedDomains.add(domain));

        config.lastSyncAt = Date.now();
        config.lastSyncBaseUrl = baseUrl;
        config.lastSyncError = null;
        config.syncedDomains = normalizedDomains;

        hasSuccessfulSync = true;
        syncSuccessForConfig = true;
        break;
      } catch (e) {
        lastError = e;
        config.lastSyncError = String(e?.message || e);
        console.warn(`Domain sync failed via ${baseUrl}:`, e);
      }
    }

    if (!syncSuccessForConfig && !config.lastSyncError) {
      config.lastSyncError = 'Sync failed';
    }
  }

  syncedDomains.forEach((domain) => mergedAllowedDomains.add(domain));

  const updatePayload = {
    [DOMAIN_SYNC_CONFIGS_KEY]: configs,
    allowedDomains: Array.from(mergedAllowedDomains)
  };

  if (hasSuccessfulSync) {
    updatePayload.lastDomainUpdate = Date.now();
  }

  await chrome.storage.local.set(updatePayload);

  if (!hasSuccessfulSync && lastError) {
    console.error('Failed to update domains from all configured primary domains:', lastError);
  }
}

// ============================================================
// Alarm: Periodisches Domain-Sync
// ============================================================
chrome.alarms.create('domainSync', { periodInMinutes: 5 });

// ============================================================
// Alarm: Keep-Alive für Relay-Verbindungen (MV3 Service Worker)
// ============================================================
// MV3 Service Worker werden nach ~30s Inaktivität beendet
// Alarm alle 25 Sekunden (unter 30s Grenze)
chrome.alarms.create('relayKeepalive', { periodInMinutes: 0.42 }); // ~25s

// Alarm für DM-Polling (Fallback)
chrome.alarms.create('dmPolling', { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'domainSync') {
    updateDomainWhitelist();
  }
  
  if (alarm.name === 'relayKeepalive') {
    // Prüfe Relay-Verbindungen, reconnect falls nötig
    relayManager.checkConnections();
  }
  
  if (alarm.name === 'dmPolling') {
    // Poll for new DMs in background
    try {
      const hasKey = await keyManager.hasKey();
      if (!hasKey) return;
      
      const protectionMode = await keyManager.getProtectionMode();
      
      // Nur pollen wenn entsperrt (cached password/passkey)
      let privateKey = null;
      try {
        if (protectionMode === KeyManager.MODE_NONE) {
          privateKey = await keyManager.getKey(null);
        } else if (protectionMode === KeyManager.MODE_PASSWORD) {
          const cached = await getCachedPassword();
          if (cached) {
            privateKey = await keyManager.getKey(cached);
          }
        } else if (protectionMode === KeyManager.MODE_PASSKEY) {
          const cached = await getCachedPasskeyAuth();
          if (cached) {
            privateKey = await keyManager.getKey(null);
          }
        }
      } catch {
        // Key nicht verfügbar - skip polling
      }
      
      if (privateKey) {
        try {
          const myPubkey = getPublicKey(privateKey);
          
          // DM-Relay aus Settings holen
          const dmRelayResult = await chrome.storage.local.get(['dmRelayUrl']);
          const relayUrl = normalizeRelayUrl(dmRelayResult.dmRelayUrl) || 'wss://relay.damus.io';
          
          await pollForNewDms(activeKeyScope, relayUrl, myPubkey, privateKey);
        } finally {
          privateKey.fill(0);
        }
      }
    } catch (error) {
      console.warn('[NIP-17] Background DM polling failed:', error.message);
    }
  }
});
async function getCachedContacts(pubkey, includeWpMembers = false) { try { const result = await chrome.storage.local.get([CONTACTS_CACHE_KEY]); const cache = result[CONTACTS_CACHE_KEY]; if (!cache || cache.pubkey !== pubkey) return null; if (Boolean(cache.includeWpMembers) !== Boolean(includeWpMembers)) return null; if (Date.now() - cache.fetchedAt > CONTACTS_CACHE_TTL) return null; return cache.contacts; } catch { return null; } } async function setCachedContacts(pubkey, contacts, includeWpMembers = false) { try { await chrome.storage.local.set({ [CONTACTS_CACHE_KEY]: { pubkey, includeWpMembers: Boolean(includeWpMembers), contacts, fetchedAt: Date.now() } }); } catch (error) { console.warn('[Nostr] Failed to cache contacts:', error.message); } }
