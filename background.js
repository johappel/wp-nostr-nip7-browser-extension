// Background Service Worker
// Importiert nostr-tools via Rollup Bundle

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';
import { KeyManager } from './lib/key-manager.js';
import { checkDomainAccess, DOMAIN_STATUS, allowDomain, blockDomain, verifyWhitelistSignature } from './lib/domain-access.js';
import { semverSatisfies } from './lib/semver.js';
import { handleNIP04Encrypt, handleNIP04Decrypt, handleNIP44Encrypt, handleNIP44Decrypt } from './lib/crypto-handlers.js';

const CURRENT_VERSION = '1.0.0';
const DOMAIN_SYNC_CONFIGS_KEY = 'domainSyncConfigs';
const LEGACY_PRIMARY_DOMAIN_KEY = 'primaryDomain';
const LEGACY_DOMAIN_SECRET_KEY = 'domainSecret';
const UNLOCK_CACHE_POLICY_KEY = 'unlockCachePolicy';
const UNLOCK_PASSWORD_SESSION_KEY = 'unlockPasswordSession';
const UNLOCK_PASSKEY_SESSION_KEY = 'unlockPasskeySession';
const UNLOCK_CACHE_POLICY_DEFAULT = '15m';
const UNLOCK_CACHE_ALLOWED_POLICIES = new Set(['off', '5m', '15m', '30m', '60m', 'session']);
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
const DIALOG_TIMEOUT_MS = 25000;
const PASSKEY_DIALOG_TIMEOUT_MS = 180000;
let domainSyncMigrationDone = false;

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

function getKeyScopeFromRequest(request) {
  const explicit = typeof request?.scope === 'string'
    ? request.scope
    : (typeof request?.payload?.scope === 'string' ? request.payload.scope : '');
  return normalizeKeyScope(explicit);
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

async function getStoredPasskeyCredentialIdForActiveScope() {
  const credentialStorageKey = keyManager.keyName(KeyManager.PASSKEY_ID_KEY);
  const storage = await chrome.storage.local.get([credentialStorageKey]);
  return String(storage[credentialStorageKey] || '').trim() || null;
}

async function configureProtectionAndStoreSecretKey(secretKey) {
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
      const srcCredKey = new KeyManager(existingPref.sourceScope)
        .keyName(KeyManager.PASSKEY_ID_KEY);
      const srcStorage = await chrome.storage.local.get([srcCredKey]);
      const existingCredentialId = String(srcStorage[srcCredKey] || '').trim();
      if (existingCredentialId) {
        await ensurePasskeyIfNeeded(await getPasskeyAuthOptions());
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
  const domain = sender.tab?.url ? new URL(sender.tab.url).hostname : null;
  const isInternalExtensionRequest = sender?.id === chrome.runtime.id && !sender?.tab?.url;
  const requestType = String(request?.type || '');
  const scopedTypes = new Set([
    'NOSTR_LOCK',
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
    'NOSTR_NIP44_DECRYPT'
  ]);

  if (scopedTypes.has(requestType)) {
    await ensureKeyScope(getKeyScopeFromRequest(request));
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

  // NOSTR_CHECK_VERSION erfordert keine Domain-Validierung
  if (request.type === 'NOSTR_CHECK_VERSION') {
    return {
      version: CURRENT_VERSION,
      updateRequired: !semverSatisfies(CURRENT_VERSION, request.payload?.minVersion)
    };
  }

  // NOSTR_LOCK - Passwort-Cache l????schen
  if (request.type === 'NOSTR_LOCK') {
    await clearUnlockCaches();
    return { locked: true };
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
        const setupResult = await promptPassword('create');
        if (!setupResult) throw new Error('Password setup canceled');
        const password = extractPasswordFromDialogResult(setupResult);
        if (!password) throw new Error('Password required');
        await keyManager.storeKey(secretKey, password);
        await clearUnlockCaches();
        await cachePasswordWithPolicy(password);
      } else if (newMode === KeyManager.MODE_PASSKEY) {
        const setupResult = await promptPassword('create');
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

      return await configureProtectionAndStoreSecretKey(restoredSecret);
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
      const result = await configureProtectionAndStoreSecretKey(secretKey);
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
      const result = await configureProtectionAndStoreSecretKey(importedSecret);
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

  if (request.type === 'NOSTR_UPSERT_DOMAIN_SYNC_CONFIG') {
    if (!isInternalExtensionRequest) {
      throw new Error('Manual domain config is only allowed from extension UI');
    }
    const { primaryDomain, domainSecret, authBroker } = request.payload || {};
    if (!primaryDomain || !domainSecret) {
      throw new Error('Primary domain and secret are required');
    }
    await upsertDomainSyncConfig(primaryDomain, domainSecret, authBroker);
    await updateDomainWhitelist();
    return await getDomainSyncState();
  }

  if (request.type === 'NOSTR_GET_DOMAIN_SYNC_STATE') {
    return await getDomainSyncState();
  }

  if (request.type === 'NOSTR_SYNC_DOMAINS_NOW') {
    await updateDomainWhitelist();
    return await getDomainSyncState();
  }

  if (request.type === 'NOSTR_REMOVE_DOMAIN_SYNC_CONFIG') {
    const normalizedHost = normalizeDomainEntry(request.payload?.host);
    if (!normalizedHost) {
      throw new Error('Invalid domain sync host');
    }

    const domainSyncConfigs = await getDomainSyncConfigs();
    const removedConfig = domainSyncConfigs[normalizedHost];
    if (!removedConfig) {
      return await getDomainSyncState();
    }

    delete domainSyncConfigs[normalizedHost];

    const { allowedDomains = [] } = await chrome.storage.local.get(['allowedDomains']);
    const keepDomains = new Set(Object.keys(domainSyncConfigs));
    for (const config of Object.values(domainSyncConfigs)) {
      for (const syncedDomain of normalizeDomainList(config.syncedDomains || [])) {
        keepDomains.add(syncedDomain);
      }
    }

    const removeDomains = new Set([normalizedHost]);
    for (const syncedDomain of normalizeDomainList(removedConfig.syncedDomains || [])) {
      if (!keepDomains.has(syncedDomain)) {
        removeDomains.add(syncedDomain);
      }
    }

    const prunedAllowedDomains = normalizeDomainList(allowedDomains)
      .filter((domainEntry) => !removeDomains.has(domainEntry));

    await chrome.storage.local.set({
      [DOMAIN_SYNC_CONFIGS_KEY]: domainSyncConfigs,
      allowedDomains: prunedAllowedDomains
    });

    await updateDomainWhitelist();
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
      if (!await keyManager.hasKey()) {
        if (!allowCreateIfMissing) {
          throw new Error('No local key found for this scope.');
        }

        // Check if user already has keys in other scopes.
        // If so, silently inherit protection mode instead of showing the full wizard.
        const existingPref = await getExistingProtectionPreference();

        if (existingPref.hasOtherScopes && existingPref.preferredProtection) {
          // Inherit protection from existing scope — no dialog needed for MODE_NONE
          const inheritedMode = existingPref.preferredProtection;

          if (inheritedMode === KeyManager.MODE_NONE) {
            // Silent key creation: same as nos2x "just approve" experience
            const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(null);
            await clearUnlockCaches();
            await openBackupDialog(npub, nsecBech32);
            return pubkey;
          }

          if (inheritedMode === KeyManager.MODE_PASSWORD) {
            // Ask for existing password (unlock), not a new one
            const srcKm = new KeyManager(existingPref.sourceScope);
            const password = await ensurePasswordIfNeeded(true);
            const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(password);
            await cachePasswordWithPolicy(password);
            await openBackupDialog(npub, nsecBech32);
            return pubkey;
          }

          if (inheritedMode === KeyManager.MODE_PASSKEY) {
            await ensurePasskeyIfNeeded(await getPasskeyAuthOptions());
            // For passkey mode we still need a credential id
            const srcCredKey = new KeyManager(existingPref.sourceScope)
              .keyName(KeyManager.PASSKEY_ID_KEY);
            const srcStorage = await chrome.storage.local.get([srcCredKey]);
            const existingCredentialId = String(srcStorage[srcCredKey] || '').trim();
            if (existingCredentialId) {
              const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(null, {
                mode: KeyManager.MODE_PASSKEY,
                passkeyCredentialId: existingCredentialId
              });
              await cachePasskeyAuthWithPolicy();
              await openBackupDialog(npub, nsecBech32);
              return pubkey;
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
  for (const scope of scopes) {
    try {
      const tmpKm = new KeyManager(scope);
      const mode = await tmpKm.getProtectionMode();
      if (mode) return { hasOtherScopes: true, preferredProtection: mode, sourceScope: scope };
    } catch {
      // skip broken scopes
    }
  }
  return { hasOtherScopes: true, preferredProtection: null };
}

async function promptPassword(mode, passkeyAuthOptions = null) {
  await chrome.storage.session.remove('passwordResult');
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
      return { width: 560, height: 760 };
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
  await chrome.windows.create({
    url: `dialog.html?type=backup&npub=${encodeURIComponent(npub)}&nsec=${encodeURIComponent(nsecBech32)}`,
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

function createDomainSyncConfig(primaryDomain, domainSecret, authBroker = null) {
  const normalizedPrimaryDomain = getPrimaryDomainBaseUrl(primaryDomain);
  const primaryHost = extractHostFromPrimaryDomain(normalizedPrimaryDomain);
  const normalizedSecret = String(domainSecret || '').trim();
  if (!normalizedPrimaryDomain || !primaryHost || !normalizedSecret) return null;
  const normalizedBroker = sanitizePasskeyAuthBroker(authBroker);

  return {
    primaryHost,
    config: {
      primaryDomain: normalizedPrimaryDomain,
      domainSecret: normalizedSecret,
      updatedAt: Date.now(),
      lastSyncAt: null,
      lastSyncBaseUrl: null,
      lastSyncError: null,
      syncedDomains: [],
      authBroker: normalizedBroker
    }
  };
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
  const storage = await chrome.storage.local.get([
    DOMAIN_SYNC_CONFIGS_KEY,
    LEGACY_PRIMARY_DOMAIN_KEY,
    LEGACY_DOMAIN_SECRET_KEY
  ]);

  let configs = normalizeDomainSyncConfigs(storage[DOMAIN_SYNC_CONFIGS_KEY]);

  if (!domainSyncMigrationDone) {
    const migrated = createDomainSyncConfig(
      storage[LEGACY_PRIMARY_DOMAIN_KEY],
      storage[LEGACY_DOMAIN_SECRET_KEY],
      null
    );

    if (migrated && !configs[migrated.primaryHost]) {
      configs[migrated.primaryHost] = migrated.config;
      await chrome.storage.local.set({ [DOMAIN_SYNC_CONFIGS_KEY]: configs });
    }

    domainSyncMigrationDone = true;
  }

  return configs;
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
    [DOMAIN_SYNC_CONFIGS_KEY]: domainSyncConfigs,
    // Legacy keys fuer Rueckwaertskompatibilitaet beibehalten
    [LEGACY_PRIMARY_DOMAIN_KEY]: normalizedPrimaryDomain,
    [LEGACY_DOMAIN_SECRET_KEY]: normalizedSecret
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
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'domainSync') updateDomainWhitelist();
});

