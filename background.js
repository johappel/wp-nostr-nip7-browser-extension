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

// Global KeyManager Instance
const keyManager = new KeyManager();

// Passwort-Cache (nur f????r laufende Session, wird bei SW-Stop gel????scht)
let cachedPassword = null;
const DIALOG_TIMEOUT_MS = 25000;
let domainSyncMigrationDone = false;

function extractPasswordFromDialogResult(result) {
  if (!result) return null;
  if (typeof result === 'string') return result; // backward compatibility
  if (result.noPassword === true) return null;
  return typeof result.password === 'string' ? result.password : null;
}

async function ensurePasswordIfNeeded(passwordProtected) {
  if (!passwordProtected) return null;
  if (cachedPassword) return cachedPassword;

  const unlockResult = await promptPassword('unlock');
  const password = extractPasswordFromDialogResult(unlockResult);
  if (!password) throw new Error('Password required');

  cachedPassword = password;
  return cachedPassword;
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
    cachedPassword = null;
    return { locked: true };
  }

  // NOSTR_GET_STATUS - Status f????r Popup (ben????tigt keine Domain)
  if (request.type === 'NOSTR_GET_STATUS') {
    const hasKey = await keyManager.hasKey();
    const passwordProtected = hasKey ? await keyManager.isPasswordProtected() : false;
    let npub = null;
    
    // Wenn entsperrt, Npub berechnen und zur????ckgeben
    if (hasKey && (!passwordProtected || cachedPassword)) {
       try {
         const pubkey = await keyManager.getPublicKey(passwordProtected ? cachedPassword : null);
         npub = nip19.npubEncode(pubkey);
       } catch (e) {
         if (passwordProtected) cachedPassword = null;
       }
    }
    
    return {
      hasKey,
      locked: hasKey && passwordProtected && !cachedPassword,
      passwordProtected,
      npub,
      noPasswordMode: hasKey && !passwordProtected
    };
  }

  // NOSTR_SET_DOMAIN_CONFIG - Konfiguration f????r Domain-Sync setzen
  if (request.type === 'NOSTR_SET_DOMAIN_CONFIG') {
    const { primaryDomain, domainSecret } = request.payload || {};
    if (!primaryDomain || !domainSecret) {
      throw new Error('Invalid domain sync config');
    }
    // Domain-Config darf nur von der Primary Domain selbst gesetzt werden.
    const primaryHost = extractHostFromPrimaryDomain(primaryDomain);
    if (!domain || !primaryHost || domain.toLowerCase() !== primaryHost.toLowerCase()) {
      throw new Error('Domain config can only be set from primary domain');
    }
    const result = await upsertDomainSyncConfig(primaryDomain, domainSecret);
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
    const { primaryDomain, domainSecret } = request.payload || {};
    if (!primaryDomain || !domainSecret) {
      throw new Error('Primary domain and secret are required');
    }
    await upsertDomainSyncConfig(primaryDomain, domainSecret);
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
      if (!await keyManager.hasKey()) {
        const createResult = await promptPassword('create');
        if (!createResult) throw new Error('Password setup canceled');

        const useNoPassword = typeof createResult === 'object' && createResult.noPassword === true;
        const password = extractPasswordFromDialogResult(createResult);
        if (!useNoPassword && !password) throw new Error('Password required');

        cachedPassword = useNoPassword ? null : password;

        const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(
          useNoPassword ? null : password
        );
        await openBackupDialog(npub, nsecBech32);
        return pubkey;
      }
      const passwordProtected = await keyManager.isPasswordProtected();
      const password = await ensurePasswordIfNeeded(passwordProtected);
      const secretKey = await keyManager.getKey(passwordProtected ? password : null);
      if (!secretKey) throw new Error(passwordProtected ? 'Invalid password' : 'No key found');
      const pubkey = getPublicKey(secretKey);
      secretKey.fill(0);
      return pubkey;
    }

    case 'NOSTR_SIGN_EVENT': {
      const passwordProtected = await keyManager.isPasswordProtected();
      const password = await ensurePasswordIfNeeded(passwordProtected);
      const sensitiveKinds = [0, 3, 4];
      if (sensitiveKinds.includes(request.payload?.kind)) {
        const confirmed = await promptSignConfirmation(request.payload, domain);
        if (!confirmed) throw new Error('Signing rejected by user');
      }
      return await keyManager.signEvent(request.payload, passwordProtected ? password : null);
    }

    case 'NOSTR_GET_RELAYS': {
      const { relays = {} } = await chrome.storage.local.get('relays');
      return relays;
    }

    case 'NOSTR_NIP04_ENCRYPT':
    case 'NOSTR_NIP04_DECRYPT': {
      const passwordProtected = await keyManager.isPasswordProtected();
      const password = await ensurePasswordIfNeeded(passwordProtected);
      const secretKey = await keyManager.getKey(passwordProtected ? password : null);
      if (!secretKey) throw new Error(passwordProtected ? 'Invalid password' : 'No key found');
      try {
        const { pubkey, plaintext, ciphertext } = request.payload;
        if (request.type === 'NOSTR_NIP04_ENCRYPT') return await handleNIP04Encrypt(secretKey, pubkey, plaintext);
        else return await handleNIP04Decrypt(secretKey, pubkey, ciphertext);
      } finally { secretKey.fill(0); }
    }

    case 'NOSTR_NIP44_ENCRYPT':
    case 'NOSTR_NIP44_DECRYPT': {
      const passwordProtected = await keyManager.isPasswordProtected();
      const password = await ensurePasswordIfNeeded(passwordProtected);
      const secretKey = await keyManager.getKey(passwordProtected ? password : null);
      if (!secretKey) throw new Error(passwordProtected ? 'Invalid password' : 'No key found');
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

async function promptPassword(mode) {
  await chrome.storage.session.remove('passwordResult');
  return new Promise((resolve) => {
    let timeoutId = null;

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
    }, DIALOG_TIMEOUT_MS);

    chrome.windows.create({
      url: `dialog.html?type=password&mode=${mode}`,
      type: 'popup', width: 400, height: 350, focused: true
    });
  });
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

  return {
    primaryDomain,
    domainSecret,
    updatedAt: Number(value.updatedAt) || null,
    lastSyncAt: Number(value.lastSyncAt) || null,
    lastSyncBaseUrl: typeof value.lastSyncBaseUrl === 'string' ? value.lastSyncBaseUrl : null,
    lastSyncError: typeof value.lastSyncError === 'string' ? value.lastSyncError : null,
    syncedDomains: normalizeDomainList(value.syncedDomains || [])
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

function createDomainSyncConfig(primaryDomain, domainSecret) {
  const normalizedPrimaryDomain = getPrimaryDomainBaseUrl(primaryDomain);
  const primaryHost = extractHostFromPrimaryDomain(normalizedPrimaryDomain);
  const normalizedSecret = String(domainSecret || '').trim();
  if (!normalizedPrimaryDomain || !primaryHost || !normalizedSecret) return null;

  return {
    primaryHost,
    config: {
      primaryDomain: normalizedPrimaryDomain,
      domainSecret: normalizedSecret,
      updatedAt: Date.now(),
      lastSyncAt: null,
      lastSyncBaseUrl: null,
      lastSyncError: null,
      syncedDomains: []
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
      syncedDomains: normalizeDomainList(config.syncedDomains || [])
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
      storage[LEGACY_DOMAIN_SECRET_KEY]
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

async function upsertDomainSyncConfig(primaryDomain, domainSecret) {
  const normalizedPrimaryDomain = getPrimaryDomainBaseUrl(primaryDomain);
  const primaryHost = extractHostFromPrimaryDomain(normalizedPrimaryDomain);
  const normalizedSecret = String(domainSecret || '').trim();

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
    syncedDomains: domainSyncConfigs[primaryHost]?.syncedDomains || []
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

