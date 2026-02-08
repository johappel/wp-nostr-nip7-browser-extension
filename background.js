// Background Service Worker
// Importiert nostr-tools via Rollup Bundle

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';
import { KeyManager } from './lib/key-manager.js';
import { checkDomainAccess, DOMAIN_STATUS, allowDomain, blockDomain, verifyWhitelistSignature } from './lib/domain-access.js';
import { semverSatisfies } from './lib/semver.js';
import { handleNIP04Encrypt, handleNIP04Decrypt, handleNIP44Encrypt, handleNIP44Decrypt } from './lib/crypto-handlers.js';

const CURRENT_VERSION = '1.0.0';

// Global KeyManager Instance
const keyManager = new KeyManager();

// Passwort-Cache (nur fÃ¼r laufende Session, wird bei SW-Stop gelÃ¶scht)
let cachedPassword = null;

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

  // PING erfordert keine Domain-Validierung (fÃ¼r Extension-Detection)
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

  // NOSTR_LOCK - Passwort-Cache lÃ¶schen
  if (request.type === 'NOSTR_LOCK') {
    cachedPassword = null;
    return { locked: true };
  }

  // NOSTR_GET_STATUS - Status fÃ¼r Popup (benÃ¶tigt keine Domain)
  if (request.type === 'NOSTR_GET_STATUS') {
    const hasKey = await keyManager.hasKey();
    const passwordProtected = hasKey ? await keyManager.isPasswordProtected() : false;
    let npub = null;
    
    // Wenn entsperrt, Npub berechnen und zurÃ¼ckgeben
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

  // NOSTR_SET_DOMAIN_CONFIG - Konfiguration fÃ¼r Domain-Sync setzen
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
    await chrome.storage.local.set({ primaryDomain, domainSecret });
    // Sofortiges Update ausf?hren
    await updateDomainWhitelist();
    const { allowedDomains = [] } = await chrome.storage.local.get('allowedDomains');
    return { success: true, allowedDomains };
  }

  // Domain-Validierung mit Bootstrapping
  const domainStatus = await checkDomainAccess(domain);
  if (domainStatus === DOMAIN_STATUS.BLOCKED) {
    throw new Error('Domain not authorized');
  }
  if (domainStatus === DOMAIN_STATUS.PENDING) {
    // User muss Domain erst bestÃ¤tigen
    const allowed = await promptDomainApproval(domain);
    if (!allowed) throw new Error('Domain rejected by user');
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
  return new Promise((resolve) => {
    chrome.windows.create({
      url: `dialog.html?type=password&mode=${mode}`,
      type: 'popup', width: 400, height: 350, focused: true
    });
    const listener = (changes) => {
      if (changes.passwordResult) {
        chrome.storage.onChanged.removeListener(listener);
        resolve(changes.passwordResult.newValue);
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
    type: 'popup', width: 500, height: 650, focused: true
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
// Domain Sync
// ============================================================
function getPrimaryDomainBaseUrl(primaryDomain) {
  const value = String(primaryDomain || '').trim();
  if (!value) return null;

  // Wenn ein vollstÃ¤ndiger Origin Ã¼bergeben wurde, nutze ihn direkt.
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      return `${url.protocol}//${url.host}`;
    } catch {
      return null;
    }
  }

  // Lokale Entwicklung ohne SSL (localhost/127.0.0.1) zulassen.
  const isLocalDev = /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(value);
  const protocol = isLocalDev ? 'http' : 'https';
  return `${protocol}://${value}`;
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

async function updateDomainWhitelist() {
  try {
    const { primaryDomain, domainSecret } = await chrome.storage.local.get(['primaryDomain', 'domainSecret']);
    if (!primaryDomain) return;
    const baseUrl = getPrimaryDomainBaseUrl(primaryDomain);
    if (!baseUrl) return;

    const response = await fetch(`${baseUrl}/wp-json/nostr/v1/domains`);
    const data = await response.json();

    // Signatur der Domain-Liste verifizieren (HMAC mit shared secret)
    if (!data.signature || !await verifyWhitelistSignature(data.domains, data.updated, data.signature, domainSecret)) {
      console.error('Domain list signature invalid');
      return;
    }
    const normalizedDomains = normalizeDomainList(data.domains);
    await chrome.storage.local.set({
      allowedDomains: normalizedDomains,
      lastDomainUpdate: Date.now()
    });
  } catch (e) {
    console.error('Failed to update domains:', e);
  }
}

// ============================================================
// Alarm: Periodisches Domain-Sync
// ============================================================
chrome.alarms.create('domainSync', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'domainSync') updateDomainWhitelist();
});

