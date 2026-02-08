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

// Passwort-Cache (nur für laufende Session, wird bei SW-Stop gelöscht)
let cachedPassword = null;

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

  // PING erfordert keine Domain-Validierung (für Extension-Detection)
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

  // NOSTR_LOCK - Passwort-Cache löschen
  if (request.type === 'NOSTR_LOCK') {
    cachedPassword = null;
    return { locked: true };
  }

  // NOSTR_GET_STATUS - Status für Popup (benötigt keine Domain)
  if (request.type === 'NOSTR_GET_STATUS') {
    const hasKey = await keyManager.hasKey();
    let npub = null;
    
    // Wenn entsperrt, Npub berechnen und zurückgeben
    if (hasKey && cachedPassword) {
       try {
         const pubkey = await keyManager.getPublicKey(cachedPassword);
         npub = nip19.npubEncode(pubkey);
       } catch (e) {
         // Falls Passwort falsch/veraltet im Cache
         cachedPassword = null;
       }
    }
    
    return {
      hasKey,
      locked: hasKey && !cachedPassword,
      npub
    };
  }

  // NOSTR_SET_DOMAIN_CONFIG - Konfiguration für Domain-Sync setzen
  if (request.type === 'NOSTR_SET_DOMAIN_CONFIG') {
    const { primaryDomain, domainSecret } = request.payload;
    await chrome.storage.local.set({ primaryDomain, domainSecret });
    // Sofortiges Update anstoßen
    updateDomainWhitelist();
    return { success: true };
  }

  // Domain-Validierung mit Bootstrapping
  const domainStatus = await checkDomainAccess(domain);
  if (domainStatus === DOMAIN_STATUS.BLOCKED) {
    throw new Error('Domain not authorized');
  }
  if (domainStatus === DOMAIN_STATUS.PENDING) {
    // User muss Domain erst bestätigen
    const allowed = await promptDomainApproval(domain);
    if (!allowed) throw new Error('Domain rejected by user');
  }

  switch (request.type) {
    case 'NOSTR_GET_PUBLIC_KEY': {
      if (!await keyManager.hasKey()) {
        cachedPassword = await promptPassword('create');
        if (!cachedPassword) throw new Error('Password required');
        const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(cachedPassword);
        await openBackupDialog(npub, nsecBech32);
        return pubkey;
      }
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
      }
      const secretKey = await keyManager.getKey(cachedPassword);
      if (!secretKey) throw new Error('Invalid password');
      const pubkey = getPublicKey(secretKey);
      secretKey.fill(0);
      return pubkey;
    }

    case 'NOSTR_SIGN_EVENT': {
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
      }
      const sensitiveKinds = [0, 3, 4];
      if (sensitiveKinds.includes(request.payload?.kind)) {
        const confirmed = await promptSignConfirmation(request.payload, domain);
        if (!confirmed) throw new Error('Signing rejected by user');
      }
      return await keyManager.signEvent(request.payload, cachedPassword);
    }

    case 'NOSTR_GET_RELAYS': {
      const { relays = {} } = await chrome.storage.local.get('relays');
      return relays;
    }

    case 'NOSTR_NIP04_ENCRYPT':
    case 'NOSTR_NIP04_DECRYPT': {
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
      }
      const secretKey = await keyManager.getKey(cachedPassword);
      if (!secretKey) throw new Error('Invalid password');
      try {
        const { pubkey, plaintext, ciphertext } = request.payload;
        if (request.type === 'NOSTR_NIP04_ENCRYPT') return await handleNIP04Encrypt(secretKey, pubkey, plaintext);
        else return await handleNIP04Decrypt(secretKey, pubkey, ciphertext);
      } finally { secretKey.fill(0); }
    }

    case 'NOSTR_NIP44_ENCRYPT':
    case 'NOSTR_NIP44_DECRYPT': {
      if (!cachedPassword) {
        cachedPassword = await promptPassword('unlock');
        if (!cachedPassword) throw new Error('Password required');
      }
      const secretKey = await keyManager.getKey(cachedPassword);
      if (!secretKey) throw new Error('Invalid password');
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

  // Wenn ein vollständiger Origin übergeben wurde, nutze ihn direkt.
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

    await chrome.storage.local.set({
      allowedDomains: data.domains,
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
