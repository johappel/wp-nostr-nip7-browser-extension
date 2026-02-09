(function () {
  'use strict';

function createNostrApi() {
  return {
    getPublicKey: async () => sendRequest('NOSTR_GET_PUBLIC_KEY'),

    signEvent: async (event) => sendRequest('NOSTR_SIGN_EVENT', event),

    getRelays: async () => sendRequest('NOSTR_GET_RELAYS'),

    nip04: {
      encrypt: async (pubkey, plaintext) =>
        sendRequest('NOSTR_NIP04_ENCRYPT', { pubkey, plaintext }),
      decrypt: async (pubkey, ciphertext) =>
        sendRequest('NOSTR_NIP04_DECRYPT', { pubkey, ciphertext })
    },

    nip44: {
      encrypt: async (pubkey, plaintext) =>
        sendRequest('NOSTR_NIP44_ENCRYPT', { pubkey, plaintext }),
      decrypt: async (pubkey, ciphertext) =>
        sendRequest('NOSTR_NIP44_DECRYPT', { pubkey, ciphertext })
    }
  };
}

const preferLock = readPreferLockFromScriptSrc();
const wpNostrApi = createNostrApi();
Object.defineProperty(wpNostrApi, '__wpNostrManaged', {
  value: true,
  configurable: false,
  enumerable: false,
  writable: false
});

installNostrApi(wpNostrApi, preferLock);
bootstrapDomainSyncConfig();

function readPreferLockFromScriptSrc() {
  const src = document.currentScript?.src;
  if (!src) return true;

  try {
    const lock = new URL(src).searchParams.get('lock');
    if (lock === null) return true;
    return lock !== '0' && lock.toLowerCase() !== 'false';
  } catch {
    return true;
  }
}

function installNostrApi(api, lockEnabled) {
  if (!lockEnabled) {
    try {
      window.nostr = api;
    } catch (err) {
      console.warn('[wp-nostr] Could not assign window.nostr while lock is disabled.', err);
    }
    return;
  }

  const existingDescriptor = Object.getOwnPropertyDescriptor(window, 'nostr');
  if (existingDescriptor && existingDescriptor.configurable === false) {
    const current = window.nostr;
    if (!current || !current.__wpNostrManaged) {
      console.warn('[wp-nostr] Another extension already locked window.nostr.');
    }
    return;
  }

  try {
    Object.defineProperty(window, 'nostr', {
      configurable: false,
      enumerable: true,
      get() {
        return api;
      },
      set(value) {
        if (value && value.__wpNostrManaged) return;
        console.warn('[wp-nostr] Ignored overwrite of window.nostr because lock is enabled.');
      }
    });
  } catch (err) {
    // Fallback if the property cannot be redefined in this page context.
    try {
      window.nostr = api;
    } catch {
      // ignore
    }
    console.warn('[wp-nostr] Could not enforce lock on this page.', err);
  }
}

function bootstrapDomainSyncConfig() {
  const config = window.nostrConfig;
  if (!config || typeof config !== 'object') return;

  const primaryDomain = String(config.primaryDomain || '').trim();
  const domainSecret = String(config.domainSecret || '').trim();
  if (!primaryDomain || !domainSecret) return;

  const authBrokerEnabled = config.authBrokerEnabled === true
    || config.authBrokerEnabled === 1
    || config.authBrokerEnabled === '1';
  const authBrokerUrl = String(config.authBrokerUrl || '').trim();
  const authBrokerOrigin = String(config.authBrokerOrigin || '').trim();
  const authBrokerRpId = String(config.authBrokerRpId || '').trim();

  sendRequest('NOSTR_SET_DOMAIN_CONFIG', {
    primaryDomain,
    domainSecret,
    authBroker: {
      enabled: authBrokerEnabled,
      url: authBrokerUrl,
      origin: authBrokerOrigin,
      rpId: authBrokerRpId
    }
  })
    .catch((err) => {
      // Normal auf Nicht-Primary-Domains; der Fehler soll den Seitenfluss nicht stoeren.
      console.debug('[wp-nostr] Domain config bootstrap skipped:', err?.message || err);
    });
}

function sendRequest(type, payload = null) {
  return new Promise((resolve, reject) => {
    const id = createRequestId();
    const handler = (e) => {
      const data = e?.data;
      if (!data || typeof data !== 'object') return;

      if (data.type === type + '_RESPONSE' && data._id === id) {
        window.removeEventListener('message', handler);
        if (data.error) reject(new Error(data.error));
        else resolve(data.result);
      }
    };
    window.addEventListener('message', handler);
    const message = { type, payload, _id: id };
    const signerScope = determineSignerScope();
    if (signerScope) {
      message.scope = signerScope;
    }
    const authBroker = readAuthBrokerFromConfig();
    if (authBroker) {
      message.authBroker = authBroker;
    }
    window.postMessage(message, '*');
  });
}

function readAuthBrokerFromConfig() {
  const config = window.nostrConfig;
  if (!config || typeof config !== 'object') return null;

  const enabled = config.authBrokerEnabled === true
    || config.authBrokerEnabled === 1
    || config.authBrokerEnabled === '1';
  const url = String(config.authBrokerUrl || '').trim();
  const origin = String(config.authBrokerOrigin || '').trim();
  const rpId = String(config.authBrokerRpId || '').trim();

  if (!enabled && !url) return null;
  if (!url) return null;
  return { enabled, url, origin, rpId };
}

function determineSignerScope() {
  const config = window.nostrConfig;
  if (!config || typeof config !== 'object') return null;

  const rawUserId = Number(config.wpUserId || config.userId || 0);
  if (!Number.isInteger(rawUserId) || rawUserId <= 0) return null;

  const host = String(window.location.host || '').trim().toLowerCase();
  if (!host) return null;

  return `wp:${host}:u:${rawUserId}`;
}

function createRequestId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  return `req-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

})();
