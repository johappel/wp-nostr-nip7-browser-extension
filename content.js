const LOCK_SETTING_KEY = 'preferWpNostrLock';
const LOCK_DEFAULT = true;
const VIEWER_CACHE_KEY = 'nostrViewerProfileCacheV1';

if (document.documentElement) {
  // Marker for pages that want to detect whether this extension bridge is active.
  document.documentElement.setAttribute('data-wp-nostr-extension-bridge', '1');
}

injectInpageScript();
primeViewerProfileCache();

async function injectInpageScript() {
  let preferLock = LOCK_DEFAULT;

  try {
    const result = await chrome.storage.local.get(LOCK_SETTING_KEY);
    if (typeof result[LOCK_SETTING_KEY] === 'boolean') {
      preferLock = result[LOCK_SETTING_KEY];
    }
  } catch {
    // Fallback to default
  }

  const script = document.createElement('script');
  script.src = `${chrome.runtime.getURL('inpage.js')}?lock=${preferLock ? '1' : '0'}`;
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);
}

// Message bridge: webpage <-> background script
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data.type?.startsWith('NOSTR_')) return;

  try {
    const response = await sendMessageWithRetry({
      type: event.data.type,
      payload: event.data.payload,
      authBroker: event.data.authBroker,
      _id: event.data._id,
      scope: typeof event.data.scope === 'string' ? event.data.scope : null,
      domain: window.location.hostname,
      origin: window.location.origin
    });

    window.postMessage({
      type: event.data.type + '_RESPONSE',
      _id: event.data._id,
      result: response?.result ?? null,
      error: response?.error ?? null
    }, '*');
  } catch (err) {
    window.postMessage({
      type: event.data.type + '_RESPONSE',
      _id: event.data._id,
      error: err.message || 'Extension communication failed'
    }, '*');
  }
});

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (!request || request.type !== 'NOSTR_GET_PAGE_CONTEXT') {
    return;
  }

  resolvePageViewerContext()
    .then((result) => sendResponse(result))
    .catch(() => sendResponse({ viewer: null, pending: true }));
  return true;
});

async function resolvePageViewerContext(maxWaitMs = 1600, stepMs = 80) {
  const start = Date.now();
  let snapshot = readViewerFromDom();

  while (!snapshot.configReady && (Date.now() - start) < maxWaitMs) {
    await new Promise((resolve) => setTimeout(resolve, stepMs));
    snapshot = readViewerFromDom();
  }

  if (!snapshot.configReady) {
    const viewerFromRest = await fetchViewerFromPageContext();
    const wpApi = readWpApiFromDom();
    const authBroker = readAuthBrokerFromDom();
    if (viewerFromRest) {
      return {
        viewer: viewerFromRest,
        pending: false,
        source: 'rest',
        wpApi,
        authBroker: authBroker || sanitizeAuthBroker(viewerFromRest?.authBroker)
      };
    }
    return { viewer: null, pending: true, wpApi, authBroker };
  }

  if (snapshot.userId === null) {
    // DOM marker says "logged out" - verify via same-origin fetch in tab context
    // to avoid false negatives in popup (especially Firefox/cookie edge cases).
    const viewerFromRest = await fetchViewerFromPageContext();
    if (viewerFromRest) {
      return {
        viewer: viewerFromRest,
        pending: false,
        source: 'rest',
        wpApi: snapshot.wpApi,
        authBroker: snapshot.authBroker || sanitizeAuthBroker(viewerFromRest?.authBroker)
      };
    }
  }

  return {
    viewer: {
      isLoggedIn: snapshot.userId !== null,
      userId: snapshot.userId,
      displayName: snapshot.displayName,
      avatarUrl: snapshot.avatarUrl,
      pubkey: snapshot.pubkey,
      userLogin: snapshot.userLogin,
      profileRelayUrl: snapshot.profileRelayUrl,
      profileNip05: snapshot.profileNip05,
      primaryDomain: snapshot.primaryDomain
    },
    pending: false,
    source: 'dom',
    wpApi: snapshot.wpApi,
    authBroker: snapshot.authBroker
  };
}

async function primeViewerProfileCache() {
  try {
    const start = Date.now();
    let snapshot = readViewerFromDom();
    while (!snapshot.configReady && (Date.now() - start) < 2200) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      snapshot = readViewerFromDom();
    }
    if (!snapshot.configReady) return;

    const origin = window.location.origin;
    const host = window.location.host.toLowerCase();
    const userId = Number(snapshot.userId) || null;
    const scope = userId && host ? `wp:${host}:u:${userId}` : 'global';
    const entry = {
      userId,
      displayName: snapshot.displayName || null,
      avatarUrl: snapshot.avatarUrl || null,
      pubkey: snapshot.pubkey || null,
      userLogin: snapshot.userLogin || null,
      profileRelayUrl: snapshot.profileRelayUrl || null,
      profileNip05: snapshot.profileNip05 || null,
      primaryDomain: snapshot.primaryDomain || null,
      origin,
      scope,
      updatedAt: Date.now()
    };

    const hasUsefulData =
      !!entry.primaryDomain ||
      !!entry.userId ||
      !!entry.displayName ||
      !!entry.userLogin ||
      !!entry.avatarUrl;
    if (!hasUsefulData) return;

    await chrome.storage.local.set({ [VIEWER_CACHE_KEY]: entry });
  } catch {
    // Optionaler Cache; Fehler sollen den Content-Flow nicht blockieren.
  }
}

function readViewerFromDom() {
  const root = document.documentElement;
  const configReady = root?.getAttribute('data-wp-nostr-config-ready') === '1';
  const rawUserId = Number(root?.getAttribute('data-wp-nostr-user-id') || 0);
  const userId = Number.isInteger(rawUserId) && rawUserId > 0 ? rawUserId : null;
  const displayName = String(root?.getAttribute('data-wp-nostr-display-name') || '').trim() || null;
  const avatarUrl = String(root?.getAttribute('data-wp-nostr-avatar-url') || '').trim() || null;
  const pubkey = String(root?.getAttribute('data-wp-nostr-pubkey') || '').trim() || null;
  const userLogin = String(root?.getAttribute('data-wp-nostr-user-login') || '').trim() || null;
  const profileRelayUrl = String(root?.getAttribute('data-wp-nostr-profile-relay-url') || '').trim() || null;
  const profileNip05 = String(root?.getAttribute('data-wp-nostr-profile-nip05') || '').trim() || null;
  const primaryDomain = String(root?.getAttribute('data-wp-nostr-primary-domain') || '').trim() || null;
  const wpApi = readWpApiFromDom();
  const authBroker = readAuthBrokerFromDom();
  return {
    configReady,
    userId,
    displayName,
    avatarUrl,
    pubkey,
    userLogin,
    profileRelayUrl,
    profileNip05,
    primaryDomain,
    wpApi,
    authBroker
  };
}

function readWpApiFromDom() {
  const root = document.documentElement;
  const restUrl = String(root?.getAttribute('data-wp-nostr-rest-url') || '').trim();
  const nonce = String(root?.getAttribute('data-wp-nostr-nonce') || '').trim();
  if (!restUrl || !nonce) return null;
  return { restUrl, nonce };
}

function readAuthBrokerFromDom() {
  const root = document.documentElement;
  const enabledAttr = String(root?.getAttribute('data-wp-nostr-auth-broker-enabled') || '').trim();
  const url = String(root?.getAttribute('data-wp-nostr-auth-broker-url') || '').trim();
  const origin = String(root?.getAttribute('data-wp-nostr-auth-broker-origin') || '').trim();
  const rpId = String(root?.getAttribute('data-wp-nostr-auth-broker-rp-id') || '').trim();
  const enabled = enabledAttr === '1' || enabledAttr.toLowerCase() === 'true';
  return sanitizeAuthBroker({ enabled, url, origin, rpId });
}

function sanitizeAuthBroker(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const enabled = raw.enabled === true || raw.enabled === 1 || raw.enabled === '1';
  const url = String(raw.url || raw.authBrokerUrl || '').trim();
  const origin = String(raw.origin || raw.authBrokerOrigin || '').trim();
  const rpId = String(raw.rpId || raw.authBrokerRpId || '').trim().toLowerCase();
  if (!enabled && !url) return null;
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (!/^https?:$/i.test(parsed.protocol)) return null;
    return {
      enabled,
      url: parsed.href,
      origin: origin || parsed.origin,
      rpId: rpId || parsed.hostname.toLowerCase()
    };
  } catch {
    return null;
  }
}

async function fetchViewerFromPageContext() {
  try {
    const response = await fetch('/wp-json/nostr/v1/viewer', {
      method: 'GET',
      credentials: 'include',
      cache: 'no-store'
    });
    if (!response.ok) return null;
    const data = await response.json();
    if (!data || typeof data !== 'object') return null;
    return {
      isLoggedIn: data.isLoggedIn === true,
      userId: Number(data.userId) || null,
      displayName: data.displayName || null,
      avatarUrl: data.avatarUrl || null,
      pubkey: data.pubkey || null,
      userLogin: data.userLogin || null,
      profileRelayUrl: data.profileRelayUrl || null,
      profileNip05: data.profileNip05 || null,
      primaryDomain: data.primaryDomain || null,
      authBroker: sanitizeAuthBroker({
        enabled: data.authBrokerEnabled,
        url: data.authBrokerUrl,
        origin: data.authBrokerOrigin,
        rpId: data.authBrokerRpId
      })
    };
  } catch {
    return null;
  }
}

async function sendMessageWithRetry(message) {
  try {
    return await chrome.runtime.sendMessage(message);
  } catch (err) {
    const text = String(err?.message || err || '');
    const shouldRetry =
      text.includes('message channel closed before a response was received') ||
      text.includes('Receiving end does not exist');

    if (!shouldRetry) throw err;

    await new Promise((resolve) => setTimeout(resolve, 120));
    return await chrome.runtime.sendMessage(message);
  }
}
