const LOCK_SETTING_KEY = 'preferWpNostrLock';
const LOCK_DEFAULT = true;

if (document.documentElement) {
  // Marker for pages that want to detect whether this extension bridge is active.
  document.documentElement.setAttribute('data-wp-nostr-extension-bridge', '1');
}

injectInpageScript();

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
    return { viewer: null, pending: true };
  }

  return {
    viewer: {
      isLoggedIn: snapshot.userId !== null,
      userId: snapshot.userId,
      displayName: snapshot.displayName,
      avatarUrl: snapshot.avatarUrl,
      pubkey: snapshot.pubkey
    },
    pending: false
  };
}

function readViewerFromDom() {
  const root = document.documentElement;
  const configReady = root?.getAttribute('data-wp-nostr-config-ready') === '1';
  const rawUserId = Number(root?.getAttribute('data-wp-nostr-user-id') || 0);
  const userId = Number.isInteger(rawUserId) && rawUserId > 0 ? rawUserId : null;
  const displayName = String(root?.getAttribute('data-wp-nostr-display-name') || '').trim() || null;
  const avatarUrl = String(root?.getAttribute('data-wp-nostr-avatar-url') || '').trim() || null;
  const pubkey = String(root?.getAttribute('data-wp-nostr-pubkey') || '').trim() || null;
  return { configReady, userId, displayName, avatarUrl, pubkey };
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
