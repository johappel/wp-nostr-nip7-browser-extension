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
