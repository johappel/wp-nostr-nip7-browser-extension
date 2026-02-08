const LOCK_SETTING_KEY = 'preferWpNostrLock';
const LOCK_DEFAULT = true;

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

  // Provide config in MAIN world before loading inpage.js.
  const configScript = document.createElement('script');
  configScript.textContent = `window.__WP_NOSTR_PREFER_LOCK__ = ${preferLock ? 'true' : 'false'};`;
  (document.head || document.documentElement).appendChild(configScript);
  configScript.remove();

  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('inpage.js');
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);
}

// Message bridge: webpage <-> background script
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data.type?.startsWith('NOSTR_')) return;

  try {
    const response = await chrome.runtime.sendMessage({
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
