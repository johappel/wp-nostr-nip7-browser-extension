// Injiziert inpage.js in MAIN world für window.nostr Zugriff
const script = document.createElement('script');
script.src = chrome.runtime.getURL('inpage.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);

// Message Bridge: Webseite <-> Background Script
// WICHTIG: _id muss durchgereicht werden für Request/Response-Korrelation
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