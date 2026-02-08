// Background Service Worker - Stub für TASK-01
// Wird in TASK-03 und TASK-04 erweitert

const CURRENT_VERSION = '1.0.0';

// Message Handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request, sender)
    .then(result => sendResponse({ result }))
    .catch(e => sendResponse({ error: e.message }));
  return true; // Async response
});

async function handleMessage(request, sender) {
  // PING erfordert keine Domain-Validierung (für Extension-Detection)
  if (request.type === 'NOSTR_PING') {
    return { pong: true, version: CURRENT_VERSION };
  }

  // NOSTR_CHECK_VERSION erfordert keine Domain-Validierung
  if (request.type === 'NOSTR_CHECK_VERSION') {
    return {
      version: CURRENT_VERSION,
      updateRequired: false // Stub - wird in TASK-06 implementiert
    };
  }

  // Alle anderen Methoden werden in TASK-03 implementiert
  throw new Error('Method not implemented yet: ' + request.type);
}