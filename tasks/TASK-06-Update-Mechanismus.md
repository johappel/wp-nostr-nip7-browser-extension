# TASK-06: Extension Update Mechanismus

## Ziel
Benachrichtigung über neue Versionen und forced updates bei Sicherheitskritischen Änderungen.

## Abhängigkeiten
- **TASK-02: WordPress Integration & Detection**

## WordPress Code

```javascript
async function checkExtensionVersion() {
  const minVersion = '1.0.0'; // Aus WordPress Option
  
  window.postMessage({ 
    type: 'NOSTR_CHECK_VERSION',
    minVersion: minVersion 
  }, '*');
  
  window.addEventListener('message', (e) => {
    if (e.data.type === 'NOSTR_VERSION_RESPONSE') {
      if (e.data.version !== minVersion) {
        showUpdatePrompt(e.data.version, minVersion);
      }
    }
  });
}
```

## Extension Code (in background.js)

```javascript
if (request.type === 'NOSTR_CHECK_VERSION') {
  return {
    version: CURRENT_VERSION,
    updateRequired: !semverSatisfies(CURRENT_VERSION, request.payload?.minVersion)
  };
}
```

## Akzeptanzkriterien

- [ ] WordPress kann minimale Extension-Version vorgeben
- [ ] User wird bei veralteter Extension benachrichtigt
