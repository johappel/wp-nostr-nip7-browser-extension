# TASK-08: Popup UI

## Ziel
Extension Popup für Status-Anzeige und Einstellungen.

## Dateien

### popup.html

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="popup.css">
</head>
<body>
  <div id="popup">
    <header>
      <h1>⚡ Nostr Signer</h1>
      <span id="version" class="badge"></span>
    </header>
    
    <div id="status"></div>
    
    <div id="key-info" hidden>
      <label>Public Key:</label>
      <code id="pubkey-display"></code>
    </div>
    
    <div id="domains-section">
      <h3>Erlaubte Domains</h3>
      <ul id="domain-list"></ul>
      <button id="add-domain">Domain hinzufügen</button>
    </div>
    
    <footer>
      <button id="lock-btn">Sperren</button>
    </footer>
  </div>
  <script src="popup.js"></script>
</body>
</html>
```

### popup.js

```javascript
document.addEventListener('DOMContentLoaded', async () => {
  const manifest = chrome.runtime.getManifest();
  document.getElementById('version').textContent = `v${manifest.version}`;
  
  const { encrypted_nsec } = await chrome.storage.local.get('encrypted_nsec');
  document.getElementById('status').innerHTML = encrypted_nsec 
    ? '<p class="locked">🔒 Gesperrt</p>'
    : '<p class="no-key">Kein Schlüssel</p>';
  
  const response = await chrome.runtime.sendMessage({ type: 'NOSTR_GET_DOMAINS' });
  const domains = response.result || [];
  const domainList = document.getElementById('domain-list');
  domains.forEach(d => {
    const li = document.createElement('li');
    li.textContent = d;
    domainList.appendChild(li);
  });
  
  document.getElementById('lock-btn').onclick = () => {
    chrome.runtime.sendMessage({ type: 'NOSTR_LOCK' });
    window.close();
  };
});
```

## Akzeptanzkriterien

- [ ] Popup zeigt Key-Status
- [ ] Erlaubte Domains werden aufgelistet
- [ ] Lock-Button sperrt die Extension
