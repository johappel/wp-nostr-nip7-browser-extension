# WP Nostr NIP-07 Browser Extension

NIP-07 Signer Extension mit WordPress-Integration (Chrome/Firefox, Manifest V3).

## Lokales E2E-Testing (ohne SSL)

### 1. Voraussetzungen

1. Node.js 18+.
2. Lokale WordPress-Instanz (z. B. `http://localhost:8080`).
3. Ein Browser-Profil für Extension-Tests (Chrome oder Firefox).

### 2. Projekt bauen und Tests ausführen

```bash
npm install
npm test
npm run build
```

Ergebnis:
- Extension-Builds liegen in `dist/chrome` und `dist/firefox`.

### 3. WordPress-Plugin lokal installieren

1. Lege einen Plugin-Ordner an, z. B. `wp-content/plugins/nostr-integration/`.
2. Kopiere folgende Dateien in diesen Ordner:
- `wp-nostr-integration.php`
- `nostr-integration.js`
- `nostr-integration.css`
3. Plugin im WordPress-Admin aktivieren.
4. Als eingeloggter User die Frontend-Seite öffnen.

### 4. Extension laden

Chrome:
1. `chrome://extensions` öffnen.
2. Developer Mode aktivieren.
3. `Load unpacked` und `dist/chrome` wählen.

Firefox:
1. `about:debugging#/runtime/this-firefox` öffnen.
2. `Load Temporary Add-on`.
3. `dist/firefox/manifest.json` wählen.

### 5. Funktional testen

1. WordPress-Seite als eingeloggter User öffnen.
2. Registrierung starten (`Mit Nostr verknüpfen`).
3. Passwort-Dialog und Backup-Dialog durchlaufen.
4. Prüfen, dass der Pubkey in WordPress gespeichert wurde.

### 6. Optional: Domain-Sync lokal prüfen

Im Browser auf der WordPress-Seite in der Konsole ausführen:

```js
window.postMessage({
  type: 'NOSTR_SET_DOMAIN_CONFIG',
  _id: crypto.randomUUID(),
  payload: {
    primaryDomain: window.location.origin, // z. B. http://localhost:8080
    domainSecret: 'DEIN_SECRET_AUS_WP_ADMIN'
  }
}, '*');
```

Hinweis:
- Lokales `http://` ist unterstützt.
- Für normale Domains bleibt `https://` der Standard.

### 7. Troubleshooting

1. Extension wird auf der WordPress-Seite nicht erkannt.
- Prüfe in der Browser-Konsole, ob `window.nostr` existiert.
- Prüfe in der Extension-Seite (`chrome://extensions` oder `about:debugging`) ob der Service Worker läuft.
- Seite nach dem Laden der Extension einmal hart neu laden.

2. Service Worker startet nicht.
- In den Extension-Details auf Fehler klicken und die erste Fehlermeldung lesen.
- Prüfe, ob du wirklich `dist/chrome` oder `dist/firefox` geladen hast.
- Nach Code-Änderungen immer neu bauen: `npm run build`, dann Extension neu laden.

3. Registrierung schlägt mit `403` oder REST-Fehler fehl.
- Als User im gleichen Browser in WordPress eingeloggt sein.
- Prüfe, ob `X-WP-Nonce` gesendet wird (Network Tab bei `/wp-json/nostr/v1/register`).
- Prüfe, ob das Plugin aktiv ist.

4. Domain-Sync meldet `Domain list signature invalid`.
- `domainSecret` muss exakt dem Secret aus den Plugin-Einstellungen entsprechen.
- `primaryDomain` muss auf die richtige Instanz zeigen (z. B. `http://localhost:8080`).
- Prüfe den Response von `/wp-json/nostr/v1/domains` auf `domains`, `updated`, `signature`.

5. Zugriff auf lokale HTTP-Domain funktioniert nicht.
- Extension neu laden, damit aktualisierte `host_permissions` aktiv sind.
- Keine alte Build-Ausgabe verwenden; erst `npm run build`, dann `dist/...` neu laden.

6. UI/JS des WordPress-Plugins wird nicht geladen.
- Prüfe im Frontend-Quelltext, ob `nostr-integration.js` und `nostr-integration.css` eingebunden sind.
- Prüfe den Plugin-Ordnerinhalt: `wp-nostr-integration.php`, `nostr-integration.js`, `nostr-integration.css`.
