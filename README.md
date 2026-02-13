# WP Nostr NIP-07 Browser Extension

Eine Browser-Erweiterung für sicheres Identitätsmanagement mit Nostr, die nahtlos mit WordPress (und anderen Systemen) zusammenarbeitet.

## Was macht diese Integration?

Diese Lösung verbindet die Welt von **WordPress** (als vertrauenswürdige Heimatbasis) mit dem **Nostr-Netzwerk** (als offener Verteilungsraum).

1.  **Sicheres Login & Signieren:** Die Extension verwaltet kryptografische Schlüssel sicher im Browser (NIP-07), statt Passwörter an Server zu senden.
2.  **Automatische Konfiguration:** WordPress erkennt die Extension und richtet sie automatisch ein.
3.  **Vertrauens-Synchronisation:** WordPress sendet der Extension eine signierte Liste vertrauenswürdiger Webseiten (Whitelist), sodass der Nutzer nicht ständig Popups bestätigen muss.
4.  **Cloud-Recovery:** Verschlüsselte Backups der Schlüssel können in WordPress gespeichert werden, um sie bei Geräteverlust wiederherzustellen.

Weitere Details finden sich im Konzept und der API-Referenz.

## Message-API Iststand (Background)

Der interne Message-Vertrag zwischen Popup/Content und `background.js` wurde bereinigt.

- Aktiv für Chat/DM: `NOSTR_SEND_DM`, `NOSTR_GET_DMS`, `NOSTR_SUBSCRIBE_DMS`
- Aktiv für Kontakte: `NOSTR_GET_CONTACTS`, `NOSTR_REFRESH_CONTACTS`, `NOSTR_ADD_CONTACT`
- Entfernt als obsolet: u. a. `NOSTR_GET_DM_RELAYS`, `NOSTR_UNSUBSCRIBE_DMS`, `NOSTR_GET_UNREAD_COUNT`, `NOSTR_CLEAR_UNREAD`, `NOSTR_CLEAR_DM_CACHE`, `NOSTR_POLL_DMS`, `NOSTR_GET_WP_MEMBERS`, `NOSTR_REFRESH_WP_MEMBERS`, `NOSTR_CHECK_VERSION`, `NOSTR_LOCK`

Die Task-Dokumente `TASK-19` und `TASK-20` sind auf den aktuellen Iststand angepasst (historische Plan-Teile bleiben als Referenz erhalten).

## Roadmap (Task-Status)

- [x] TASK-00: Projekt-Uebersicht
- [x] TASK-01: Extension Grundgeruest
- [x] TASK-02: WordPress-Integration-Detection
- [x] TASK-03: Extension Key-Management-UI
- [x] TASK-04: NIP04-NIP44-Encryption
- [x] TASK-05: Domain-Whitelist
- [x] TASK-06: Update-Mechanismus
- [x] TASK-07: Build-Pipeline
- [x] TASK-08: Popup-UI
- [x] TASK-09: Unit-Tests
- [x] TASK-10: Passkey-WP-Backup-Recovery
- [x] TASK-11: WP-Backup-Restore-Routines
- [x] TASK-12: Primary-Domain-Auth-Broker
- [x] TASK-13: CSS-Design-UTF8-Dark-Light-Blue-Glow
- [ ] TASK-14: e2e-Test
- [ ] TASK-15: Deployment

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
npm run package:chrome
npm run package:firefox
```

Ergebnis:
- Extension-Builds liegen in `dist/chrome` und `dist/firefox`.
- Chrome-ZIP für CWS liegt in `dist/packages/` (z. B. `wp-nostr-signer-chrome-1.0.1.zip`).
- Firefox-XPI liegt in `dist/packages/` (z. B. `wp-nostr-signer-firefox-1.0.1.xpi`).
- Hinweis: Das lokale XPI ist unsigniert. In Firefox Release kann das als "Datei ist korrupt" erscheinen. Für dauerhafte Installation muss die XPI signiert werden (AMO / `web-ext sign`).

Firefox XPI signieren (AMO):

PowerShell:
```powershell
$env:WEB_EXT_API_KEY="DEIN_AMO_JWT_ISSUER"
$env:WEB_EXT_API_SECRET="DEIN_AMO_JWT_SECRET"
$env:FIREFOX_SIGN_CHANNEL="unlisted" # optional: unlisted|listed
npm run sign:firefox
```

bash:
```bash
export WEB_EXT_API_KEY="DEIN_AMO_JWT_ISSUER"
export WEB_EXT_API_SECRET="DEIN_AMO_JWT_SECRET"
export FIREFOX_SIGN_CHANNEL="unlisted" # optional: unlisted|listed
npm run sign:firefox
```

Hinweis:
- `sign:firefox` baut zuerst neu (`dist/firefox`) und startet dann `web-ext sign`.
- Wenn `web-ext` lokal nicht installiert ist, wird automatisch `npx web-ext` verwendet.

Chrome Release (CWS):

```bash
npm run release:chrome
```

Hinweis:
- `release:chrome` erzeugt zuerst das Upload-ZIP und zeigt danach eine kurze CWS-Checkliste.
- Lokale `.crx`-Installation per Drag-and-drop ist auf Chrome (Windows/macOS) für normale Nutzer blockiert.
- Vor CWS-Upload in `manifest.chrome.json` die Host-Liste anpassen:
  - `https://example.com/*`
  - `https://*.example.com/*`
  durch eure echten Produktionsdomains ersetzen.

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

7. Eine andere NIP-07 Extension (z. B. nos2x) ueberschreibt window.nostr.
- Oeffne das Popup der WP Nostr Extension und aktiviere Prefer WP Nostr Lock.
- Lade den Tab neu, damit die Inpage-API mit Lock neu injiziert wird.
- Wenn du bewusst die andere Extension bevorzugen willst, deaktiviere den Lock wieder.

8. Firefox zeigt die Extension-Sidebar links statt rechts.
- Die Position der Firefox-Sidebar ist eine Browser-Einstellung und kann nicht von der Extension erzwungen werden.
- In Firefox in der Sidebar auf Einstellungen gehen und "Move Sidebar to Right" waehlen.

9. Firefox meldet beim Installieren von `dist/packages/*.xpi` "Datei ist korrupt".
- Das ist bei unsignierten XPIs in Firefox Release ein typisches Symptom.
- Für lokale Tests `about:debugging#/runtime/this-firefox` und `Load Temporary Add-on` mit `dist/firefox/manifest.json` nutzen.
- Für Verteilung oder dauerhafte Installation die Erweiterung signieren (AMO / `web-ext sign`).
