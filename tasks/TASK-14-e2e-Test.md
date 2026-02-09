# TASK-14: E2E Test-Automatisierung (Extension + WordPress)

## Ziel
Automatisierte End-to-End-Tests fuer die kritischen User-Flows zwischen Browser-Extension und WordPress-Integration:
1. Extension Detection und `window.nostr` Verfuegbarkeit.
2. Key-Setup und Basis-NIP-07 Requests.
3. Domain-Whitelist / Primary-Domain-Sync.
4. Cloud-Backup Save/Restore (happy path + Fehlerfaelle).
5. Auth-Broker Flow (falls aktiviert) mit sauberem Fallback.

## Abhaengigkeiten
- **TASK-01: Extension Grundgeruest**
- **TASK-02: WordPress-Integration-Detection**
- **TASK-03: Extension Key-Management & UI**
- **TASK-09: Unit Tests**
- **TASK-10: Passkey + WP Backup Recovery**
- **TASK-11: WP Backup Restore Routinen**
- **TASK-12: Primary-Domain Auth Broker**
- **TASK-13: CSS-/Design-System** (nur visuelle Smoke-Checks)

## Ergebnis
Nach Abschluss dieses Tasks:
- `npm run test:e2e` fuehrt E2E-Tests reproduzierbar lokal aus.
- Kritische Flows sind in Chromium und Firefox abgedeckt.
- Fehlerzustaende liefern stabile Assertions (kein "flaky" Blindklick-Test).
- E2E-Reporting zeigt Screenshots/Traces bei Fehlschlaegen.

---

## Scope
1. Test-Harness fuer Browser-Extension + WordPress-Testinstanz.
2. Deterministische Testdaten (Test-User, Test-Domain, Test-Nonce).
3. E2E-Szenarien fuer:
   - Detect/Register,
   - Sign/Encrypt/Decrypt,
   - Domain-Config Sync,
   - Backup Upload/Metadata/Download/Delete,
   - Broker Assertion inkl. Fallback.
4. CI-faehige Ausfuehrung im Headless-Modus.

## Nicht-Ziele
1. Last-/Performance-Tests auf Produktionsniveau.
2. Vollstaendige Pixel-Regression fuer jedes UI-Element.
3. Ersatz von Unit-Tests durch E2E-Tests.

## Test-Stack (Vorschlag)
1. **Playwright** als E2E-Runner.
2. Extension-Loading via Persistent Context:
   - Chromium mit `--disable-extensions-except` / `--load-extension`.
   - Firefox mit temporaerem Add-on-Load (Playwright Firefox-Context).
3. WP-Testumgebung lokal (z. B. Docker-Compose oder vorhandene lokale Instanz) mit seedbaren Testdaten.
4. Traces/Screenshots/Videos nur bei Fehlern.

## Zu erstellende/anzupassende Dateien
1. `playwright.config.js`
   - Projekte fuer `chromium` und `firefox`.
   - BaseURL fuer lokale WP-Testinstanz.
2. `e2e/setup/global-setup.js`
   - Testdaten vorbereiten (User/Login/Fixtures).
   - ggf. API-seitiges Reset der Testdaten.
3. `e2e/fixtures/extension.js`
   - Laden der gebauten Extension aus `dist/chrome` bzw. `dist/firefox`.
4. `e2e/specs/detection-register.spec.js`
5. `e2e/specs/nip07-ops.spec.js`
6. `e2e/specs/domain-sync.spec.js`
7. `e2e/specs/backup-restore.spec.js`
8. `e2e/specs/auth-broker.spec.js`
9. `package.json`
   - Scripts: `test:e2e`, `test:e2e:headed`, `test:e2e:debug`.
10. `README.md`
   - Sektion fuer E2E-Ausfuehrung, Voraussetzungen und Troubleshooting.

## Mindest-Testfaelle
1. **Detection**
   - WP-Frontend erkennt installierte Extension.
   - `window.nostr` ist vorhanden und antwortet auf `NOSTR_PING`.
2. **Register Flow**
   - User kann Pubkey registrieren.
   - Doppelte Registrierung verursacht keinen stillen Inkonsistenzzustand.
3. **NIP-07 Basisfunktionen**
   - `getPublicKey` liefert valides Hex-Format.
   - `signEvent` liefert Signatur mit korrekter Event-ID.
4. **Encryption Flow**
   - NIP-04/NIP-44 Encrypt/Decrypt Roundtrip funktioniert.
5. **Domain Sync**
   - Signierte Domain-Liste wird akzeptiert.
   - Ungueltige Signatur wird abgelehnt.
6. **Backup Flow**
   - Upload -> Metadata -> Download -> Restore funktioniert mit passendem Scope.
   - `backup_not_found` und `backup_pubkey_mismatch` werden klar behandelt.
7. **Auth Broker**
   - Aktivierter Broker wird genutzt.
   - Bei Broker-Fehler greift lokaler Passkey-Fallback.

## Stabilitaetsregeln gegen Flakiness
1. Keine Sleep-basierten Waits, nur explizite Conditions (`expect`, network-idle, UI-state).
2. Isolierte Testdaten pro Spec (eigener User/Scope oder sauberer Reset).
3. Jeder Test ist einzeln wiederholbar und unabhaengig.
4. Harte Assertions auf API-Responses und sichtbare Statusmeldungen.

## Akzeptanzkriterien
1. `npm run build` und danach `npm run test:e2e` laufen lokal erfolgreich.
2. Mindestens ein kompletter Happy Path pro Kernfeature ist automatisiert.
3. Mindestens ein Negativfall pro sicherheitskritischem Feature ist automatisiert.
4. Fehlgeschlagene Tests erzeugen verwertbare Artefakte (Trace/Screenshot/Logs).
5. Tests sind in Chromium und Firefox lauffaehig (bekannte Abweichungen dokumentiert).

## Implementierungsplan
1. Playwright und E2E-Ordnerstruktur einfuehren.
2. Extension-Start und WP-Test-Setup robust machen.
3. Detection/Register Spezifikation umsetzen.
4. NIP-07 + Domain-Sync Spezifikationen umsetzen.
5. Backup/Restore + Broker Spezifikationen umsetzen.
6. Flaky-Stellen stabilisieren und Reporting aktivieren.
7. README/CI-Dokumentation finalisieren.

## Definition of Done
1. E2E-Suite ist versioniert und lokal reproduzierbar.
2. Kritische Flows sind automatisiert und stabil.
3. Dokumentation fuer Entwickler ist vollstaendig.
4. Offene Risiken (falls vorhanden) sind explizit im Task dokumentiert.
