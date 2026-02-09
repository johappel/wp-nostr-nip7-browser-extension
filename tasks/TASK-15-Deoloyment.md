# TASK-15: Deployment (Release, Stores, WordPress Rollout)

## Ziel
Ein standardisierter, reproduzierbarer Deployment-Prozess fuer:
1. Browser-Extension (Chrome + Firefox),
2. WordPress-Plugin,
3. gemeinsame Versionierung und Rollback.

## Abhaengigkeiten
- **TASK-07: Build Pipeline & Browser-Kompatibilitaet**
- **TASK-09: Unit Tests**
- **TASK-14: E2E Test-Automatisierung**

## Ergebnis
Nach Abschluss dieses Tasks:
- Es gibt einen klaren Release-Runbook fuer Dev, Staging und Produktion.
- Deployment ist fuer Chrome Web Store, Firefox Add-ons und WordPress reproduzierbar dokumentiert.
- Rollback kann ohne Datenverlust fuer User-Keys und Backup-Metadaten durchgefuehrt werden.

---

## Scope
1. Release-Prozess definieren (Versionierung, Build, Signierung, Auslieferung).
2. Store-Deployment fuer Chrome und Firefox dokumentieren.
3. WordPress-Plugin-Rollout inkl. DB/Option-Kompatibilitaet absichern.
4. Post-Deployment-Pruefungen und Monitoring festlegen.
5. Rollback-Prozeduren fuer Extension und Plugin bereitstellen.

## Nicht-Ziele
1. Vollautomatisierte Store-Submissions ohne manuelle Freigabe.
2. Austausch des bestehenden Build-Stacks.
3. Migration historischer, nicht kompatibler Alt-Daten jenseits definierter Migrationsroutinen.

## Release-Strategie
1. Semver verwenden: `MAJOR.MINOR.PATCH`.
2. Ein Release-Tag entspricht genau einer ausgelieferten Version.
3. Extension- und Plugin-Versionen werden abgestimmt (Kompatibilitaetsmatrix pflegen).
4. Sicherheitsfixes als priorisierte Patch-Releases.

## Zu erstellende/anzupassende Dateien
1. `docs/deployment/RELEASE-RUNBOOK.md`
   - End-to-end Ablauf fuer Vorbereitung, Freigabe, Rollout, Rollback.
2. `docs/deployment/COMPATIBILITY-MATRIX.md`
   - Mapping: Extension-Version <-> Plugin-Version <-> minimale API-Version.
3. `docs/deployment/STORE-CHECKLIST.md`
   - Chrome Web Store und Firefox Add-ons Checkliste.
4. `docs/deployment/ROLLBACK.md`
   - Schrittfolge fuer kontrollierten Rueckbau.
5. `README.md`
   - Kurzfassung des Deployments und Verweise auf Runbook.
6. `package.json`
   - Optionale Scripts fuer Release-Helfer:
   - `release:verify`, `release:package`, `release:notes`.

## Deployment-Pipeline (Soll)
1. **Pre-Release Validation**
   - `npm ci`
   - `npm test`
   - `npm run build`
   - `npm run test:e2e`
2. **Artefakte erzeugen**
   - Chrome Build: `dist/chrome`
   - Firefox Package: `npm run package:firefox`
   - Plugin ZIP mit eindeutigem Versionsnamen.
3. **Release Notes**
   - Aenderungen, Breaking Changes, Migrationshinweise, bekannte Risiken.
4. **Staging Rollout**
   - Test in Staging-WP + frischem Browser-Profil.
5. **Produktion**
   - Store-Upload (Chrome/Firefox) + Plugin-Deployment.
6. **Post-Deploy Checks**
   - Detection, Register, Signatur, Domain-Sync, Backup/Restore, Broker-Fallback.

## Store-spezifische Anforderungen
1. **Chrome Web Store**
   - Privacy- und Permissions-Formulare aktuell halten.
   - Aenderungen an `host_permissions` explizit pruefen.
2. **Firefox Add-ons**
   - Signiertes XPI bereitstellen.
   - MV3-Kompatibilitaet und bekannte Unterschiede dokumentieren.
3. **Beide Stores**
   - Screenshots/Descriptions pro Release aktualisieren, falls UI-Flow geaendert wurde.

## WordPress-Deployment
1. Plugin vor Rollout in Staging aktiv pruefen.
2. REST-Endpunkte auf Verfuegbarkeit und Nonce-Verhalten testen.
3. Option-/Meta-Migrationen idempotent halten.
4. Keine Aenderung darf vorhandene User-Pubkeys still ueberschreiben.
5. Backup-Daten bleiben auch bei Plugin-Update intakt.

## Sicherheits- und Compliance-Checks
1. Keine Klartext-Ausgabe von `nsec` in Logs oder API-Responses.
2. CSP/Nonce/Origin-Regeln fuer relevante Flows validieren.
3. Domain-Whitelist-Signaturen auf Staging und Produktion pruefen.
4. Mindestversion-Mechanismus (`NOSTR_CHECK_VERSION`) fuer kritische Fixes testen.

## Rollback-Strategie
1. **Extension Rollback**
   - Vorversion aus Store-Release-Historie bereitstellen.
   - Kompatibilitaetscheck gegen aktives Plugin erzwingen.
2. **Plugin Rollback**
   - Vorversion aus Release-Artefakt installieren.
   - DB-Schema/Migrationsstatus verifizieren.
3. **Kommunikation**
   - Incident-Notiz mit Ursache, Impact, Workaround und ETA.

## Akzeptanzkriterien
1. Ein neuer Release kann anhand des Runbooks ohne implizites Wissen ausgerollt werden.
2. Deployment in Chrome, Firefox und WordPress ist dokumentiert und praktisch testbar.
3. Rollback fuer Extension und Plugin ist getestet und dokumentiert.
4. Post-Deploy Smoke-Checks sind definiert und reproduzierbar.
5. Keine Regression in sicherheitskritischen Flows (Key-Handling, Domain-Sync, Backup/Restore).

## Test- und Abnahme-Checkliste
1. Build/Test/E2E erfolgreich in CI.
2. Manuelle Smoke-Tests auf Staging erfolgreich.
3. Store-Pakete und Plugin-ZIP entsprechen der geplanten Version.
4. Changelog/Release Notes veroeffentlicht.
5. Monitoring der ersten 24h nach Rollout ohne kritische Fehler.

## Definition of Done
1. Deployment-Dokumente sind versioniert und aktuell.
2. Release-Prozess ist fuer mindestens einen kompletten Durchlauf validiert.
3. Rollback wurde mindestens einmal in Staging durchgespielt.
4. Verantwortlichkeiten fuer Release-Freigabe und Incident-Reaktion sind festgelegt.
