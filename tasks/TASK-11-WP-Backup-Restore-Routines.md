# TASK-11: WP Backup Restore Routinen (Passkey-first)

## Ziel
Ein durchgaengiger, reproduzierbarer Wiederherstellungsflow fuer Nostr-Keys:
- Backup liegt usergebunden in WordPress.
- Restore erfolgt primaer ueber Passkey-Freigabe.
- Flow funktioniert fuer verschiedene Browser auf demselben Account.
- UX ist fuer Endnutzer klar und fehlertolerant.

## Scope
1. Dokumentation der kompletten Routinen (Upload, Status, Restore, Delete).
2. Implementierung eines lauffaehigen Flows in Popup + Background.
3. Kompatibilitaet mit bestehenden `/backup/*` Endpunkten.

## Nicht-Ziele
1. Serverseitige Kryptographie mit Klartext-Key.
2. Automatische Konto-Umschaltung ohne explizite Benutzeraktion.
3. Vollstaendige Migration alter externer Signer.

## Begriffe
1. `Scope`: Schluessel-Namespace (`global` oder `wp:<host>:u:<id>`).
2. `WP API Context`: `restUrl` + `nonce` des aktiven WP-Tabs.
3. `Backup Blob`: AES-GCM verschluesselter Private Key.
4. `wrappedDekPasskey`: verschluesselter DEK fuer passkey-gated Restore.

## Datenfluss (Soll)
1. Backup Status laden:
   - Popup -> Background (`NOSTR_BACKUP_STATUS`) -> WP `/backup/metadata`.
2. Backup erzeugen:
   - Popup -> Background (`NOSTR_BACKUP_ENABLE`) -> Key entsperren -> Passkey-Assertion ->
     DEK/Blob erzeugen -> WP `/backup/upload`.
3. Backup wiederherstellen:
   - Popup -> Background (`NOSTR_BACKUP_RESTORE`) -> WP `/backup/download` ->
     Passkey-Assertion -> Blob entschluesseln -> Key lokal importieren.
4. Backup loeschen:
   - Popup -> Background (`NOSTR_BACKUP_DELETE`) -> WP `/backup/delete`.

## Zustandstabelle (Popup)
1. Kein WP-Kontext:
   - Cloud-Backup Buttons deaktiviert.
   - Hinweis: nur auf eingeloggtem WP-Tab moeglich.
2. WP-Kontext vorhanden, kein Backup:
   - `Backup jetzt speichern` aktiv.
3. WP-Kontext vorhanden, Backup vorhanden:
   - `Aus WP-Backup wiederherstellen` und `Cloud-Backup loeschen` aktiv.
4. Laufende Operation:
   - Buttons temporaer deaktiviert + Statusmeldung.

## Sicherheit (Pragmatisch, v1)
1. Klartext-nsec wird nie zu WP gesendet.
2. Blob ist clientseitig AES-GCM verschluesselt.
3. Passkey ist Gate fuer Wrapping/Unwrapping des DEK.
4. Bei Entschluesselungsfehlern: kein stilles Partial-Restore.
5. Pubkey wird nach Restore gegen Backup-Metadaten geprueft.

## Fehlerbehandlung
1. `401/403`:
   - WP-Session abgelaufen -> User zu Reload/Login auffordern.
2. `404 backup_not_found`:
   - Kein Backup vorhanden.
3. `409 backup_pubkey_mismatch`:
   - Backup passt nicht zur erwarteten Identitaet.
4. Passkey-Fehler:
   - klare Meldung, kein Datenverlust.
5. Entschluesselungsfehler:
   - Hinweis auf falsche Passkey-Identitaet oder inkonsistentes Backup.

## API-Vertrag (bereits vorhanden)
1. `POST /wp-json/nostr/v1/backup/metadata`
2. `POST /wp-json/nostr/v1/backup/upload`
3. `POST /wp-json/nostr/v1/backup/download`
4. `POST /wp-json/nostr/v1/backup/delete`

## Implementierungsplan
1. **Context-Layer**:
   - Active Tab liefert `restUrl` + `nonce` + `userId`.
2. **Background-Handler**:
   - `NOSTR_BACKUP_STATUS`
   - `NOSTR_BACKUP_ENABLE`
   - `NOSTR_BACKUP_RESTORE`
   - `NOSTR_BACKUP_DELETE`
3. **Popup-UI**:
   - Cloud-Backup-Statusanzeige.
   - Buttons fuer Save/Restore/Delete.
4. **Dialog/Passkey**:
   - Assertion liefert verwendete Credential-ID zur Laufzeit.
5. **Tests**:
   - Crypto-/Flow-Tests fuer serialize/deserialize + Fehlerfaelle.

## Akzeptanzkriterien
1. User kann Backup-Status im Popup sehen.
2. User kann Backup fuer aktiven Scope in WP speichern.
3. User kann Backup aus WP laden und als lokalen Key aktivieren.
4. Flow scheitert mit klarer Meldung statt still.
5. Bestehende Key-Scope-Logik bleibt intakt.
