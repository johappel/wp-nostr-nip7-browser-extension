# TASK-10: Passkey + WP Backup Recovery

## Ziel
Ein nutzerfreundlicher Recovery-Flow ohne merkpflichtige Passphrase:
- Key-Backup wird in WordPress gespeichert.
- Entsperrung fuer Restore erfolgt per Passkey (WebAuthn) und optional Recovery-Code.
- Entsperrung der Extension selbst folgt ebenfalls "passkey-first" mit Fallback.
- Unlocked-Session-Cache ist durch den User konfigurierbar (inkl. bis Session-Ende).
- Kein Klartext-nsec auf dem Server.

## Abhaengigkeiten
- **TASK-02: WordPress Integration & Detection** (REST, Nonce, User-Kontext)
- **TASK-03: Extension Key-Management & UI** (KeyManager, nsec-Handling)
- **TASK-08: Popup UI** (Export/Import-Flaechen)
- **TASK-09: Unit Tests** (Tests erweitern)

## Ergebnis
Nach Abschluss dieses Tasks:
- User kann "Cloud-Backup aktivieren" im Popup.
- Ein verschluesseltes Backup wird im WP-Account gespeichert.
- Wiederherstellung per Passkey funktioniert, wenn dieselbe Passkey-Credential verfuegbar ist.
- Optionaler Recovery-Code funktioniert als Fallback.
- Unlock-Cache ist einstellbar: `off`, `5m`, `15m`, `30m`, `60m`, `session`.
- Bestehender `nostr_pubkey` wird nicht still ueberschrieben (bereits umgesetzt).

---

## UX-Prinzipien

1. Kein Pflichtfeld "Passphrase merken".
2. Standardpfad: Biometrie/PIN ueber Passkey.
3. Fallbackpfad: einmalig angezeigter Recovery-Code.
4. Klare Warnung bei Key-Wechsel (anderer Pubkey).
5. Unlock-Cache ist transparent und vom User steuerbar.

---

## Sicherheitsmodell

1. Extension verschluesselt nsec clientseitig mit zufaelligem Data Key (`DEK`, AES-256-GCM).
2. Backup-Blob (ciphertext + iv + aad + version) wird an WP uebertragen.
3. `DEK` wird nicht im Klartext gespeichert:
   - Primaer: WebAuthn PRF/hmac-secret abgeleiteter Key wraps `DEK`.
   - Fallback: Recovery-Code (hoch entropisch) wraps `DEK`.
4. WP speichert nur:
   - `backup_blob`
   - `wrapped_dek_passkey`
   - `wrapped_dek_recovery` (optional)
   - Metadaten (created_at, updated_at, key_fingerprint).
5. Optional: serverseitiges Wrapping zusaetzlich mit WP Secret (Defense in depth, nicht als Hauptschutz).

---

## Zu erstellende/anzupassende Dateien

### 1. `wp-nostr-integration.php`
- Neue REST-Endpunkte:
  - `POST /nostr/v1/backup/upload`
  - `POST /nostr/v1/backup/metadata`
  - `POST /nostr/v1/backup/download`
  - `POST /nostr/v1/backup/delete`
- Zugriff nur fuer eingeloggten User auf eigenes Backup.
- Rate-Limits fuer Download/Restore.

### 2. `background.js`
- Neue Message-Types:
  - `NOSTR_BACKUP_ENABLE`
  - `NOSTR_BACKUP_STATUS`
  - `NOSTR_BACKUP_RESTORE`
  - `NOSTR_BACKUP_DELETE`
  - `NOSTR_SET_UNLOCK_CACHE_POLICY`
- Orchestrierung Backup/Restore.
- Verwaltung des passwortbasierten Unlock-Caches (inkl. Session-Option).

### 3. `lib/key-manager.js`
- Methoden:
  - `exportEncryptedBackup()`
  - `importEncryptedBackup()`
  - `replaceKeyWithConfirmation()`
- Validierung: importierter Key ergibt erwarteten Pubkey.

### 4. `popup.html`, `popup.js`, `popup.css`
- UI:
  - "Cloud-Backup aktivieren"
  - "Aus WP wiederherstellen"
  - "Backup loeschen"
  - "Recovery-Code anzeigen/herunterladen" (nur einmal bei Setup)
  - "Unlock Cache" Policy-Auswahl (`off`, `5m`, `15m`, `30m`, `60m`, `session`)

### 5. `tasks/*.test.js`
- Tests fuer Backup-Blob-Format, Key-Wrapping, Restore-Checks, API-Fehlerfaelle.

---

## API-Datenmodell (V1)

### Upload Request
```json
{
  "version": 1,
  "pubkey": "hex64",
  "backupBlob": "base64",
  "blobIv": "base64",
  "blobAad": "base64",
  "wrappedDekPasskey": "base64",
  "wrappedDekRecovery": "base64-or-null",
  "keyFingerprint": "sha256-base64"
}
```

### Metadata Response
```json
{
  "hasBackup": true,
  "version": 1,
  "pubkey": "hex64",
  "updatedAt": 1739000000,
  "hasRecoveryWrap": true
}
```

---

## Ablauf

### A) Backup aktivieren
1. User klickt "Cloud-Backup aktivieren".
2. Extension erzeugt Backup-Blob + wrapped DEK.
3. WP speichert Blob im User-Meta.
4. UI bestaetigt Erfolg und zeigt Recovery-Hinweis.

### B) Wiederherstellung in anderem Browser
1. User klickt "Aus WP wiederherstellen".
2. Extension holt Metadaten und Blob.
3. User entsperrt via Passkey (oder Recovery-Code).
4. Extension entpackt nsec lokal, validiert Pubkey.
5. Bei vorhandenem anderem lokalen Key: explizite Ueberschreib-Warnung.

Hinweis:
- Firefox und Chrome koennen unter Windows unterschiedliche Passkey-Stores nutzen.
- Dadurch kann ein in Firefox erzeugtes Backup-Wrap in Chrome ggf. nicht direkt entschluesselt werden.
- Pragmatiker-Flow:
  - nsec im Quell-Browser exportieren
  - nsec im Ziel-Browser importieren
  - neues Cloud-Backup im Ziel-Browser anlegen

### C) Key-Rotation
1. User waehlt "Neuen Key aktivieren".
2. Pflichtdialog mit Folgen (alter Pubkey passt nicht mehr).
3. Server-Update nur nach ausdruecklicher Bestaetigung.

---

## Akzeptanzkriterien

1. Restore ohne Passphrase-Merken moeglich (Passkey-first).
2. Kein Klartext-nsec in WP DB/Logs/REST.
3. Fehlversuche sind rate-limitiert und nachvollziehbar.
4. Bestehender WP-Pubkey wird nicht still ersetzt.
5. Cross-Browser Restore ist nur dann direkt per Passkey moeglich, wenn dieselbe Credential im Ziel-Browser verfuegbar ist.
6. Unlock-Cache-Policy ist im Popup aenderbar und wirkt sofort.
7. Option `session` haelt den Unlock maximal bis Browser-Ende.

---

## Offene Punkte

1. WebAuthn PRF Support-Matrix fuer Chrome/Firefox final pruefen.
2. Fallback-Policy definieren, wenn PRF nicht verfuegbar ist:
   - Recovery-Code only
   - oder lokaler Export/Import.
3. Speicherort in WP:
   - `usermeta` ausreichend oder eigene Tabelle fuer Audit/Versionierung.
