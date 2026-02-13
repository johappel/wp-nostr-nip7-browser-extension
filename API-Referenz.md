# API Referenz: Nostr Extension Backend Protocol

Diese Dokumentation beschreibt die REST-API-Endpunkte, die vom Backend (z. B. WordPress Plugin oder KeyCloak Adapter) bereitgestellt werden müssen, damit die NIP-07 Browser Extension vollständig funktioniert.

## Grundlagen

*   **Base URL:** `/wp-json/nostr/v1` (Standard in WordPress, konfigurierbar in der Extension).
*   **Authentifizierung:** Die meisten Endpunkte erfordern einen eingeloggten Benutzer (Session-Cookie).
*   **Sicherheit:** Schreibende Anfragen (`POST`, `PUT`, `DELETE`) erfordern in WordPress einen Nonce-Header (`X-WP-Nonce`), der im Frontend bereitgestellt wird.
*   **Datenformat:** JSON.

### Extension Message-Protokoll (Iststand 2026-02)

Diese Datei beschreibt primär die Backend-REST-API. Da in älteren Task-Dokumenten auch interne Extension-Message-Commands dokumentiert wurden, hier der aktuelle Stand für den Background-Message-Vertrag:

**Aktiv:**
- `NOSTR_PING`
- `NOSTR_SET_UNLOCK_CACHE_POLICY`
- `NOSTR_CHANGE_PROTECTION`
- `NOSTR_GET_STATUS`
- `NOSTR_GET_KEY_SCOPE_INFO`
- `NOSTR_BACKUP_STATUS`, `NOSTR_BACKUP_ENABLE`, `NOSTR_BACKUP_RESTORE`, `NOSTR_BACKUP_DELETE`
- `NOSTR_EXPORT_NSEC`, `NOSTR_CREATE_NEW_KEY`, `NOSTR_IMPORT_NSEC`
- `NOSTR_PUBLISH_PROFILE`
- `NOSTR_GET_CONTACTS`, `NOSTR_REFRESH_CONTACTS`, `NOSTR_ADD_CONTACT`
- `NOSTR_SEND_DM`, `NOSTR_GET_DMS`, `NOSTR_SUBSCRIBE_DMS`
- `NOSTR_SET_DOMAIN_CONFIG`, `NOSTR_GET_DOMAIN_SYNC_STATE`
- `NOSTR_GET_PUBLIC_KEY`, `NOSTR_SIGN_EVENT`, `NOSTR_GET_RELAYS`
- `NOSTR_NIP04_ENCRYPT`, `NOSTR_NIP04_DECRYPT`, `NOSTR_NIP44_ENCRYPT`, `NOSTR_NIP44_DECRYPT`

**Entfernt (Obsolete-Cleanup):**
- `NOSTR_CHECK_VERSION`, `NOSTR_LOCK`
- `NOSTR_DELETE_SCOPE_KEY`, `NOSTR_LIST_ALL_SCOPE_KEYS`
- `NOSTR_GET_WP_MEMBERS`, `NOSTR_REFRESH_WP_MEMBERS`
- `NOSTR_GET_CONVERSATIONS`, `NOSTR_GET_DM_RELAYS`, `NOSTR_UNSUBSCRIBE_DMS`
- `NOSTR_GET_UNREAD_COUNT`, `NOSTR_CLEAR_UNREAD`
- `NOSTR_SET_DM_NOTIFICATIONS`, `NOSTR_GET_DM_NOTIFICATIONS`
- `NOSTR_CLEAR_DM_CACHE`, `NOSTR_POLL_DMS`
- `NOSTR_UPSERT_DOMAIN_SYNC_CONFIG`, `NOSTR_SYNC_DOMAINS_NOW`, `NOSTR_REMOVE_DOMAIN_SYNC_CONFIG`

---

## 1. Domain Management & Konfiguration

Diese Endpunkte dienen der Synchronisation von Vertrauenseinstellungen (Whitelists) und der Initialisierung der Extension.

### 1.1 Domain Whitelist abrufen
Liefert die Liste der vertrauenswürdigen Domains, signiert vom Server.

*   **Methode:** `GET`
*   **Pfad:** `/domains`
*   **Zugriff:** Öffentlich

**Response (200 OK):**
```json
{
  "domains": [
    "example.com",
    "community.edufeed.org"
  ],
  "updated": 1709200000,
  "signature": "hmac_sha256_hex_string"
}
```
*   `signature`: HMAC-SHA256 von `json_encode(domains) + '|' + updated` mit dem `domainSecret`.

### 1.2 Viewer Context & Config
Liefert Informationen über den aktuellen Benutzer und globale Konfigurationen für die Extension (z. B. Auth-Broker URLs).

*   **Methode:** `GET`
*   **Pfad:** `/viewer`
*   **Zugriff:** Öffentlich (liefert `isLoggedIn: false` wenn Gast)

**Response (200 OK):**
```json
{
  "isLoggedIn": true,
  "userId": 123,
  "displayName": "Max Mustermann",
  "avatarUrl": "https://...",
  "pubkey": "a1b2c3...", 
  "primaryDomain": "https://example.com",
  "authBrokerEnabled": true,
  "authBrokerUrl": "https://auth.example.com/?nostr_auth_broker=1",
  "authBrokerOrigin": "https://auth.example.com",
  "authBrokerRpId": "example.com"
}
```

---

## 2. Identitäts-Registrierung

Verknüpft einen Nostr Public Key (Npub) mit dem Benutzerkonto im Backend.

### 2.1 Public Key registrieren
Setzt den Public Key für den aktuellen Benutzer, falls noch keiner existiert.

*   **Methode:** `POST`
*   **Pfad:** `/register`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "pubkey": "hex_string_64_chars"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "pubkey": "hex_string...",
  "registered": "2024-03-01 12:00:00"
}
```

### 2.2 Public Key ersetzen (Key Rotation)
Ersetzt einen bestehenden Key. Erfordert die Angabe des alten Keys zur Vermeidung von Race Conditions.

*   **Methode:** `POST`
*   **Pfad:** `/register/replace`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "pubkey": "new_hex_string...",
  "expectedCurrentPubkey": "old_hex_string..."
}
```

---

## 3. Encrypted Key Backup (Cloud Recovery)

Ermöglicht das Speichern und Laden eines verschlüsselten Private Keys. Das Backend sieht **niemals** den Klartext-Key oder das Entschlüsselungspasswort.

### 3.1 Backup Metadaten abrufen
Prüft, ob ein Backup vorhanden ist, ohne den Blob zu laden.

*   **Methode:** `POST`
*   **Pfad:** `/backup/metadata`
*   **Zugriff:** Authentifiziert

**Response (200 OK):**
```json
{
  "hasBackup": true,
  "version": 1,
  "pubkey": "hex_string...",
  "updatedAt": 1709200000,
  "hasRecoveryWrap": true,
  "passkeyCredentialFingerprint": "sha256_base64..."
}
```

### 3.2 Backup hochladen
Speichert den verschlüsselten Key-Blob.

*   **Methode:** `POST`
*   **Pfad:** `/backup/upload`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "version": 1,
  "pubkey": "hex_string...",
  "backupBlob": "base64_aes_gcm_ciphertext",
  "blobIv": "base64_iv",
  "blobAad": "base64_aad",
  "wrappedDekPasskey": "base64_wrapped_key_for_passkey",
  "wrappedDekRecovery": "base64_wrapped_key_for_recovery_code",
  "keyFingerprint": "sha256_base64",
  "passkeyCredentialFingerprint": "sha256_base64"
}
```

### 3.3 Backup herunterladen
Lädt den verschlüsselten Blob zur Wiederherstellung.

*   **Methode:** `POST`
*   **Pfad:** `/backup/download`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "expectedPubkey": "hex_string..." // Optional, zur Verifikation
}
```

**Response (200 OK):**
Gibt die gleichen Felder wie beim Upload zurück (Blob, IV, Wrapped Keys).

### 3.4 Backup löschen
Entfernt das Backup vom Server.

*   **Methode:** `POST`
*   **Pfad:** `/backup/delete`
*   **Zugriff:** Authentifiziert

---

## 4. WebAuthn Broker (Optional)

Dient dazu, Passkey-Operationen (Assertions) über eine zentrale Domain (`authBrokerOrigin`) abzuwickeln, auch wenn der User sich auf einer Subdomain befindet. Dies umgeht Browser-Restriktionen bezüglich WebAuthn-Origins.

### 4.1 Assertion Challenge anfordern
Startet den Login/Unlock-Prozess via Passkey.

*   **Methode:** `POST`
*   **Pfad:** `/webauthn/assert/challenge`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "intent": "unlock_key" // oder "backup_access"
}
```

**Response (200 OK):**
```json
{
  "challengeId": "random_id",
  "challengeOptions": {
    "challenge": "base64url_encoded_challenge",
    "rpId": "example.com",
    "timeout": 120000,
    "userVerification": "preferred"
  },
  "origin": "https://auth.example.com"
}
```

### 4.2 Assertion verifizieren
Prüft die vom Browser/Extension signierte Challenge.

*   **Methode:** `POST`
*   **Pfad:** `/webauthn/assert/verify`
*   **Zugriff:** Authentifiziert

**Request Body:**
```json
{
  "challengeId": "id_from_step_4.1",
  "clientDataJSON": "base64url...",
  "credentialId": "base64url...",
  "authenticatorData": "base64url...",
  "signature": "base64url..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "token": "signed_jwt_or_token_proving_verification"
}
```

---

## Fehlerbehandlung

Die API nutzt Standard HTTP Status Codes:

*   `200 OK`: Erfolg.
*   `400 Bad Request`: Ungültige Parameter (z. B. falsches Pubkey-Format).
*   `401 Unauthorized`: Nicht eingeloggt oder Session abgelaufen.
*   `403 Forbidden`: Fehlende Berechtigung (z. B. falscher Nonce).
*   `404 Not Found`: Ressource nicht gefunden (z. B. kein Backup vorhanden).
*   `409 Conflict`: Konflikt (z. B. Pubkey bereits vergeben, Backup-Pubkey passt nicht zum Account).
*   `429 Too Many Requests`: Rate Limit überschritten (z. B. bei Backup-Downloads).
*   `500 Internal Server Error`: Serverfehler.

**Fehler-Response Body:**
```json
{
  "code": "error_code_string",
  "message": "Human readable error message",
  "data": {
    "status": 409,
    "additional_info": "..."
  }
}
```