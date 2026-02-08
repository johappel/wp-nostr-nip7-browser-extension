# TASK-09: Unit Tests

## Ziel
Erstellung von Unit-Tests für die kritischen Logik-Komponenten der Extension.

## Abhängigkeiten
- **TASK-03: Key-Management**
- **TASK-04: Encryption**
- **TASK-05: Domain Whitelist**

## Ergebnis
Nach Abschluss dieses Tasks:
- `npm test` führt Tests erfolgreich aus.
- Abdeckung für:
  - `KeyManager` (Generierung, Verschlüsselung, Signatur)
  - `DomainAccess` (Whitelist-Check, Signatur-Verifikation)
  - `CryptoHandlers` (NIP-04, NIP-44)

---

## Zu erstellende Dateien

### 1. tests/setup.js

Mocking der Chrome Storage API und `crypto.subtle` (falls in Node-Umgebung nötig, Vitest nutzt jsdom/happy-dom, die WebCrypto oft unterstützen).

### 2. tests/key-manager.test.js

Tests für:
- `generateKey`
- `storeKey` / `getKey` (Verschlüsselung)
- `signEvent`

### 3. tests/domain-access.test.js

Tests für:
- `checkDomainAccess` (Blocked, Allowed, Pending)
- `verifyWhitelistSignature` (HMAC Validierung)

### 4. tests/crypto-handlers.test.js

Tests für:
- NIP-04 Encrypt/Decrypt
- NIP-44 Encrypt/Decrypt

---

## Technische Details

- Wir nutzen `vitest` als Test-Runner.
- `chrome.storage.local` muss gemockt werden.
- `TextEncoder`/`TextDecoder` und `crypto` sind in modernen Node-Versionen (und Vitest) verfügbar.