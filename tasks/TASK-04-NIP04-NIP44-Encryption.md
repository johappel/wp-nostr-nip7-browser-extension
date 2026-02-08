# TASK-04: NIP-04 & NIP-44 Encryption

## Ziel
Implementierung der Verschlüsselungsmethoden für NIP-04 (Legacy) und NIP-44 (Modern) unter Verwendung von `nostr-tools`.

## Abhängigkeiten
- **TASK-03: Key-Management & UI** (für Zugriff auf Private Key)

## Ergebnis
Nach Abschluss dieses Tasks unterstützt die Extension:
- `window.nostr.nip04.encrypt`
- `window.nostr.nip04.decrypt`
- `window.nostr.nip44.encrypt`
- `window.nostr.nip44.decrypt`

---

## Zu erstellende Dateien

### 1. src/lib/crypto-handlers.js

Kapselt die `nostr-tools` Aufrufe für NIP-04 und NIP-44.

### 2. src/background.js (Update)

Integration der Handler in den Message-Loop des Service Workers.

---

## Sicherheitsregeln

### 1. Key Handling
- Der Private Key wird nur kurzzeitig entschlüsselt.
- Nach der Operation wird `secretKey.fill(0)` aufgerufen (Memory Wipe).
- Zugriff erfordert entsperrte Extension (Passwort-Cache aktiv).

### 2. Domain Access
- Verschlüsselung/Entschlüsselung ist nur für whitelisted Domains erlaubt.
- Dies wird bereits durch den zentralen Check in `background.js` (aus TASK-03) sichergestellt.

## Technische Details

- **NIP-04**: Nutzt AES-256-CBC. Der IV wird oft an den Ciphertext angehängt (`ciphertext?iv=...`).
- **NIP-44**: Nutzt ChaCha20-Poly1305. Sicherer und moderner.

Die Implementierung nutzt die Funktionen aus `nostr-tools`, um Standardkonformität zu gewährleisten.