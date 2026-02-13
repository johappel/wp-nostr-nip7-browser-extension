# TASK-08: Popup UI

## Hinweis zum Iststand (2026-02)

Historisches Task-Dokument. Die frühere Lock-Aktion per `NOSTR_LOCK` wurde entfernt.
Aktive Popup-Kommunikation läuft über Commands wie `NOSTR_GET_STATUS`, `NOSTR_SET_UNLOCK_CACHE_POLICY`, `NOSTR_CHANGE_PROTECTION`, Key/Backup/Profile/DM-Commands.

## Ziel
Implementierung der Benutzeroberfläche für das Extension-Popup (`popup.html`).

## Abhängigkeiten
- **TASK-03: Key-Management & UI** (für Status-Abfragen)

## Ergebnis
Nach Abschluss dieses Tasks:
- Klick auf Extension-Icon öffnet ein UI.
- UI zeigt Status (Setup nötig, Gesperrt, Bereit).
- User kann Npub kopieren.
- (historisch) User kann Extension sperren ("Lock").

---

## Zu erstellende Dateien

### 1. src/popup.html

Struktur der UI.

### 2. src/popup.css

Styling passend zum Dialog-Design.

### 3. src/popup.js

Logik für:
- Kommunikation mit Background-Script (u. a. `NOSTR_GET_STATUS`).
- UI-Updates basierend auf Status.
- Clipboard-Aktionen.

### 4. src/background.js (Update)

Hinzufügen von `NOSTR_GET_STATUS` zur Message-Loop, damit das Popup den Status abfragen kann, ohne Dialoge zu öffnen.

---

## Technische Details

- `popup.js` wird nicht gebundelt (siehe `rollup.config.js`), daher kein Import von `nostr-tools` möglich.
- Alle kryptografischen Operationen oder Formatierungen (z.B. hex zu npub) müssen im Background-Script erfolgen und als String an das Popup gesendet werden.