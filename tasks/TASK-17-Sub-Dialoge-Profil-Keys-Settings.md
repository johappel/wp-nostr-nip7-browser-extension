# TASK-17: Sub-Dialoge – Profil-Detail, Schlüssel & Tresor, Einstellungen

## Ziel

Drei Dialog-Views implementieren, die über die Footer-Navigation bzw. den User-Hero erreichbar sind und die bisherige Popup-Funktionalität in eine übersichtlichere Struktur überführen.

## Abhängigkeiten

- TASK-16 (App-Shell & View-Router – muss zuerst stehen)
- TASK-08 (bisherige Popup-UI als Ausgangsbasis)
- TASK-10 (Passkey + WP Backup)
- TASK-11 (Backup/Restore Routinen)
- TASK-12 (Auth Broker)
- TASK-13 (CSS Design-System)

## Ergebnis

Die bisherigen Sektionen aus `popup.html` werden in drei eigenständige Views/Dialoge überführt:

---

## 1. Profil-Dialog (öffnet via Klick auf User-Hero)

### Inhalt

```text
┌──────────────────────────────┐
│  ← Zurück        Profil     │
├──────────────────────────────┤
│  ┌─────────┐                │
│  │ Avatar  │  Display Name  │
│  │  (groß) │  @user_login   │
│  └─────────┘  nip05@...     │
├──────────────────────────────┤
│  Öffentlicher Schlüssel      │
│  ┌──────────────────┬──┐    │
│  │ npub1abc...xyz   │📋│    │
│  └──────────────────┴──┘    │
│  ┌──────────────────┬──┐    │
│  │ hex: a1b2c3...   │📋│    │
│  └──────────────────┴──┘    │
├──────────────────────────────┤
│  NIP-05 Identität           │
│  alice@example.com           │
├──────────────────────────────┤
│  Primary Domain              │
│  example.com                 │
├──────────────────────────────┤
│  Profil-Relay                │
│  wss://relay.example.com     │
├──────────────────────────────┤
│  [  Profil an Nostr senden ] │
├──────────────────────────────┤
│  Mitglieder-Instanz          │
│  ┌──────────────────────┐   │
│  │ Origin, WP-Version,  │   │
│  │ Plugin-Version, Sync │   │
│  └──────────────────────┘   │
└──────────────────────────────┘
```

### Funktionalität (Migration aus bisheriger popup.js)

- `renderProfileCard()` → Profil-Dialog rendern
- `renderInstanceCard()` → Instanz-Info im Profil-Dialog
- `buildProfilePublishPayload()` + publish-Button → bleibt
- Copy-Lines für npub und hex-pubkey (bestehende `renderCopyLine()`)
- `refreshUserButton` → Profil-Dialog bekommt eigenen Reload-Button
- Fehlende Profilfelder werden als Hinweis angezeigt (`getMissingProfileFields()`)

---

## 2. Schlüssel & Tresor (View: Keys – Footer-Tab 🔑)

### Layout

```text
┌──────────────────────────────┐
│  Nostr-Schlüssel             │
├──────────────────────────────┤
│  Schutzart: [Dropdown ▾]    │
│  🔐 Passkey / 🔑 Passwort   │
│  / 🔓 Ohne Schutz           │
├──────────────────────────────┤
│                              │
│  ── Export ──                │
│  [Exportieren]               │
│  ┌──────────────────┬──┬──┐ │
│  │ nsec1... (hidden)│👁│📋│ │
│  └──────────────────┴──┴──┘ │
│  [⬇ Schlüsseldatei]         │
│                              │
│  ── Import ──                │
│  ┌──────────────────┬──────┐│
│  │ nsec1... (Input) │Import││
│  └──────────────────┴──────┘│
│                              │
│  ── Neuer Schlüssel ──       │
│  ⚠ Warnung: Identitätsverlust│
│  [Erstellen]                 │
│                              │
├──────────────────────────────┤
│  ── Tresor (WordPress) ──    │
│  Status: Letzte Sicherung... │
│                              │
│  [Speichern] [Wiederherstellen]│
│  [Löschen]                   │
└──────────────────────────────┘
```

### Funktionalität (Migration)

- `exportKeyButton` → Export-Sektion
- `backupOutputToggleButton`, `backupOutputCopyButton`, `backupDownloadButton` → Export
- `importNsecInput` + `importKeyButton` → Import-Sektion
- `createKeyButton` → Neuer Schlüssel (mit Danger-Warnung)
- `protectionRow` (Schutzart-Dropdown) → oben in Keys-View
- Cloud-Backup (`cloudBackupEnableButton`, `cloudBackupRestoreButton`, `cloudBackupDeleteButton`) → Tresor-Sektion
- `cloudBackupMeta` → Status-Anzeige im Tresor

---

## 3. Settings (View: Settings – Footer-Tab ⚙️)

### Layout

```text
┌──────────────────────────────┐
│  Einstellungen               │
├──────────────────────────────┤
│                              │
│  ReLogin-Dauer               │
│  Für sensible Aktionen       │
│  [Dropdown: 5m/15m/...▾]    │
│  Status: 🟢 aktiv / inaktiv │
│                              │
├──────────────────────────────┤
│  WP-Nostr-Lock               │
│  ☑ window.nostr schützen     │
│  Hinweis: Wirkt nach Reload  │
│                              │
├──────────────────────────────┤
│  Nachrichten-Relay           │
│  ┌──────────────────────┐   │
│  │ wss://relay.damus.io │   │
│  └──────────────────────┘   │
│  Relay für DM-Empfang/Versand│
│  (Kind 10050 / NIP-17)      │
│                              │
├──────────────────────────────┤
│  Erweitert                   │
│  Version: 1.0.0              │
│  Scope: wp:example.com:42    │
└──────────────────────────────┘
```

### Funktionalität (Migration)

- `unlockCachePolicySelect` + `unlockCacheState` + `unlockCacheHint` → ReLogin-Sektion
- `checkbox` (prefer-lock) → WP-Nostr-Lock Sektion
- **NEU**: Nachrichten-Relay Konfiguration (für TASK-19/20)
  - Eingabefeld für persönlichen DM-Relay
  - Wird in `chrome.storage.local` gespeichert unter Key `dmRelayUrl`
  - Default: leer (nutzt dann Kind 10050 des Gesprächspartners)
- Version + aktiver Scope als Info-Zeile

---

## Implementierungsplan

### Schritt 1: Views in popup.html anlegen

Innerhalb des `view-container` aus TASK-16 die drei Views mit ihren Sektionen als HTML-Blöcke erstellen. Bestehende IDs beibehalten, wo möglich, um Event-Listener-Migration zu minimieren.

### Schritt 2: Profil-Dialog als Overlay

- Bottom-Sheet Dialog (aus TASK-16 Dialog-System)
- Wird geöffnet via Klick auf `.user-hero`
- Alle Profil-Daten + Instanz-Info + Publish-Button

### Schritt 3: Event-Listener Migration

Bestehende Event-Listener aus `popup.js` werden auf die neuen DOM-Strukturen angepasst:

```javascript
// Bisheriger Flow:
// document.addEventListener('DOMContentLoaded', ...) → direkte Element-Referenzen

// Neuer Flow:
// Gleiche Logik, aber Elemente sind jetzt in Views verteilt
// Element-IDs bleiben gleich → Listener-Code ändert sich minimal
```

### Schritt 4: Zustandssynchronisation

Wenn ein View aktiv wird (`switchView()`), muss ggf. der Zustand aktualisiert werden:

```javascript
function onViewActivated(viewId) {
  switch (viewId) {
    case 'keys':
      refreshProtectionRow(); // Schutzart-Dropdown aktualisieren
      refreshCloudBackupState(); // Tresor-Status laden
      break;
    case 'settings':
      refreshUnlockState(); // ReLogin-Status aktualisieren
      break;
  }
}
```

### Schritt 5: Nachrichten-Relay Setting (Vorbereitung für TASK-19)

```javascript
const DM_RELAY_KEY = 'dmRelayUrl';

async function loadDmRelay() {
  const result = await chrome.storage.local.get([DM_RELAY_KEY]);
  return result[DM_RELAY_KEY] || '';
}

async function saveDmRelay(url) {
  const normalized = normalizeRelayUrl(url);
  if (normalized) {
    await chrome.storage.local.set({ [DM_RELAY_KEY]: normalized });
  }
}
```

## Akzeptanzkriterien

- [ ] Klick auf User-Hero öffnet Profil-Dialog mit allen bisherigen Profil-Infos
- [ ] Profil-Dialog: Pubkeys (npub + hex) kopierbar, Publish-Button funktioniert
- [ ] Keys-View: Export, Import, Erstellen funktionieren wie bisher
- [ ] Keys-View: Tresor-Sektion (WordPress Cloud Backup) vollständig eingebaut
- [ ] Keys-View: Schutzart-Dropdown oben sichtbar
- [ ] Settings-View: ReLogin-Dauer + Status-Badge
- [ ] Settings-View: WP-Nostr-Lock Checkbox
- [ ] Settings-View: Nachrichten-Relay Feld (speichert in storage)
- [ ] Alle bisherigen Funktionen aus dem alten Popup bleiben erreichbar
- [ ] Status-Meldungen (`#status`) werden view-übergreifend angezeigt
- [ ] Kein Funktionsverlust gegenüber dem bisherigen Popup

## Hinweise

- Bestehende Element-IDs möglichst beibehalten, um den Refactoring-Aufwand in `popup.js` zu minimieren
- `popup.js` darf keine `import`-Statements enthalten (kein Bundling)
- Profil-Dialog und Views teilen sich den gleichen Datenkontext (`activeViewer`, `activeRuntimeStatus`)
