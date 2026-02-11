# TASK-16: Popup-Redesign – App-Shell, Footer-Navigation & View-Router

## Ziel

Das bisherige Scroll-basierte Popup wird in eine moderne App-Shell mit Footer-Navigation und Dialog-basiertem View-System umgebaut. Das neue Layout orientiert sich an nativen Messaging-Apps (siehe Screenshot-Referenz).

## Abhängigkeiten

- TASK-08 (Popup UI – bestehend)
- TASK-13 (CSS-Design-System – bestehende Tokens wiederverwenden)

## Ergebnis

| Datei | Änderung |
|-------|----------|
| `popup.html` | Komplett-Umbau: App-Shell mit Header, Content-Area, Footer-Nav |
| `popup.css` | Neues Layout-System, Views, Footer-Bar, Transitions |
| `popup.js` | View-Router, Dialog-Management, Event-Delegation |
| `manifest.chrome.json` | ggf. Popup-Größe anpassen |
| `manifest.firefox.json` | ggf. Popup-Größe anpassen |

## Design-Spezifikation

### Gesamtstruktur

```text
┌──────────────────────────────┐
│  HEADER                      │
│  ┌──────────────────────┐    │
│  │ App-Name + Status    │ 🔔 │
│  └──────────────────────┘    │
├──────────────────────────────┤
│  USER HERO                   │
│  ┌──────────┬───────────┐    │
│  │  Avatar  │ Name      │    │
│  │          │ nip05     │    │
│  └──────────┴───────────┘    │
├──────────────────────────────┤
│  CONTENT AREA (wechselnd)    │
│                              │
│  [Home / Chat / Keys / ...]  │
│                              │
│                              │
│                              │
├──────────────────────────────┤
│  FOOTER NAV                  │
│  🏠    🔑    🕐    ⚙️       │
│  Home  Keys  History  Settings│
└──────────────────────────────┘
```

### Header

- App-Name: **"WP Nostr Signer"** (oder kurz "NostrSign")
- Verbindungsstatus: grüner/roter Punkt + "Connected" / "Offline"
- Optional: Notification-Badge (Anzahl ungelesener Nachrichten)

### User Hero (klickbar → öffnet Profil-Dialog, siehe TASK-17)

- Prominente Karte mit Avatar, Display-Name, NIP-05 Adresse
- Hintergrund: Gradient passend zum Design-System (accent-soft)
- Klick öffnet den Profil-Detail-Dialog

### Content Area

- Standardansicht: **Home** = Kontaktliste / Chat-Übersicht (siehe TASK-20)
- Wechsel über Footer-Navigation
- Views werden als übereinander liegende Panels realisiert (`display: none` / `display: block`)
- Smooth Transitions via CSS `opacity` + `transform`

### Footer Navigation Bar

| Icon | Label | View | Beschreibung |
|------|-------|------|-------------|
| 🏠 | Home | `view-home` | Kontaktliste & Chat-Übersicht (Primary Domain) |
| 🔑 | Keys | `view-keys` | Schlüssel-Verwaltung (Export, Import, Tresor) |
| 🕐 | History | `view-history` | Letzte Signing-Events, Aktivitätslog |
| ⚙️ | Settings | `view-settings` | Schutzart, Unlock-Policy, Lock, Relays |

- Active State: Icon + Label mit `--accent` Farbe, leichter Glow
- Inkaktiver State: `--muted` Farbe
- Feste Höhe: ~48px
- Border-top: `1px solid var(--border)`

## Implementierungsplan

### Schritt 1: HTML-Grundgerüst

```html
<body>
  <main class="app-shell">
    <header class="app-header">...</header>
    <section class="user-hero" id="user-hero">...</section>
    
    <!-- Views -->
    <div class="view-container">
      <div class="view active" id="view-home">...</div>
      <div class="view" id="view-keys">...</div>
      <div class="view" id="view-history">...</div>
      <div class="view" id="view-settings">...</div>
    </div>
    
    <!-- Overlay-Dialoge -->
    <div class="dialog-overlay" id="dialog-overlay">
      <div class="dialog" id="dialog-profile">...</div>
    </div>

    <nav class="footer-nav" id="footer-nav">
      <button class="nav-item active" data-view="home">🏠<span>Home</span></button>
      <button class="nav-item" data-view="keys">🔑<span>Keys</span></button>
      <button class="nav-item" data-view="history">🕐<span>History</span></button>
      <button class="nav-item" data-view="settings">⚙️<span>Settings</span></button>
    </nav>
  </main>
</body>
```

### Schritt 2: CSS – App-Shell Layout

```css
.app-shell {
  display: flex;
  flex-direction: column;
  width: 420px;
  height: 580px;       /* feste Höhe für Extension-Popup */
  overflow: hidden;
}

.view-container {
  flex: 1;
  overflow-y: auto;
  position: relative;
}

.view {
  display: none;
  padding: 10px 14px;
}

.view.active {
  display: block;
}

.footer-nav {
  display: flex;
  border-top: 1px solid var(--border);
  background: var(--surface);
  padding: 6px 0;
}

.nav-item {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  font-size: 10px;
  color: var(--muted);
  background: none;
  border: none;
  cursor: pointer;
}

.nav-item.active {
  color: var(--accent);
}
```

### Schritt 3: View-Router in JavaScript

```javascript
function switchView(viewId) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  
  const view = document.getElementById(`view-${viewId}`);
  const navItem = document.querySelector(`[data-view="${viewId}"]`);
  if (view) view.classList.add('active');
  if (navItem) navItem.classList.add('active');
}

// Dialog-System
function openDialog(dialogId) {
  const overlay = document.getElementById('dialog-overlay');
  const dialog = document.getElementById(dialogId);
  overlay.classList.add('open');
  dialog.classList.add('open');
}

function closeDialog() {
  document.getElementById('dialog-overlay').classList.remove('open');
  document.querySelectorAll('.dialog.open').forEach(d => d.classList.remove('open'));
}
```

### Schritt 4: Migration bestehender Funktionalität

Die bestehenden Popup-Funktionen (aus `popup.js`) werden auf die neuen Views verteilt:

| Bisherige Section | Neuer Ort |
|-------------------|-----------|
| Profil-Section (hero, pubkeys, publish) | **Dialog: Profil-Detail** (via User-Hero Klick) |
| WP-Nostr-Lock Checkbox | **View: Settings** |
| Unlock/ReLogin Section | **View: Settings** |
| Backup Section (Export/Import/Create) | **View: Keys** |
| Cloud Backup | **View: Keys** (Tresor-Tab) |
| Instance Section | **Dialog: Profil-Detail** oder **View: Home** |
| Schutzart-Dropdown | **View: Settings** |

### Schritt 5: Dialog-Overlay CSS

```css
.dialog-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 100;
  display: none;
  align-items: flex-end;
  backdrop-filter: blur(4px);
}

.dialog-overlay.open {
  display: flex;
}

.dialog {
  width: 100%;
  max-height: 85%;
  background: var(--surface);
  border-radius: var(--radius) var(--radius) 0 0;
  padding: 16px;
  overflow-y: auto;
  transform: translateY(100%);
  transition: transform 0.25s ease;
}

.dialog.open {
  transform: translateY(0);
}
```

## Akzeptanzkriterien

- [ ] Popup zeigt App-Shell mit Header, Hero, Content, Footer
- [ ] 4 Footer-Tabs wechseln die aktive View ohne Seitenreload
- [ ] Views smooth ein-/ausblenden
- [ ] Dialoge öffnen als Bottom-Sheet Overlay
- [ ] Klick auf User-Hero öffnet Profil-Dialog
- [ ] Zurück-Button / Overlay-Klick schließt Dialoge
- [ ] Alle bestehenden Funktionen bleiben erreichbar (umverteilt auf Views)
- [ ] Dark/Light Mode funktioniert korrekt
- [ ] Chrome + Firefox kompatibel
- [ ] Feste Popup-Größe: ~420×580px (kein Overflow am Body)

## Hinweise

- `popup.js` wird NICHT gebundelt → kein `import` von nostr-tools möglich
- Alle Crypto-Operationen weiterhin via `chrome.runtime.sendMessage` an den Background-Worker
- Bestehende CSS Custom Properties aus TASK-13 wiederverwenden
- Keine externen UI-Frameworks (Vanilla JS + CSS)
