# AGENTS.md: NIP-07 Signer Extension für WordPress Nostr Integration

## Projektübersicht

Entwicklung einer Browser Extension (Chrome/Firefox), die:
1. NIP-07 Signer-Funktionalität bereitstellt
2. Nahtlos mit WordPress-Instanzen integriert
3. Automatische Domain-Authentifizierung über Whitelist
4. Sichere Key-Generierung mit Backup-Export

---

## Architektur

### Komponenten

```text
┌─────────────────┐     ┌────────────────────┐     ┌─────────────────┐
│  WordPress Site │◄───►│  Browser Extension │◄───►│  Nostr Relays   │
│  (PHP/REST API) │     │  (Manifest V3)     │     │  (WebSocket)    │
└─────────────────┘     └────────────────────┘     └─────────────────┘
         ▲                        │
         └────────────────────────┘
              Domain Whitelist
              Npub Registration
```

### Technik-Stack

| Komponente | Technologie | Begründung |
|------------|-------------|------------|
| Extension Core | Vanilla JS + WebExtension API | Maximale Kompatibilität |
| Nostr Crypto | nostr-tools v2+ (ES Module) | Standard-Implementierung |
| Build Pipeline | Rollup / esbuild | nostr-tools Bundling für MV3 Service Worker |
| WordPress Backend | PHP + REST API | Native Integration |
| Key Storage | Extension Storage API + AES-GCM | Verschlüsselt mit User-Passwort |
| UI | Vanilla JS + CSS | Keine Dependencies |
| Browser Compat | webextension-polyfill | Chrome + Firefox Unterstützung |

---

## Projektstruktur

```text
src/
├── background.js        # Service Worker (importiert nostr-tools)
├── content.js           # Bridge Script (kein Bundling nötig)
├── inpage.js            # NIP-07 API (IIFE, kein Import)
├── dialog.js            # Dialog-Logik
├── dialog.html
├── dialog.css
├── popup.html           # Extension Popup
├── popup.js
├── popup.css
├── icons/               # Icons (16, 48, 128)
├── manifest.chrome.json # Chrome MV3 Manifest
└── manifest.firefox.json # Firefox MV3 Manifest
```