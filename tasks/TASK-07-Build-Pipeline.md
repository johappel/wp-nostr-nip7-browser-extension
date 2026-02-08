# TASK-07: Build Pipeline & Browser-Kompatibilität

## Ziel
Einrichtung einer robusten Build-Pipeline mit Rollup, um:
1. `nostr-tools` und andere Abhängigkeiten in den Service Worker zu bundeln.
2. Separate Builds für Chrome (Manifest V3) und Firefox (Manifest V3) zu erstellen.
3. Statische Assets (Icons, HTML, CSS) automatisch zu kopieren.

## Abhängigkeiten
- **TASK-01: Extension Grundgerüst**

## Ergebnis
Nach Abschluss dieses Tasks:
- `npm run build` erstellt fertige Extension-Pakete in `dist/chrome` und `dist/firefox`.
- `npm run dev` startet den Watch-Mode für Entwicklung.
- `nostr-tools` ist korrekt im Background-Script verfügbar.

---

## Zu erstellende Dateien

### 1. package.json

Definition der Abhängigkeiten und Scripts.

### 2. rollup.config.js

Konfiguration für:
- Input: `src/background.js`
- Output: `dist/chrome/background.js` (Format: ES Module)
- Plugins: Node Resolve, CommonJS, Copy (für Manifest & Assets)

### 3. .gitignore

Ausschluss von `node_modules` und `dist`.

### 4. manifest.firefox.json

Spezifisches Manifest für Firefox (MV3).

---