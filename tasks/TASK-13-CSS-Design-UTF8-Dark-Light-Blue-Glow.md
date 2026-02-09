# TASK-13: CSS- und Design-System (UTF-8, Dark/Light, Blue Glow)

## Ziel
Modernisierung von `popup` und `dialog` mit einem konsistenten Design-System:
1. korrekte UTF-8 Darstellung (inkl. Umlaute),
2. automatisches Dark/Light Theme basierend auf dem Betriebssystem,
3. modernes visuelles Erscheinungsbild mit blauem Glow-Effekt in relevanten UI-States.

## Abhängigkeiten
- **TASK-03: Extension Key-Management & UI**
- **TASK-08: Popup UI**
- **TASK-12: Primary-Domain Auth Broker** (betroffene Dialog-Flows)

## Scope
1. Einheitliche Design-Variablen (CSS Custom Properties) für Farben, Radius, Schatten, Abstände, Typografie.
2. Theme-Umschaltung über `prefers-color-scheme`:
   - Light Theme als Standard,
   - Dark Theme automatisch bei System-Dark-Mode.
3. Überarbeitung von:
   - `popup.html`, `popup.css`, `popup.js`,
   - `dialog.html`, `dialog.css`, `dialog.js`.
4. Klar erkennbare visuelle Zustände:
   - normal,
   - hover,
   - focus-visible,
   - active,
   - disabled,
   - error/success.
5. Blauer Glow-Effekt als Signature-Stil:
   - bei primären Aktionen (`.btn-primary`),
   - bei Fokuszuständen von Inputs/Buttons,
   - bei wichtigen Statuskarten (z. B. aktiver Signer, Passkey-Aktion).
6. Lesbarkeit und Kontrast gemäß WCAG AA (mindestens 4.5:1 für Fließtext).
7. Responsives Verhalten für Popup- und Dialog-Größen in Chrome und Firefox.

## Nicht-Ziele
1. Einführung eines externen UI-Frameworks.
2. Wechsel auf React/Vue oder Build-Umstellung.
3. Kompletter Redesign der WordPress-Frontend-Integration außerhalb von Extension-UI.

## UTF-8 und Sprache (Pflicht)
1. Alle UI-Texte in `popup` und `dialog` auf korrektes Deutsch oder korrektes Deutsch/Englisch prüfen.
2. Dateien müssen als UTF-8 (ohne kaputte Umlaute/Encoding-Artefakte) vorliegen.
3. Typische Problemtexte aktiv korrigieren, z. B.:
   - `fÃ¼r` -> `für`
   - `SchlÃ¼ssel` -> `Schlüssel`
4. Keine Mischformen aus fehlerhaftem Encoding im sichtbaren UI.

## Design-Richtlinien
1. Farbkonzept:
   - neutrales Basis-Theme,
   - Akzentfarbe Blau für Interaktion und Fokus.
2. Blue Glow:
   - weicher Außen- und Innen-Glow (z. B. über `box-shadow`),
   - keine übertriebene Leuchtstärke,
   - im Dark Theme etwas stärker als im Light Theme.
3. Typografie:
   - klare Hierarchie für Titel, Labels, Hinweise, Code-Werte.
4. Bewegungen:
   - kurze, gezielte Transitionen (120–220ms),
   - kein visuelles Flackern bei Theme-Wechsel.
5. Komponenten:
   - Buttons, Inputs, Selects, Cards, Hinweise, Statuszeilen, Copy-Zeilen.

## Technische Leitplanken
1. CSS-Variablen zentral definieren, z. B.:
   - `--bg`, `--surface`, `--text`, `--muted`,
   - `--accent`, `--accent-glow`,
   - `--border`, `--danger`, `--success`.
2. Theme-Switch über:
   - `@media (prefers-color-scheme: dark) { ... }`
3. Fokus sichtbar und barrierearm:
   - `:focus-visible` mit klarem Ring + Glow.
4. `color-scheme` setzen, damit native Form-Controls korrekt gerendert werden.
5. Keine Inline-Styles für neue Design-Logik.

## Akzeptanzkriterien
1. Popup und Dialog passen sich automatisch an System Dark/Light Mode an.
2. Primäre Aktionen haben einen modernen, blauen Glow-State (hover/focus/active).
3. Alle sichtbaren Texte in Popup/Dialog sind sprachlich konsistent und korrekt codiert (UTF-8, Umlaute).
4. Keine abgeschnittenen Inhalte oder unlesbaren Kontraste in gängigen Fenstergrößen.
5. Design wirkt in Chrome und Firefox konsistent (kleine Browser-Unterschiede erlaubt).
6. Bestehende Funktionalität (Unlock, Passkey, Backup, Domain-Sync) bleibt unverändert nutzbar.

## Implementierungsplan
1. **Bestandsaufnahme**
   - Encoding-Probleme in Popup/Dialog-Texten erfassen.
   - bestehende Komponenten und States inventarisieren.
2. **Design-Tokens einführen**
   - CSS-Variablen in `popup.css` und `dialog.css` strukturieren.
3. **Theme-Implementierung**
   - Light/Dark Varianten über `prefers-color-scheme`.
4. **Komponenten-Refactoring**
   - Buttons, Inputs, Cards, Status, Copy-UI vereinheitlichen.
5. **Blue Glow States**
   - primäre Interaktionselemente final stylen und feinjustieren.
6. **Text- und Encoding-Fix**
   - UI-Texte sprachlich/technisch korrigieren (UTF-8).
7. **Cross-Browser QA**
   - Chrome + Firefox manuell prüfen, danach Build/Test laufen lassen.

## Test-Checkliste
1. `npm run build` erfolgreich.
2. `npm test` erfolgreich.
3. Sichtprüfung:
   - Windows Light Theme,
   - Windows Dark Theme,
   - Chrome Popup + Dialog,
   - Firefox Popup + Dialog.
4. Fokus-Navigation per Tastatur (`Tab`, `Shift+Tab`) mit sichtbar eindeutigen Fokusstates.
