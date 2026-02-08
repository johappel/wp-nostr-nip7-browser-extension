# Validierung: Sicherheitsregeln & Abhängigkeiten

## Übersicht der erstellten Task-Dateien

| Task | Dateiname | Abhängigkeiten |
|------|-----------|----------------|
| TASK-00 | TASK-00-Projekt-Uebersicht.md | - |
| TASK-01 | TASK-01-Extension-Grundgeruest.md | - |
| TASK-02 | TASK-02-WordPress-Integration-Detection.md | TASK-01 |
| TASK-03 | TASK-03-Extension-Key-Management-UI.md | TASK-01, TASK-07 |
| TASK-04 | TASK-04-NIP04-NIP44-Encryption.md | TASK-03 |
| TASK-05 | TASK-05-Domain-Whitelist.md | TASK-02 |
| TASK-06 | TASK-06-Update-Mechanismus.md | TASK-02 |
| TASK-07 | TASK-07-Build-Pipeline.md | TASK-01 |
| TASK-08 | TASK-08-Popup-UI.md | TASK-03 |
| TASK-09 | TASK-09-Unit-Tests.md | TASK-03, TASK-04 |

## Validierung der Sicherheitsregeln

### 1. NSEC REGELN

| Regel | Berücksichtigt in |
|-------|-------------------|
| Nsec nur AES-GCM verschlüsselt | TASK-03 (KeyManager) |
| Nsec nie in Webseiten-Kontext | TASK-03 (background.js) |
| Memory-Wipe nach Verwendung | TASK-03, TASK-04 (fill(0)) |
| Backup nur einmal | TASK-03 (Backup-Dialog) |

### 2. DOMAIN REGELN

| Regel | Berücksichtigt in |
|-------|-------------------|
| Domain-Validierung für Signatur-Anfragen | TASK-03 |
| Bootstrapping für unbekannte Domains | TASK-03 |
| Whitelist nur von autorisierten WP-Instanzen | TASK-05 |
| PING/VERSION_CHECK domain-frei | TASK-01, TASK-03 |

### 3. UI REGELN

| Regel | Berücksichtigt in |
|-------|-------------------|
| Signatur zeigt Domain + Event-Info | TASK-03 |
| Sensitive Events erfordern Bestätigung | TASK-03 |
| Backup-Dialog mit Checkbox | TASK-03 |
| Passwort min. 8 Zeichen + Wiederholung | TASK-03 |

### 4. KOMMUNIKATION REGELN

| Regel | Berücksichtigt in |
|-------|-------------------|
| WordPress Nonce-Validierung | TASK-02 |
| HTTPS erzwungen | TASK-03, TASK-05 |
| Keine Inline-Scripts | TASK-01 |
| Message-Bridge mit _id | TASK-01 |
| Domain-Listen HMAC-signiert | TASK-02, TASK-05 |

### 5. KEY-STORAGE REGELN

| Regel | Berücksichtigt in |
|-------|-------------------|
| AES-GCM Verschlüsselung | TASK-03 |
| PBKDF2 600.000 Iterations | TASK-03 |
| Salt und IV separat gespeichert | TASK-03 |
| Passwort nur Memory-Cache | TASK-03 |
| SW Neustart = Passwort neu eingeben | TASK-03 |

## Empfohlene Ausführungsreihenfolge

1. **TASK-00** - Lesen für Gesamtverständnis
2. **TASK-01** - Extension Grundgerüst
3. **TASK-07** - Build Pipeline
4. **TASK-02** - WordPress Integration
5. **TASK-03** - Key-Management & UI
6. **TASK-04** - Encryption
7. **TASK-08** - Popup UI
8. **TASK-05** - Domain Whitelist
9. **TASK-06** - Update Mechanismus
10. **TASK-09** - Unit Tests