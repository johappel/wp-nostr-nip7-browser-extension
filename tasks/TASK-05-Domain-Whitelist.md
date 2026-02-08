# TASK-05: Multi-Domain Whitelist Management

## Ziel
Implementierung des Synchronisations-Mechanismus für die Domain-Whitelist. Die Extension lädt periodisch eine Liste vertrauenswürdiger Domains von der konfigurierten "Primary Domain" (WordPress) und verifiziert diese mittels HMAC-Signatur.

## Abhängigkeiten
- **TASK-02: WordPress Integration** (stellt den REST-Endpoint bereit)
- **TASK-03: Key-Management & UI** (stellt die Basis-Struktur in background.js bereit)

## Ergebnis
Nach Abschluss dieses Tasks:
- Extension akzeptiert Konfiguration für `primaryDomain` und `domainSecret`.
- Hintergrund-Prozess (Alarm) ruft `/wp-json/nostr/v1/domains` ab.
- Signatur der Domain-Liste wird geprüft.
- Bei Erfolg wird die lokale Whitelist (`allowedDomains`) aktualisiert.

---

## Zu erstellende / zu ändernde Dateien

### 1. src/lib/domain-access.js

Erweiterung um `verifyWhitelistSignature`. Diese Funktion rekonstruiert den Payload (`json_encode($domains) . '|' . $timestamp`) und prüft die HMAC-SHA256 Signatur gegen das gespeicherte Secret.

### 2. src/background.js

Update der `updateDomainWhitelist` Funktion:
- Verwendung der neuen Verifikations-Logik.
- Implementierung eines neuen Message-Handlers `NOSTR_SET_DOMAIN_CONFIG`, um die Primary Domain und das Secret initial zu setzen (z.B. durch den User oder ein Admin-Script).

---

## Sicherheitsregeln

### 1. Signatur-Prüfung
- Die Signatur MUSS valide sein, bevor Domains in die `allowedDomains` Liste übernommen werden.
- Das Secret darf die Extension nie verlassen (nur `verify`, kein Export).

### 2. Daten-Integrität
- Der Timestamp der Antwort sollte geprüft werden, um Replay-Attacken mit alten Listen zu erschweren (optional, hier implementiert als "neuer als letztes Update").

## Technische Details

### Signatur-Schema (PHP Seite)
```php
$payload = json_encode($domains);
$signature = hash_hmac('sha256', $payload . '|' . $timestamp, $secret);
```

### Verifikation (JS Seite)
- `JSON.stringify(domains)` muss dem PHP `json_encode` entsprechen (bei einfachen String-Arrays ist das der Fall).
- `crypto.subtle.verify` mit HMAC-SHA256.