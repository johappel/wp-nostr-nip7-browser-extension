# Konzept: NIP-07 Browser Extension & Identity Provider Integration

Dieses Dokument erklärt die Funktionsweise der NIP-07 Extension, die Besonderheiten der Integration mit WordPress und wie diese Architektur auf andere Identity Provider (IdP) wie KeyCloak übertragen werden kann.

---

## 1. Einführung: Das Problem mit Passwörtern

Herkömmliche Logins basieren darauf, dass der Nutzer ein Geheimnis (Passwort) an einen Server sendet. Das hat Nachteile:
- Der Server kennt das Geheimnis (oder einen Hash).
- Der Nutzer muss es sich merken oder einen Manager nutzen.
- Phishing-Seiten können das Passwort abfangen.

**Die Lösung (Nostr / NIP-07):**
Statt ein Passwort zu senden, besitzt der Nutzer einen **kryptografischen Schlüssel** (Private Key), der seinen Computer nie verlässt. Wenn er sich einloggen will, signiert er lediglich eine "Herausforderung" (Challenge). Der Server prüft die Unterschrift, kennt aber niemals den Schlüssel.

---

## 2. Wie funktionieren NIP-07 Extensions? (Für Laien)

Eine NIP-07 Extension (wie diese hier oder Alby/nos2x) fungiert als **digitaler Ausweis und Unterschriftenmappe** im Browser.

### Funktionsweise
1. **Der Tresor:** Die Extension speichert den privaten Schlüssel sicher und verschlüsselt auf dem Gerät des Nutzers.
2. **Die Schnittstelle (`window.nostr`):** Die Extension stellt Webseiten ein Objekt `window.nostr` zur Verfügung. Das ist wie ein Schalter, an dem Webseiten anklopfen können.
3. **Der Türsteher:** Wenn eine Webseite (z. B. ein Blog) fragt: *"Kannst du diesen Text signieren?"*, fängt die Extension diese Anfrage ab.
4. **Die Kontrolle:** Es öffnet sich ein Fenster (Popup), und der Nutzer wird gefragt: *"Die Seite xyz.com möchte, dass du etwas unterschreibst. Erlaubst du das?"*
5. **Die Unterschrift:** Nur wenn der Nutzer "Ja" sagt, wird die Signatur erstellt und an die Webseite zurückgegeben. Der private Schlüssel selbst wird **niemals** herausgegeben.

---

## 3. Das Besondere an der WordPress-Integration

Normalerweise sind NIP-07 Extensions "dumm". Sie kennen keine vertrauenswürdigen Seiten und fragen den Nutzer bei jeder neuen Domain erneut um Erlaubnis. Zudem ist das Backup des Schlüssels alleinige Sache des Nutzers (Zettelwirtschaft).

Diese Extension ändert das durch das Konzept der **Primary Domain**.

### A. WordPress als Vertrauensanker (Primary Domain)
Der Nutzer verknüpft die Extension einmalig mit seiner "Heimat"-WordPress-Instanz.
- **Automatische Whitelist:** WordPress sendet der Extension regelmäßig eine Liste vertrauenswürdiger Domains (z. B. alle Projektseiten des Unternehmens).
- **Sicherheit:** Diese Liste ist kryptografisch signiert (HMAC). Die Extension akzeptiert sie nur, wenn die Signatur stimmt.
- **Vorteil:** Der Nutzer muss nicht auf jeder Firmen-Webseite einzeln bestätigen. Es fühlt sich an wie Single-Sign-On (SSO).

### B. Cloud-Backup ohne Risiko
Die Extension kann ein verschlüsseltes Backup des Schlüssels in WordPress speichern.
- Der Schlüssel wird **im Browser** verschlüsselt (mit einem Passkey oder Wiederherstellungscode).
- WordPress speichert nur den "Datensalat" (Blob).
- WordPress kann den Schlüssel **nicht** lesen (Zero-Knowledge).
- Geht der PC kaputt, lädt man den Blob aus WordPress und entschlüsselt ihn lokal wieder.

### C. Nahtlose Erkennung
Das WordPress-Plugin erkennt automatisch, ob die Extension installiert ist. Falls nicht, bietet es dem Nutzer direkt die Installation an und führt ihn durch das Setup.

---

## 4. Praxis-Szenario: Bildungscommunity & edufeed

Um den Nutzen dieser Architektur greifbar zu machen, betrachten wir ein konkretes Beispiel: Eine Bildungscommunity, die Inhalte (OER) erstellt und über das BMBF-geförderte Projekt "edufeed" vernetzt.

**Die Ausgangslage:**
*   **Die Basis:** Eine WordPress-Plattform, auf der Lehrkräfte Inhalte erstellen.
*   **Das Ziel:** Inhalte sollen nicht im "Silo" WordPress bleiben, sondern über das Nostr-Protokoll im edufeed-Netzwerk geteilt und diskutiert werden.

**Der Ablauf für die Lehrkraft (Nutzerreise):**

1.  **Login im vertrauten Raum:**
    Die Lehrkraft meldet sich ganz normal an ihrer WordPress-Bildungsplattform an.

2.  **Nahtlose Identitäts-Erstellung:**
    Das System erkennt: "Nutzer hat noch keine Nostr-ID". Die Extension wird installiert und generiert im Hintergrund sicher die Schlüssel.
    *   *Vorteil:* Die Lehrkraft muss nichts über Kryptografie wissen.

3.  **Verifikation & Reputation (NIP-05):**
    WordPress verknüpft den neuen Schlüssel automatisch mit dem Benutzerkonto.
    *   Auf Nostr erscheint die Lehrkraft nun **verifiziert** als: `lehrerin_anna@bildungscommunity.de`.
    *   Im gesamten edufeed-Netzwerk ist sofort erkennbar: Diese Person gehört offiziell zur Bildungscommunity.

4.  **Inhalte teilen (OER-Distribution):**
    Erstellt die Lehrkraft einen Inhalt in WordPress, signiert die Extension diesen digital.
    *   Der Inhalt wird an **edufeed** gesendet.
    *   Da er signiert ist, ist die Urheberschaft mathematisch beweisbar und fälschungssicher.

5.  **Teilnahme am Diskurs:**
    Die Community nutzt ein Nostr-basiertes Forum.
    *   Die Lehrkraft muss keinen neuen Account erstellen.
    *   Die Extension loggt sie automatisch ein.
    *   Sie diskutiert mit ihrer verifizierten Identität (`@bildungscommunity.de`), auch mit Nutzern anderer Plattformen.

**Fazit des Szenarios:**
WordPress dient als **Heimat und Vertrauensanker** (Identity Provider). Nostr dient als **offener Verteilungsraum**. Die Extension ist der **Schlüssel**, der beides sicher verbindet.

---

## 5. Abstraktion: Forking für KeyCloak (oder andere IdPs)

Die Architektur dieses Projekts ist modular aufgebaut. Die Extension ist der **Client**, WordPress ist das **Backend**. Um dies für KeyCloak (einen verbreiteten Open-Source Identity Provider) zu nutzen, muss lediglich das Backend ausgetauscht und der Client minimal konfiguriert werden.

### Architektur-Überblick

```text
┌──────────────────────┐          ┌──────────────────────┐
│   Browser Extension  │          │   Identity Backend   │
│      (Der Client)    │◄────────►│ (WP Plugin / KeyCloak)│
└──────────┬───────────┘          └──────────┬───────────┘
           │                                 │
           │ 1. API-Vertrag (REST)           │
           └─────────────────────────────────┘
```

### Der API-Vertrag (Was das Backend liefern muss)

Damit die Extension mit einem anderen Backend funktioniert, muss dieses folgende REST-Endpunkte bereitstellen (Beispiele):

> **Hinweis:** Eine vollständige technische Spezifikation aller Endpunkte und Parameter finden Sie in der [API-Referenz](API-Referenz.md).

1.  **`GET /domains`**
    *   **Zweck:** Liefert die Whitelist der erlaubten URLs.
    *   **Format:** JSON mit `domains` (Array), `updated` (Timestamp) und `signature` (HMAC-SHA256).
    *   **KeyCloak-Umsetzung:** Ein KeyCloak-Plugin (SPI), das die "Allowed Web Origins" eines Clients ausliest und signiert zurückgibt.

2.  **`POST /register`**
    *   **Zweck:** Verknüpft den öffentlichen Schlüssel (Npub) mit dem eingeloggten User.
    *   **KeyCloak-Umsetzung:** Speichern des Pubkeys als User-Attribut.

3.  **`POST /backup/*`** (Optional)
    *   **Zweck:** Speichern/Laden des verschlüsselten Key-Backups.
    *   **KeyCloak-Umsetzung:** Speichern des Blobs in einem benutzerdefinierten Speicher oder User-Attribut.

### Schritt-für-Schritt zum KeyCloak-Fork

Um dieses Repo für KeyCloak anzupassen, sind folgende Schritte nötig:

#### 1. Extension anpassen (Client)
Der Code der Extension ist zu 95% wiederverwendbar (Kryptografie, UI, Speicherverwaltung).
*   **Anpassung:** In `src/background.js` und `src/lib/domain-access.js` muss die Logik für die API-URLs konfigurierbar gemacht werden.
*   **Konfiguration:** Statt fest auf `/wp-json/nostr/v1/` zu zeigen, könnte die Base-URL in den Extension-Settings hinterlegt werden (z. B. `https://auth.example.com/realms/myrealm/nostr-extension`).

#### 2. KeyCloak Extension schreiben (Server)
Anstatt des WordPress-Plugins (`wp-nostr-integration.php`) schreibt man eine KeyCloak Extension (Java/Kotlin).
*   Diese Extension implementiert `RealmResourceProvider`.
*   Sie stellt die oben genannten Endpunkte bereit.
*   Sie nutzt das KeyCloak-interne Session-Management, um sicherzustellen, dass nur eingeloggte User Schlüssel registrieren oder Backups laden können.

### Aufwandsabschätzung

*   **Extension (Frontend):** Geringer Aufwand. Hauptsächlich Umbenennung (Branding) und Konfiguration der API-Pfade.
*   **KeyCloak (Backend):** Mittlerer Aufwand. Ein Java-Entwickler muss die REST-Endpunkte in KeyCloak nachbauen, die im WordPress-PHP-Code bereits definiert sind. Die Logik (Signaturprüfung, Datenhaltung) ist jedoch identisch.

---

## Zusammenfassung

Dieses Projekt liefert nicht nur eine WordPress-Lösung, sondern eine **Blaupause für unternehmensweite Identitätsverwaltung mit Nostr**.

*   **Kern:** Eine sichere Browser-Extension für Key-Management.
*   **Integration:** Ein Protokoll zur Synchronisation von Vertrauen (Whitelists) und Daten (Backups) zwischen Browser und Server.

Durch Austausch des Server-Parts (WordPress Plugin) gegen einen Adapter für KeyCloak, Auth0 oder Okta kann diese Lösung in jede moderne IT-Infrastruktur integriert werden.