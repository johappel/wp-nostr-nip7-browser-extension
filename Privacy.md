# Datenschutzerklaerung (Chrome Dashboard) - WP Nostr Signer

Stand: 13. Februar 2026

## Allgemeine Beschreibung
Die Erweiterung ist fuer den Einsatz im Rahmen eines geplanten WordPress-Auftritts vorgesehen. Sie stellt die NIP-07 Bridge im Browser bereit, verbindet WordPress-REST-Endpunkte der vom Nutzer verwendeten Domain mit der lokalen Signer-Funktion und nutzt Nostr-Relay-Verbindungen (WebSocket) fuer Nostr-Funktionen wie Profilabgleich, Kontakte und Direktnachrichten. Domain-Zugriffe werden dabei ueber Whitelist und Nutzerbestaetigung kontrolliert.

## Beschreibung Alleiniger Zweck
Die Erweiterung stellt einen lokalen NIP-07 Signer bereit, damit Nutzer auf WordPress- und Nostr-Webseiten ihre Nostr-Identitaet sicher verwenden koennen (Signieren, Verschluesseln/Entschluesseln, Kontakt- und DM-Funktionen) und Domain-Zugriffe kontrolliert freigeben koennen.

## Begruendung fuer Berechtigungen

### `storage`
Wird fuer die lokale Speicherung benoetigt: Schluesselmaterial (verschluesselt oder unverschluesselt je nach Nutzerwahl), Schutzmodus, Domain-Whitelist/Blocklist, UI-Einstellungen, Kontakt-/DM-Cache und technische Zustandsdaten.

### `activeTab`
Wird genutzt, um den aktuell aktiven Tab zu lesen (Origin/Tab-ID) und den WordPress-Kontext im aktiven Tab gezielt abzufragen. Kein Auslesen kompletter Browser-Historie.

### `alarms`
Wird fuer wiederkehrende Hintergrundaufgaben genutzt:
- Domain-Sync mit der Primary-Domain-Whitelist
- Relay-Keepalive bei MV3 Service Worker
- periodisches DM-Polling als Fallback

### `notifications`
Wird fuer lokale Desktop-Benachrichtigungen bei neuen Direktnachrichten genutzt (optional abschaltbar).

### `sidePanel`
Wird verwendet, um die Erweiterungs-UI alternativ zum Popup im Browser-Seitenpanel zu oeffnen.

### Begruendung fuer Hostberechtigung (`http://*/*`, `https://*/*`)
Die Erweiterung injiziert die NIP-07 Bridge in Webseitenkontexte und muss WordPress-REST-Endpunkte auf den vom Nutzer verwendeten Domains erreichen. Zudem werden Nostr-Relay-Verbindungen (WebSocket) zu konfigurierten Relays aufgebaut. Die Domainfreigabe wird intern durch Whitelist/Benutzerbestaetigung begrenzt.

## Nutzt die Extension Remote Code?
Nein. Die Erweiterung laedt oder evaluiert keinen externen JavaScript-Code zur Laufzeit (kein `eval`, kein `new Function`, kein Remote-Script-Import). Netzwerkzugriffe dienen nur dem Datenaustausch mit WordPress-APIs und Nostr-Relays.

## Welche Nutzerdaten werden erfasst

| Datenkategorie | Erfasst | Zweck / Umfang |
|---|---|---|
| Personenidentifizierbare Informationen | Ja (eingeschraenkt) | Aus WordPress-Kontext koennen z. B. `displayName`, `userLogin`, `avatarUrl`, `userId`, `pubkey`, `nip05` verarbeitet werden. Nutzung fuer UI, Scope-Zuordnung, Registrierung und optionale Kontaktanzeige. |
| Gesundheitsinformationen | Nein | Keine Erfassung oder Verarbeitung. |
| Finanzdaten und Zahlungsinformationen | Nein | Keine Erfassung oder Verarbeitung. |
| Authentifizierungsdaten | Ja | Nostr-Private-Key (lokal), Schutzdaten (Passwort- oder Passkey-Modus), Passkey-Credential-ID/Fingerprint fuer Backup-Funktionen, sowie WordPress-Nonce im laufenden API-Kontext. |
| Persoenliche Kommunikation | Ja (wenn DM-Funktion genutzt wird) | Direktnachrichten werden fuer Versand/Empfang verarbeitet, lokal zwischengespeichert und als Vorschau in Benachrichtigungen angezeigt. |
| Ort | Nein (direkt) | Keine GPS-/Standortabfrage. Netzwerkbedingt sehen angebundene Server/Relays technisch die IP-Adresse, die Erweiterung erhebt keine separate Standortmetrik. |
| Webprotokoll | Ja (eingeschraenkt) | Gespeichert werden benoetigte Domain-/Origin-Informationen (z. B. aktive Seite, erlaubte/gesperrte Domains). Keine allgemeine Surf-Historie. |
| Nutzeraktivitaet | Ja (eingeschraenkt) | Verarbeitet werden nur funktionsbezogene Interaktionen in der Erweiterung (z. B. Freigaben, Einstellungen, Signaturbestaetigungen), keine Telemetrie/Tracking ueber Webseitenaktivitaet. |
| Websitecontent | Ja (eingeschraenkt) | Inhalte aus Nostr-Anfragen der Webseite (z. B. Event-Payload fuer Signieren/Verschluesseln/Entschluesseln) werden zur Funktionsausfuehrung verarbeitet. |

## Weitergabe / Verkauf
- Kein Verkauf personenbezogener Daten.
- Keine Werbe- oder Analytics-Telemetrie an den Erweiterungsentwickler.
- Datenuebertragungen erfolgen nur funktional an:
  - die jeweils genutzte WordPress-Instanz (REST-API, optional Backup/Domain-Sync)
  - vom Nutzer konfigurierte oder standardmaessig verwendete Nostr-Relays
