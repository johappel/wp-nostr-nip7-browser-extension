# TASK-12: Primary-Domain Auth Broker (WebAuthn Assertion)

## Ziel
Passkey-Assertions sollen ueber eine stabile Primary-Domain-Origin laufen, auch wenn der User auf unterschiedlichen Projekt-Domains startet.

## Warum
1. Browser verhalten sich bei Passkeys je nach Origin unterschiedlich.
2. Eine feste Broker-Origin verbessert Wiedererkennung lokaler Passkeys.
3. Die Extension kann Domain-gebundenen Kontext behalten und trotzdem eine zentrale RP nutzen.

## Implementiert
1. Neue WP REST Endpunkte:
   - `POST /wp-json/nostr/v1/webauthn/assert/challenge`
   - `POST /wp-json/nostr/v1/webauthn/assert/verify`
2. Neue Broker-Seite:
   - `/?nostr_auth_broker=1`
   - rendert `nostr-auth-broker.js`
3. WP Admin Settings:
   - `nostr_auth_broker_enabled`
   - `nostr_auth_broker_origin`
   - `nostr_auth_broker_rp_id`
   - `nostr_auth_broker_dev_mode_unverified`
4. Extension-Kontext:
   - `nostrConfig` enthaelt `authBroker*` Felder.
   - DOM-Marker + Content-Script transportieren Broker-Infos ins Popup.
   - Domain-Sync speichert Broker-Config pro Primary-Domain.
5. Passkey Unlock Flow:
   - `dialog.js` nutzt optional Broker-Handshake (`READY -> ASSERT_REQUEST -> ASSERT_RESULT`).
   - Lokaler Passkey-Flow bleibt als Fallback aktiv.
6. Cloud Backup/Restore:
   - uebergibt Broker-Kontext an den Passkey-Unlock.
7. Sicherheitsgurt im Runtime-Flow:
   - Broker-Nutzung ist aktuell Opt-in (`useAuthBroker=1`) statt Default.
   - Standard bleibt lokaler Passkey-Unlock, bis Credential-Enrollment fuer Broker produktiv vorhanden ist.
8. Robustheit beim lokalen Unlock:
   - Unlock versucht zuerst die gespeicherte Credential-ID.
   - Bei typischen Fehlern (`NotAllowedError`, `UnknownError`, transient) erfolgt genau ein Discoverable-Fallback.
   - Erfolgreich gefundene Credential-ID wird im aktiven Scope wieder gespeichert (self-healing).

## Aktueller Sicherheitsstatus
1. Challenge/Origin-Checks sind serverseitig aktiv.
2. Vollstaendige WebAuthn-Signaturpruefung ist noch nicht produktiv implementiert.
3. Fuer Integrationstests gibt es `dev_mode_unverified` (nur Testbetrieb).

## Offene Arbeit (Produktionsreife)
1. Serverseitige Verifikation von:
   - `authenticatorData` (RP-ID Hash, Flags, SignCount)
   - `signature` gegen gespeicherten PublicKey des Credentials
2. Credential-Registrierung und persistente Credential-Verwaltung pro WP-User.
3. Token-Hardening:
   - kuerzere Lebenszeit
   - audience binding
   - nonce replay protection

## Akzeptanzkriterien
1. Broker kann in WP aktiviert/konfiguriert werden.
2. Extension kann bei Passkey-Unlock den Broker-Pfad nutzen.
3. Bei fehlendem Broker oder Fehlern bleibt lokaler Fallback funktionsfaehig.
4. Cloud Backup/Restore laeuft mit Broker-basierter Passkey-Bestaetigung.
