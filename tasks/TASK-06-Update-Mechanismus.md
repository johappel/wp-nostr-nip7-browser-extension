# TASK-06: Extension Update Mechanismus

## Hinweis zum Iststand (2026-02)

Dieses Dokument ist historisch. Der früher beschriebene Message-Command `NOSTR_CHECK_VERSION` wurde entfernt.

Update-Management erfolgt aktuell über Release-Prozess (Store-Versionen, Changelog, Deployment-Checks), nicht mehr über einen dedizierten Runtime-Command.

## Ziel
Benachrichtigung über neue Versionen und forced updates bei Sicherheitskritischen Änderungen.

## Abhängigkeiten
- **TASK-02: WordPress Integration & Detection**

## WordPress Code

```javascript
async function checkExtensionVersion() {
  // Historisch (entfernt): NOSTR_CHECK_VERSION
  // Aktuell: Update-Hinweise erfolgen außerhalb des Runtime-Message-Protokolls
  // über Store-Release/Deployment-Checks.
}
```

## Extension Code (in background.js)

```javascript
// Historisch (entfernt):
// if (request.type === 'NOSTR_CHECK_VERSION') { ... }
```

## Akzeptanzkriterien (historisch)

- [ ] (historisch) WordPress kann minimale Extension-Version vorgeben
- [ ] (historisch) User wird bei veralteter Extension benachrichtigt
