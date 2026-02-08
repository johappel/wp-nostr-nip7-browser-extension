# TASK-05: Multi-Domain Whitelist Management

## Ziel
Automatische Synchronisation erlaubter Domains über alle WordPress-Instanzen.

## Abhängigkeiten
- **TASK-02: WordPress Integration & Detection**

## Ergebnis
- Admin kann Domains in WordPress verwalten
- Extension aktualisiert Whitelist automatisch (alle 5 Minuten)

---

## Code für background.js

```javascript
// Domain Sync
async function syncDomainsFromAllSites() {
  const { wordpressSites = [], allowedDomains = [] } = 
    await chrome.storage.local.get(['wordpressSites', 'allowedDomains']);
  
  const allDomains = new Set(allowedDomains);
  
  for (const siteUrl of wordpressSites) {
    try {
      const response = await fetch(`${siteUrl}/wp-json/nostr/v1/domains`);
      const data = await response.json();
      if (data.domains) {
        data.domains.forEach(d => allDomains.add(d));
      }
    } catch (e) {
      console.error(`Failed to sync from ${siteUrl}:`, e);
    }
  }

  await chrome.storage.local.set({
    allowedDomains: Array.from(allDomains),
    lastDomainSync: Date.now()
  });
}

// Alarm alle 5 Minuten
chrome.alarms.create('domainSync', { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'domainSync') syncDomainsFromAllSites();
});
```

## Akzeptanzkriterien

- [ ] Domains werden synchronisiert
- [ ] User kann manuell Domains hinzufügen
- [ ] Sync alle 5 Minuten
