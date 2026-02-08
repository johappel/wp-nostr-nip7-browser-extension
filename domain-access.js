// Domain Access Control mit Bootstrapping

export const DOMAIN_STATUS = {
  BLOCKED: 'blocked',
  ALLOWED: 'allowed',
  PENDING: 'pending'
};

/**
 * Prüft Domain-Status
 * @param {string|null} domain - Zu prüfende Domain
 * @param {object} storage - Chrome storage API
 * @returns {Promise<string>} - DOMAIN_STATUS
 */
export async function checkDomainAccess(domain, storage = chrome.storage.local) {
  if (!domain) return DOMAIN_STATUS.BLOCKED;

  const { allowedDomains = [], blockedDomains = [] } =
    await storage.get(['allowedDomains', 'blockedDomains']);

  if (blockedDomains.includes(domain)) return DOMAIN_STATUS.BLOCKED;
  if (allowedDomains.includes(domain)) return DOMAIN_STATUS.ALLOWED;

  // Domain ist noch unbekannt -> User fragen (Bootstrapping)
  return DOMAIN_STATUS.PENDING;
}

/**
 * Fügt Domain zur Allowlist hinzu
 * @param {string} domain - Domain hinzuzufügen
 * @param {object} storage - Chrome storage API
 */
export async function allowDomain(domain, storage = chrome.storage.local) {
  const { allowedDomains = [] } = await storage.get(['allowedDomains']);
  if (!allowedDomains.includes(domain)) {
    allowedDomains.push(domain);
    await storage.set({ allowedDomains });
  }
}

/**
 * Fügt Domain zur Blocklist hinzu
 * @param {string} domain - Domain hinzuzufügen
 * @param {object} storage - Chrome storage API
 */
export async function blockDomain(domain, storage = chrome.storage.local) {
  const { blockedDomains = [] } = await storage.get(['blockedDomains']);
  if (!blockedDomains.includes(domain)) {
    blockedDomains.push(domain);
    await storage.set({ blockedDomains });
  }
}

export default checkDomainAccess;