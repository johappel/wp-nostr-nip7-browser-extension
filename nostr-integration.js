/**
 * Nostr WordPress Integration
 * Erkennt NIP-07 Extension und ermoeglicht Registrierung
 */
class NostrWPIntegration {
  constructor() {
    const legacyConfigObject = (
      window.nostrWP &&
      typeof window.nostrWP === 'object' &&
      typeof window.nostrWP.configureDomainSync !== 'function'
    ) ? window.nostrWP : null;

    this.config = window.nostrConfig || legacyConfigObject || {};
    this.hasExtension = false;
    this.npub = null;
    this.flowPromise = null;
    this.extensionRecoveryActive = false;
    this.publishViewerContext();
    this.init();
  }

  isWpLoggedIn() {
    return this.config.isLoggedIn === true
      || this.config.isLoggedIn === 1
      || this.config.isLoggedIn === '1';
  }

  publishViewerContext() {
    const root = document.documentElement;
    if (!root) return;

    root.setAttribute('data-wp-nostr-config-ready', '1');

    const rawUserId = Number(this.config.wpUserId || this.config.userId || 0);
    const userId = Number.isInteger(rawUserId) && rawUserId > 0 ? rawUserId : null;
    const isLoggedIn = this.isWpLoggedIn() && userId !== null;

    if (!isLoggedIn) {
      root.removeAttribute('data-wp-nostr-user-id');
      root.removeAttribute('data-wp-nostr-display-name');
      root.removeAttribute('data-wp-nostr-avatar-url');
      root.removeAttribute('data-wp-nostr-pubkey');
      return;
    }

    root.setAttribute('data-wp-nostr-user-id', String(userId));
    root.setAttribute('data-wp-nostr-display-name', String(this.config.wpDisplayName || ''));
    root.setAttribute('data-wp-nostr-avatar-url', String(this.config.wpAvatarUrl || ''));
    root.setAttribute('data-wp-nostr-pubkey', String(this.config.wpPubkey || ''));
  }

  async init() {
    // Nur fuer eingeloggte User
    if (!this.isWpLoggedIn()) {
      return;
    }

    // 1. Extension Detection
    this.hasExtension = await this.detectExtension();
    if (!this.hasExtension) {
      // Race beim Seitenstart abfangen: Bridge/API kann kurz spaeter erscheinen.
      await this.waitForExtensionAvailability(3000, 120);
      this.hasExtension = await this.detectExtension();
    }

    if (!this.hasExtension) {
      this.showInstallPrompt();
      this.startExtensionRecoveryWatcher();
      return;
    }

    await this.runMainFlow();
  }

  async detectExtension() {
    if (this.isRequiredExtensionAvailable()) {
      return true;
    }

    try {
      const result = await this.sendExtensionMessage('NOSTR_PING', null, 1500);
      if (result && result.pong === true) {
        console.log('[Nostr] Extension detected');
        return true;
      }
    } catch {
      // handled by fallback checks below
    }

    return this.isRequiredExtensionAvailable();
  }

  async runMainFlow() {
    if (this.flowPromise) {
      return this.flowPromise;
    }

    this.flowPromise = (async () => {
      // Domain-Sync fuer Trusted Domains initialisieren
      await this.configureDomainSync();

      // 2. Pruefe ob User registriert ist
      const wpUser = await this.getCurrentWPUser();

      if (!wpUser.pubkey) {
        // 3. Registrierungs-Flow
        await this.handleRegistration();
      } else {
        // 4. Pruefe ob Npub uebereinstimmt
        await this.verifyExistingUser(wpUser.pubkey);
      }
    })();

    try {
      await this.flowPromise;
    } catch (error) {
      this.flowPromise = null;
      throw error;
    }
  }

  startExtensionRecoveryWatcher() {
    if (this.extensionRecoveryActive) {
      return;
    }
    this.extensionRecoveryActive = true;
    this.scheduleExtensionRecoveryCheck(1);
  }

  async scheduleExtensionRecoveryCheck(attempt) {
    const maxAttempts = 60; // ~30s
    if (attempt > maxAttempts) {
      this.extensionRecoveryActive = false;
      return;
    }

    let available = false;
    try {
      available = await this.detectExtension();
    } catch {
      available = false;
    }

    if (available) {
      this.extensionRecoveryActive = false;
      this.hasExtension = true;
      document.getElementById('nostr-install-modal')?.remove();
      try {
        await this.runMainFlow();
      } catch (error) {
        console.error('[Nostr] Recovery flow failed:', error);
      }
      return;
    }

    setTimeout(() => {
      this.scheduleExtensionRecoveryCheck(attempt + 1);
    }, 500);
  }

  async configureDomainSync() {
    // Domain sync is only supported with this extension's message bridge.
    if (!this.isBridgeAvailable()) {
      return;
    }

    const primaryDomain = this.config.primaryDomain || this.config.siteDomain;
    const domainSecret = this.config.domainSecret;

    if (!primaryDomain || !domainSecret) {
      console.warn('[Nostr] Domain sync config missing, skipping automatic whitelist sync');
      return;
    }

    const payload = { primaryDomain, domainSecret };
    let lastError = null;

    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const result = await this.sendExtensionMessage(
          'NOSTR_SET_DOMAIN_CONFIG',
          payload,
          3500
        );
        if (!result?.success) {
          console.warn('[Nostr] Domain sync config not acknowledged by extension');
        }
        return;
      } catch (error) {
        lastError = error;
        if (attempt < 3) {
          await this.delay(250 * attempt);
        }
      }
    }

    console.warn('[Nostr] Failed to configure domain sync:', lastError);
  }

  async sendExtensionMessage(type, payload = null, timeoutMs = 1000) {
    return new Promise((resolve, reject) => {
      const id = this.createRequestId();
      let finished = false;

      const cleanup = () => {
        finished = true;
        window.removeEventListener('message', handler);
        clearTimeout(timeout);
      };

      const handler = (e) => {
        const data = e?.data;
        if (!data || typeof data !== 'object') return;

        if (data.type === type + '_RESPONSE' && data._id === id) {
          cleanup();
          if (data.error) reject(new Error(data.error));
          else resolve(data.result);
        }
      };

      const timeout = setTimeout(() => {
        if (!finished) {
          cleanup();
          reject(new Error('Extension response timeout'));
        }
      }, timeoutMs);

      window.addEventListener('message', handler);
      const message = { type, payload, _id: id };
      const scope = this.getSignerScope();
      if (scope) {
        message.scope = scope;
      }
      window.postMessage(message, '*');
    });
  }

  getSignerScope() {
    const rawUserId = Number(this.config.wpUserId || this.config.userId || 0);
    if (!Number.isInteger(rawUserId) || rawUserId <= 0) return null;
    const host = String(window.location.host || '').trim().toLowerCase();
    if (!host) return null;
    return `wp:${host}:u:${rawUserId}`;
  }

  createRequestId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    }
    return `req-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  isNostrApiAvailable() {
    const nostrApi = window.nostr;
    return Boolean(nostrApi && typeof nostrApi.getPublicKey === 'function');
  }

  isManagedNostrApiAvailable() {
    const nostrApi = window.nostr;
    return Boolean(
      nostrApi &&
      typeof nostrApi.getPublicKey === 'function' &&
      nostrApi.__wpNostrManaged === true
    );
  }

  isRequiredExtensionAvailable() {
    return this.isBridgeAvailable() || this.isManagedNostrApiAvailable();
  }

  hasOtherNip07Signer() {
    return this.isNostrApiAvailable() && !this.isManagedNostrApiAvailable();
  }

  isBridgeAvailable() {
    return document.documentElement?.getAttribute('data-wp-nostr-extension-bridge') === '1';
  }

  async waitForNostrApi(maxWaitMs = 3000, intervalMs = 120) {
    const start = Date.now();
    while ((Date.now() - start) < maxWaitMs) {
      if (this.isNostrApiAvailable()) {
        return true;
      }
      await this.delay(intervalMs);
    }
    return false;
  }

  async waitForExtensionAvailability(maxWaitMs = 3000, intervalMs = 120) {
    const start = Date.now();
    while ((Date.now() - start) < maxWaitMs) {
      if (this.isRequiredExtensionAvailable()) {
        return true;
      }
      await this.delay(intervalMs);
    }
    return false;
  }

  isFirefoxBrowser() {
    return /firefox\//i.test(navigator.userAgent || '');
  }

  getInstallStoreUrl() {
    const defaultChromeStoreUrl = 'https://chrome.google.com/webstore/detail/[EXTENSION_ID]';
    const defaultFirefoxStoreUrl = 'https://addons.mozilla.org/firefox/addon/[ADDON_SLUG]';
    const legacyStoreUrl = String(this.config.extensionStoreUrl || '').trim();

    if (this.isFirefoxBrowser()) {
      const firefoxStoreUrl = String(this.config.extensionStoreUrlFirefox || '').trim();
      if (firefoxStoreUrl) return firefoxStoreUrl;
      if (legacyStoreUrl && !/chrome\.google\.com\/webstore/i.test(legacyStoreUrl)) {
        return legacyStoreUrl;
      }
      return defaultFirefoxStoreUrl;
    }

    const chromeStoreUrl = String(this.config.extensionStoreUrlChrome || '').trim();
    if (chromeStoreUrl) return chromeStoreUrl;
    if (legacyStoreUrl) return legacyStoreUrl;
    return defaultChromeStoreUrl;
  }

  async getPublicKey() {
    // Prefer our managed signer API if it is active.
    if (this.isManagedNostrApiAvailable()) {
      return await window.nostr.getPublicKey();
    }

    // If bridge is available, force bridge path to avoid taking keys from third-party signers.
    if (this.isBridgeAvailable()) {
      const pubkey = await this.sendExtensionMessage('NOSTR_GET_PUBLIC_KEY', null, 30000);
      if (typeof pubkey !== 'string' || pubkey.length < 10) {
        throw new Error('Extension returned invalid public key');
      }
      return pubkey;
    }

    // Fallback only when no bridge exists.
    if (this.isNostrApiAvailable()) {
      return await window.nostr.getPublicKey();
    }

    if (!this.hasExtension && !this.isBridgeAvailable()) {
      throw new Error('Nostr extension bridge is not available');
    }

    throw new Error('No compatible Nostr signer available');
  }

  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  showInstallPrompt() {
    // Last-minute guard against stale detection state.
    if (this.isRequiredExtensionAvailable()) {
      return;
    }

    if (document.getElementById('nostr-install-modal')) {
      return;
    }

    const storeUrl = this.getInstallStoreUrl();
    const hasOtherSigner = this.hasOtherNip07Signer();
    const title = hasOtherSigner
      ? 'wp-nostr Signer erforderlich'
      : 'Nostr Signer erforderlich';
    const introText = hasOtherSigner
      ? 'Ein anderer NIP-07 Signer wurde erkannt. Fuer diese WordPress-Integration wird die wp-nostr Browser Extension benoetigt.'
      : 'Fuer die sichere Anmeldung mit Nostr benoetigst du unsere Browser Extension.';
    const signerHint = hasOtherSigner
      ? '<p class="nostr-modal-hint">Hinweis: Vorhandene Signer bleiben nutzbar, aber Domain-Sync und nahtlose WP-Integration funktionieren nur mit wp-nostr.</p>'
      : '';

    const modal = document.createElement('div');
    modal.id = 'nostr-install-modal';
    modal.innerHTML = `
      <div class="nostr-modal-backdrop">
        <div class="nostr-modal">
          <h3>${title}</h3>
          <p>${introText}</p>
          ${signerHint}

          <div class="install-steps">
            <ol>
              <li>Extension aus dem Store herunterladen</li>
              <li>Extension installieren</li>
              <li>Diese Seite neu laden</li>
            </ol>
          </div>

          <div class="nostr-modal-actions">
            <a href="${storeUrl}"
               target="_blank"
               rel="noopener noreferrer"
               class="nostr-btn nostr-btn-primary">
              wp-nostr installieren
            </a>

            <button class="nostr-btn nostr-btn-secondary" id="nostr-dismiss">
              Spaeter erinnern
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('nostr-dismiss').onclick = () => {
      modal.remove();
      sessionStorage.setItem('nostr_install_dismissed', 'true');
    };

    if (sessionStorage.getItem('nostr_install_dismissed') === 'true') {
      modal.remove();
    }
  }

  async handleRegistration() {
    try {
      this.showRegistrationUI();
    } catch (error) {
      console.error('[Nostr] Registration setup failed:', error);
    }
  }

  showRegistrationUI() {
    if (document.getElementById('nostr-register-btn')) {
      return;
    }

    const container = document.createElement('div');
    container.id = 'nostr-register-container';
    container.innerHTML = `
      <div class="nostr-register-prompt">
        <p>Verknuepfe deinen Nostr-Account mit deinem WordPress-Profil</p>
        <button id="nostr-register-btn" class="nostr-btn nostr-btn-primary">
          Mit Nostr verknuepfen
        </button>
      </div>
    `;

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(container, target.firstChild);

    document.getElementById('nostr-register-btn').onclick = async () => {
      await this.performRegistration();
    };
  }

  async performRegistration() {
    const btn = document.getElementById('nostr-register-btn');
    btn.disabled = true;
    btn.textContent = 'Registriere...';

    try {
      const hexPubkey = await this.getPublicKey();

      const response = await fetch(`${this.config.restUrl}register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WP-Nonce': this.config.nonce
        },
        body: JSON.stringify({ pubkey: hexPubkey })
      });

      let result = {};
      try {
        result = await response.json();
      } catch {
        result = {};
      }

      if (response.ok && result.success) {
        this.showRegistrationSuccess();
        document.getElementById('nostr-register-container')?.remove();
      } else {
        throw new Error(this.formatRegistrationError(response, result, hexPubkey));
      }
    } catch (error) {
      console.error('[Nostr] Registration failed:', error);
      this.showError(error.message);
      btn.disabled = false;
      btn.textContent = 'Mit Nostr verknuepfen';
    }
  }

  formatRegistrationError(response, result, attemptedPubkey) {
    const status = Number(response?.status || 0);
    const code = String(result?.code || '').trim();
    const message = String(result?.message || '').trim();
    const shortKey = this.formatShortPubkey(attemptedPubkey);

    if (status === 409 && code === 'pubkey_in_use') {
      return [
        'Dieser Pubkey ist bereits einem anderen Account zugeordnet.',
        `Verwendeter Signer-Pubkey: ${shortKey}`,
        'Bitte den richtigen Schluessel fuer diesen WP-User in der Extension waehlen oder importieren.'
      ].join('\n');
    }

    if (status === 409 && code === 'pubkey_already_registered') {
      const currentPubkey = String(result?.data?.currentPubkey || '').trim();
      const currentInfo = currentPubkey
        ? `Aktuell registriert: ${this.formatShortPubkey(currentPubkey)}`
        : 'Fuer diesen Account ist bereits ein anderer Pubkey registriert.';
      return [
        currentInfo,
        `Vom Signer geliefert: ${shortKey}`,
        'Bitte bewusst Key-Rotation durchfuehren statt still zu ueberschreiben.'
      ].join('\n');
    }

    if (status === 401 || status === 403) {
      return 'WordPress-Session ist nicht mehr gueltig. Bitte Seite neu laden und erneut anmelden.';
    }

    return message || `Registrierung fehlgeschlagen (HTTP ${status || 'unknown'}).`;
  }

  formatShortPubkey(pubkey) {
    const value = String(pubkey || '').trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(value)) return value || '(unbekannt)';
    return `${value.slice(0, 12)}...${value.slice(-8)}`;
  }

  async verifyExistingUser(expectedPubkey) {
    // Avoid unexpected signer popups for third-party NIP-07 providers.
    // Automatic verification is only safe with our own bridge-based extension.
    if (!this.isBridgeAvailable()) {
      console.info('[Nostr] Skipping automatic key verification (no wp-nostr bridge detected)');
      return;
    }

    try {
      const currentPubkey = await this.getPublicKey();
      if (currentPubkey !== expectedPubkey) {
        this.showKeyMismatchWarning(expectedPubkey, currentPubkey);
      } else {
        console.log('[Nostr] Key verified successfully');
        this.showVerifiedStatus();
      }
    } catch (error) {
      console.error('[Nostr] Verification failed:', error);
    }
  }

  showKeyMismatchWarning(expected, actual) {
    console.warn('[Nostr] Key mismatch:', { expected, actual });
    const expectedShort = this.formatShortPubkey(expected);
    const actualShort = this.formatShortPubkey(actual);

    const warning = document.createElement('div');
    warning.className = 'nostr-warning';
    warning.innerHTML = `
      <p>Dein Nostr-Schluessel stimmt nicht mit dem registrierten Schluessel ueberein.</p>
      <p>Registriert: <code>${expectedShort}</code></p>
      <p>Aktueller Browser: <code>${actualShort}</code></p>
      <p>Bitte denselben privaten Schluessel in beiden Browsern importieren (Backup/Restore), damit beide dieselbe Identitaet nutzen.</p>
    `;

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(warning, target.firstChild);
  }

  showRegistrationSuccess() {
    const success = document.createElement('div');
    success.className = 'nostr-success';
    success.innerHTML = `
      <p>Dein Nostr-Account wurde erfolgreich verknuepft!</p>
    `;

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(success, target.firstChild);

    setTimeout(() => success.remove(), 5000);
  }

  showVerifiedStatus() {
    const badge = document.createElement('div');
    badge.className = 'nostr-verified-badge';
    badge.innerHTML = 'Nostr verifiziert';
    badge.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#4CAF50;color:white;padding:8px 16px;border-radius:4px;font-size:14px;z-index:9999;';
    document.body.appendChild(badge);

    setTimeout(() => badge.remove(), 3000);
  }

  showError(message) {
    const error = document.createElement('div');
    error.className = 'nostr-error';
    const paragraph = document.createElement('p');
    paragraph.textContent = `Fehler: ${String(message || 'Unbekannter Fehler')}`;
    paragraph.style.whiteSpace = 'pre-line';
    error.appendChild(paragraph);

    const container = document.getElementById('nostr-register-container');
    if (container) {
      container.insertBefore(error, container.firstChild);
      setTimeout(() => error.remove(), 5000);
    }
  }

  async getCurrentWPUser() {
    try {
      const response = await fetch(`${this.config.restUrl}user`, {
        headers: { 'X-WP-Nonce': this.config.nonce }
      });
      return await response.json();
    } catch (error) {
      console.error('[Nostr] Failed to get user:', error);
      return { pubkey: null };
    }
  }
}

function initNostrWPIntegration() {
  if (window.__nostrWPIntegration) return;

  const instance = new NostrWPIntegration();
  window.__nostrWPIntegration = instance;

  // Backward compatibility: expose on window.nostrWP unless occupied by another object.
  if (!window.nostrWP || typeof window.nostrWP.configureDomainSync === 'function') {
    window.nostrWP = instance;
  }
}

// Robust gegen spaet geladenes Script (z. B. durch Caching/Optimierungs-Plugins).
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNostrWPIntegration, { once: true });
} else {
  initNostrWPIntegration();
}
