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
    this.init();
  }

  async init() {
    // Nur fuer eingeloggte User
    if (!this.config.isLoggedIn) {
      return;
    }

    // 1. Extension Detection
    this.hasExtension = await this.detectExtension();
    if (!this.hasExtension) {
      // Race beim Seitenstart abfangen: NIP-07 API kann kurz spaeter erscheinen.
      await this.waitForNostrApi(3000, 120);
      this.hasExtension = this.isNostrApiAvailable();
    }

    if (!this.hasExtension) {
      this.showInstallPrompt();
      return;
    }

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
  }

  async detectExtension() {
    return new Promise((resolve) => {
      const requestId = `detect-${this.createRequestId()}`;
      window.postMessage({ type: 'NOSTR_PING', _id: requestId }, '*');

      const handler = (e) => {
        if (e.data.type === 'NOSTR_PING_RESPONSE' && e.data._id === requestId) {
          window.removeEventListener('message', handler);
          if (e.data.error) {
            resolve(false);
            return;
          }
          console.log('[Nostr] Extension detected');
          resolve(true);
        }
      };

      window.addEventListener('message', handler);

      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve(this.isNostrApiAvailable());
      }, 800);
    });
  }

  async configureDomainSync() {
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
        if (e.data.type === type + '_RESPONSE' && e.data._id === id) {
          cleanup();
          if (e.data.error) reject(new Error(e.data.error));
          else resolve(e.data.result);
        }
      };

      const timeout = setTimeout(() => {
        if (!finished) {
          cleanup();
          reject(new Error('Extension response timeout'));
        }
      }, timeoutMs);

      window.addEventListener('message', handler);
      window.postMessage({ type, payload, _id: id }, '*');
    });
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

  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  showInstallPrompt() {
    const storeUrl = this.config.extensionStoreUrl ||
      'https://chrome.google.com/webstore/detail/[EXTENSION_ID]';

    const modal = document.createElement('div');
    modal.id = 'nostr-install-modal';
    modal.innerHTML = `
      <div class="nostr-modal-backdrop">
        <div class="nostr-modal">
          <h3>Nostr Signer erforderlich</h3>
          <p>Fuer die sichere Anmeldung mit Nostr benoetigst du unsere Browser Extension.</p>

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
              Extension installieren
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
      const hexPubkey = await window.nostr.getPublicKey();

      const response = await fetch(`${this.config.restUrl}register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WP-Nonce': this.config.nonce
        },
        body: JSON.stringify({ pubkey: hexPubkey })
      });

      const result = await response.json();

      if (response.ok && result.success) {
        this.showRegistrationSuccess();
        document.getElementById('nostr-register-container')?.remove();
      } else {
        throw new Error(result.message || 'Registrierung fehlgeschlagen');
      }
    } catch (error) {
      console.error('[Nostr] Registration failed:', error);
      this.showError(error.message);
      btn.disabled = false;
      btn.textContent = 'Mit Nostr verknuepfen';
    }
  }

  async verifyExistingUser(expectedPubkey) {
    try {
      const currentPubkey = await window.nostr.getPublicKey();
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

    const warning = document.createElement('div');
    warning.className = 'nostr-warning';
    warning.innerHTML = `
      <p>Dein Nostr-Schluessel stimmt nicht mit dem registrierten Schluessel ueberein.</p>
      <p>Bitte pruefe, ob du die richtige Extension verwendest.</p>
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
    error.innerHTML = `<p>Fehler: ${message}</p>`;

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
