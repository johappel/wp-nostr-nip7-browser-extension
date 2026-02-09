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
      root.removeAttribute('data-wp-nostr-rest-url');
      root.removeAttribute('data-wp-nostr-nonce');
      root.removeAttribute('data-wp-nostr-auth-broker-enabled');
      root.removeAttribute('data-wp-nostr-auth-broker-url');
      root.removeAttribute('data-wp-nostr-auth-broker-origin');
      root.removeAttribute('data-wp-nostr-auth-broker-rp-id');
      return;
    }

    root.setAttribute('data-wp-nostr-user-id', String(userId));
    root.setAttribute('data-wp-nostr-display-name', String(this.config.wpDisplayName || ''));
    root.setAttribute('data-wp-nostr-avatar-url', String(this.config.wpAvatarUrl || ''));
    root.setAttribute('data-wp-nostr-pubkey', String(this.config.wpPubkey || ''));
    root.setAttribute('data-wp-nostr-rest-url', String(this.config.restUrl || ''));
    root.setAttribute('data-wp-nostr-nonce', String(this.config.nonce || ''));
    root.setAttribute('data-wp-nostr-auth-broker-enabled', this.config.authBrokerEnabled ? '1' : '0');
    root.setAttribute('data-wp-nostr-auth-broker-url', String(this.config.authBrokerUrl || ''));
    root.setAttribute('data-wp-nostr-auth-broker-origin', String(this.config.authBrokerOrigin || ''));
    root.setAttribute('data-wp-nostr-auth-broker-rp-id', String(this.config.authBrokerRpId || ''));
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

    const payload = {
      primaryDomain,
      domainSecret,
      authBroker: {
        enabled: this.config.authBrokerEnabled === true
          || this.config.authBrokerEnabled === 1
          || this.config.authBrokerEnabled === '1',
        url: String(this.config.authBrokerUrl || ''),
        origin: String(this.config.authBrokerOrigin || ''),
        rpId: String(this.config.authBrokerRpId || '')
      }
    };
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

  async getPublicKey(options = {}) {
    const createIfMissing = options?.createIfMissing !== false;

    // Prefer our managed signer API if it is active.
    if (this.isManagedNostrApiAvailable()) {
      return await window.nostr.getPublicKey();
    }

    // If bridge is available, force bridge path to avoid taking keys from third-party signers.
    if (this.isBridgeAvailable()) {
      const payload = createIfMissing ? null : { createIfMissing: false };
      const pubkey = await this.sendExtensionMessage('NOSTR_GET_PUBLIC_KEY', payload, 30000);
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
        await this.tryPublishKind0Profile(hexPubkey);
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

  shouldPublishKind0OnRegister() {
    const value = this.config.publishKind0OnRegister;
    if (value === true || value === 1 || value === '1') return true;
    if (value === false || value === 0 || value === '0') return false;
    return false;
  }

  getConfiguredProfileRelays() {
    const raw = String(this.config.profileRelayUrl || '').trim();
    if (!raw) return [];

    const parts = raw.split(/[\s,;]+/g).map((entry) => entry.trim()).filter(Boolean);
    const normalized = parts
      .map((entry) => this.normalizeRelayUrl(entry))
      .filter(Boolean);

    return Array.from(new Set(normalized));
  }

  normalizeRelayUrl(input) {
    const value = String(input || '').trim();
    if (!value) return null;

    let candidate = value;
    if (/^https?:\/\//i.test(candidate)) {
      candidate = candidate.replace(/^http:\/\//i, 'ws://').replace(/^https:\/\//i, 'wss://');
    }

    if (!/^wss?:\/\//i.test(candidate)) {
      candidate = `wss://${candidate.replace(/^\/+/, '')}`;
    }

    try {
      const url = new URL(candidate);
      if (!/^wss?:$/i.test(url.protocol)) return null;
      return `${url.protocol}//${url.host}${url.pathname}${url.search}${url.hash}`;
    } catch {
      return null;
    }
  }

  createKind0ProfileContent() {
    const displayName = String(this.config.wpDisplayName || '').trim();
    const avatarUrl = String(this.config.wpAvatarUrl || '').trim();
    const nip05 = String(this.config.profileNip05 || '').trim();
    const userLogin = String(this.config.wpUserLogin || '').trim();

    const profile = {};
    if (userLogin) profile.name = userLogin;
    if (displayName) profile.display_name = displayName;
    if (avatarUrl) profile.picture = avatarUrl;
    if (nip05) profile.nip05 = nip05;
    profile.website = window.location.origin;

    return profile;
  }

  async tryPublishKind0Profile(expectedPubkey) {
    if (!this.shouldPublishKind0OnRegister()) return;

    const relays = this.getConfiguredProfileRelays();
    if (!relays.length) return;

    if (!this.isNostrApiAvailable() || typeof window.nostr.signEvent !== 'function') {
      console.warn('[Nostr] kind:0 publish skipped: signEvent API not available');
      return;
    }

    const eventTemplate = {
      kind: 0,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: JSON.stringify(this.createKind0ProfileContent())
    };

    let signed;
    try {
      signed = await window.nostr.signEvent(eventTemplate);
    } catch (error) {
      console.warn('[Nostr] kind:0 publish skipped: signing failed', error);
      return;
    }

    const signedPubkey = String(signed?.pubkey || '').toLowerCase();
    if (expectedPubkey && signedPubkey && signedPubkey !== String(expectedPubkey).toLowerCase()) {
      console.warn('[Nostr] kind:0 publish skipped: signer pubkey mismatch');
      return;
    }

    let lastError = null;
    for (const relayUrl of relays) {
      try {
        await this.publishEventToRelay(relayUrl, signed, 9000);
        console.info('[Nostr] kind:0 profile published to relay:', relayUrl);
        return;
      } catch (error) {
        lastError = error;
      }
    }

    if (lastError) {
      console.warn('[Nostr] kind:0 publish failed on all relays:', lastError);
    }
  }

  async publishEventToRelay(relayUrl, event, timeoutMs = 9000) {
    return await new Promise((resolve, reject) => {
      let settled = false;
      let socket;

      const finish = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
          try {
            socket.close();
          } catch {
            // ignore close errors
          }
        }
        if (err) reject(err);
        else resolve(true);
      };

      const timer = setTimeout(() => {
        finish(new Error('Relay timeout while publishing kind:0 event'));
      }, timeoutMs);

      try {
        socket = new WebSocket(relayUrl);
      } catch (error) {
        clearTimeout(timer);
        reject(error);
        return;
      }

      socket.onopen = () => {
        socket.send(JSON.stringify(['EVENT', event]));
      };

      socket.onerror = () => {
        finish(new Error(`Relay connection failed: ${relayUrl}`));
      };

      socket.onmessage = (messageEvent) => {
        let data;
        try {
          data = JSON.parse(messageEvent.data);
        } catch {
          return;
        }

        if (!Array.isArray(data) || data.length < 2) return;
        if (data[0] !== 'OK') return;
        if (data[1] !== event.id) return;

        const accepted = data[2] === true;
        if (accepted) {
          finish(null);
          return;
        }

        const reason = String(data[3] || 'Relay rejected event');
        finish(new Error(reason));
      };
    });
  }

  async verifyExistingUser(expectedPubkey) {
    // Avoid unexpected signer popups for third-party NIP-07 providers.
    // Automatic verification is only safe with our own bridge-based extension.
    if (!this.isBridgeAvailable()) {
      console.info('[Nostr] Skipping automatic key verification (no wp-nostr bridge detected)');
      return;
    }

    const expected = String(expectedPubkey || '').trim().toLowerCase();
    const signerStatus = await this.getScopedSignerStatus();
    if (signerStatus && signerStatus.hasKey === false) {
      await this.showMissingLocalKeyWarning(expected);
      return;
    }

    try {
      const currentPubkey = String(await this.getPublicKey({ createIfMissing: false }) || '').trim().toLowerCase();
      if (currentPubkey !== expected) {
        this.showKeyMismatchWarning(expected, currentPubkey);
      } else {
        console.log('[Nostr] Key verified successfully');
        const warning = document.querySelector('.nostr-warning');
        if (warning) warning.remove();
        this.showVerifiedStatus();
      }
    } catch (error) {
      if (this.isMissingLocalKeyError(error)) {
        await this.showMissingLocalKeyWarning(expected);
        return;
      }
      console.error('[Nostr] Verification failed:', error);
    }
  }

  async getScopedSignerStatus() {
    try {
      const status = await this.sendExtensionMessage('NOSTR_GET_STATUS', null, 5000);
      if (!status || typeof status !== 'object') return null;
      return status;
    } catch {
      return null;
    }
  }

  isMissingLocalKeyError(error) {
    const message = String(error?.message || error || '').toLowerCase();
    if (!message) return false;
    return message.includes('no key found')
      || message.includes('no key available')
      || message.includes('no local key found');
  }

  async getCloudBackupStatus() {
    const restUrl = String(this.config.restUrl || '').trim();
    const nonce = String(this.config.nonce || '').trim();
    if (!restUrl || !nonce) return null;

    try {
      const status = await this.sendExtensionMessage('NOSTR_BACKUP_STATUS', {
        wpApi: { restUrl, nonce }
      }, 10000);
      if (!status || typeof status !== 'object') return null;
      return status;
    } catch {
      return null;
    }
  }

  async showMissingLocalKeyWarning(expectedPubkey) {
    console.warn('[Nostr] No local signer key found for scoped WP user');
    const existingWarning = document.querySelector('.nostr-warning');
    if (existingWarning) {
      existingWarning.remove();
    }

    const expected = String(expectedPubkey || '').trim().toLowerCase();
    const expectedShort = this.formatShortPubkey(expected);
    const backupStatus = await this.getCloudBackupStatus();
    const hasBackup = backupStatus?.hasBackup === true;
    const backupPubkey = String(backupStatus?.pubkey || '').trim().toLowerCase();
    const backupMatches = hasBackup && backupPubkey !== '' && (!expected || backupPubkey === expected);
    const restoreBlockedByCredential = backupStatus?.restoreLikelyAvailable === false
      && String(backupStatus?.restoreUnavailableReason || '') === 'credential_mismatch';

    const backupInfo = !backupStatus
      ? 'Cloud-Backup-Status konnte nicht automatisch geprueft werden. Du kannst Restore im Popup trotzdem direkt versuchen.'
      : hasBackup
        ? backupMatches
          ? `Cloud-Backup mit passendem Pubkey gefunden (${this.formatShortPubkey(backupPubkey)}).`
          : `Cloud-Backup gefunden, aber mit anderem Pubkey (${this.formatShortPubkey(backupPubkey)}).`
        : 'Kein Cloud-Backup fuer diesen User vorhanden.';

    const restoreHint = restoreBlockedByCredential
      ? '<p>Hinweis: Restore ist in diesem Browser vermutlich blockiert (Passkey-Credential stammt aus einem anderen Browser-Profil).</p>'
      : '';

    const warning = document.createElement('div');
    warning.className = 'nostr-warning';
    warning.innerHTML = `
      <p>Dieser WordPress-Account ist bereits mit Nostr verknuepft, aber im aktuellen Browser-Scope ist noch kein lokaler Schluessel vorhanden.</p>
      <p>Registriert: <code>${expectedShort}</code></p>
      <p>${backupInfo}</p>
      ${restoreHint}
      <p><strong>Empfohlener Ablauf:</strong></p>
      <p>1) Extension-Popup oeffnen -> <strong>WP Cloud Backup</strong> -> <strong>Aus Cloud wiederherstellen</strong>.</p>
      <p>2) Falls Restore nicht funktioniert: nsec im alten Browser exportieren und hier importieren (Popup -> Backup / Restore).</p>
      <p>3) Seite neu laden oder unten auf <strong>Neu pruefen</strong> klicken.</p>
      <p>4) Nur wenn du bewusst rotieren willst: neuen lokalen Key erzeugen und explizit uebernehmen.</p>
      <div class="nostr-modal-actions">
        <button type="button" class="nostr-btn nostr-btn-secondary" id="nostr-recheck-key">
          Jetzt neu pruefen
        </button>
      </div>
    `;

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(warning, target.firstChild);

    const recheckButton = warning.querySelector('#nostr-recheck-key');
    if (recheckButton) {
      recheckButton.onclick = async () => {
        recheckButton.disabled = true;
        try {
          await this.verifyExistingUser(expected);
        } finally {
          recheckButton.disabled = false;
        }
      };
    }
  }

  showKeyMismatchWarning(expected, actual) {
    console.warn('[Nostr] Key mismatch:', { expected, actual });
    const existingWarning = document.querySelector('.nostr-warning');
    if (existingWarning) {
      existingWarning.remove();
    }
    const expectedShort = this.formatShortPubkey(expected);
    const actualShort = this.formatShortPubkey(actual);

    const warning = document.createElement('div');
    warning.className = 'nostr-warning';
    warning.innerHTML = `
      <p>Dein Nostr-Schluessel stimmt nicht mit dem registrierten Schluessel ueberein.</p>
      <p>Registriert: <code>${expectedShort}</code></p>
      <p>Aktueller Browser: <code>${actualShort}</code></p>
      <p>Empfohlen: denselben privaten Schluessel aus dem Browser mit dem registrierten Pubkey uebernehmen (Cloud-Restore oder nsec-Import).</p>
      <div class="nostr-modal-actions">
        <button type="button" class="nostr-btn nostr-btn-primary" id="nostr-adopt-browser-key">
          Lokalen Key bewusst uebernehmen
        </button>
        <button type="button" class="nostr-btn nostr-btn-secondary" id="nostr-recheck-key">
          Jetzt neu pruefen
        </button>
      </div>
    `;

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(warning, target.firstChild);

    const adoptButton = warning.querySelector('#nostr-adopt-browser-key');
    if (adoptButton) {
      adoptButton.onclick = async () => {
        adoptButton.disabled = true;
        const originalLabel = adoptButton.textContent;
        adoptButton.textContent = 'Uebernehme...';
        try {
          await this.adoptCurrentBrowserProfile(expected, actual);
          warning.remove();
          this.showVerifiedStatus();
        } catch (error) {
          this.showError(error?.message || String(error));
          adoptButton.disabled = false;
          adoptButton.textContent = originalLabel;
        }
      };
    }

    const recheckButton = warning.querySelector('#nostr-recheck-key');
    if (recheckButton) {
      recheckButton.onclick = async () => {
        recheckButton.disabled = true;
        try {
          await this.verifyExistingUser(expected);
        } finally {
          recheckButton.disabled = false;
        }
      };
    }
  }

  async adoptCurrentBrowserProfile(expected, actual) {
    if (!/^[a-f0-9]{64}$/i.test(String(actual || ''))) {
      throw new Error('Aktueller Browser-Pubkey ist ungueltig.');
    }

    const payload = {
      pubkey: String(actual || '').toLowerCase(),
      expectedCurrentPubkey: String(expected || '').toLowerCase()
    };

    let response;
    let result;
    try {
      ({ response, result } = await this.postNostrJson('register/replace', payload));
    } catch {
      response = null;
      result = {};
    }

    const routeMissing =
      !response ||
      Number(response.status || 0) === 404 ||
      String(result?.code || '') === 'rest_no_route';

    if (routeMissing) {
      ({ response, result } = await this.postNostrJson('register', {
        ...payload,
        replace: true
      }));
    }

    if (!response.ok || !result?.success) {
      const status = Number(response.status || 0);
      const message = String(result?.message || '');
      if (status === 409 && String(result?.code || '') === 'pubkey_in_use') {
        throw new Error('Der aktuelle Browser-Pubkey gehoert bereits zu einem anderen Account und kann nicht uebernommen werden.');
      }
      if (status === 409 && String(result?.code || '') === 'pubkey_already_registered') {
        throw new Error([
          'Dieser Account hat bereits einen anderen registrierten Schluessel.',
          'So loest du das:',
          '1) Im Browser mit dem registrierten Account den Schluessel exportieren.',
          '2) In diesem Browser denselben Schluessel importieren (Popup > Backup / Restore).',
          '3) Seite neu laden.',
          'Falls der alte Browser/Backup nicht mehr verfuegbar ist: Admin muss den Nostr-Pubkey fuer den User zuruecksetzen.'
        ].join('\n'));
      }
      throw new Error(message || `Profil-Uebernahme fehlgeschlagen (HTTP ${status || 'unknown'}).`);
    }
  }

  async postNostrJson(path, payload) {
    const response = await fetch(`${this.config.restUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WP-Nonce': this.config.nonce
      },
      body: JSON.stringify(payload || {})
    });

    let result = {};
    try {
      result = await response.json();
    } catch {
      result = {};
    }
    return { response, result };
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
      return;
    }

    const target = document.querySelector('.entry-content') ||
      document.querySelector('main') ||
      document.body;
    target.insertBefore(error, target.firstChild);
    setTimeout(() => error.remove(), 7000);
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
