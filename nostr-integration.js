/**
 * Nostr WordPress Integration
 * Erkennt NIP-07 Extension und ermöglicht Registrierung
 */
class NostrWPIntegration {
  constructor() {
    this.config = window.nostrConfig || {};
    this.hasExtension = false;
    this.npub = null;
    this.init();
  }

  async init() {
    // Nur für eingeloggte User
    if (!this.config.isLoggedIn) {
      return;
    }

    // 1. Extension Detection
    this.hasExtension = await this.detectExtension();
    
    if (!this.hasExtension) {
      this.showInstallPrompt();
      return;
    }

    // 2. Prüfe ob User registriert ist
    const wpUser = await this.getCurrentWPUser();
    
    if (!wpUser.pubkey) {
      // 3. Registrierungs-Flow
      await this.handleRegistration();
    } else {
      // 4. Prüfe ob Npub übereinstimmt
      await this.verifyExistingUser(wpUser.pubkey);
    }
  }

  async detectExtension() {
    return new Promise((resolve) => {
      // Ping an Extension
      window.postMessage({ type: 'NOSTR_PING', _id: 'detect' }, '*');
      
      const handler = (e) => {
        if (e.data.type === 'NOSTR_PING_RESPONSE') {
          window.removeEventListener('message', handler);
          console.log('[Nostr] Extension detected:', e.data.version);
          resolve(true);
        }
      };
      
      window.addEventListener('message', handler);
      
      // Timeout nach 500ms
      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve(false);
      }, 500);
    });
  }

  showInstallPrompt() {
    const storeUrl = this.config.extensionStoreUrl || 
                     'https://chrome.google.com/webstore/detail/[EXTENSION_ID]';
    
    const modal = document.createElement('div');
    modal.id = 'nostr-install-modal';
    modal.innerHTML = `
      <div class="nostr-modal-backdrop">
        <div class="nostr-modal">
          <h3>🔐 Nostr Signer erforderlich</h3>
          <p>Für die sichere Anmeldung mit Nostr benötigst du unsere Browser Extension.</p>
          
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
              Später erinnern
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    
    // Dismiss Handler
    document.getElementById('nostr-dismiss').onclick = () => {
      modal.remove();
      // Merke dir, dass User dismissed hat (Session Storage)
      sessionStorage.setItem('nostr_install_dismissed', 'true');
    };
    
    // Nicht anzeigen wenn bereits dismissed
    if (sessionStorage.getItem('nostr_install_dismissed') === 'true') {
      modal.remove();
    }
  }

  async handleRegistration() {
    try {
      // Zeige Registrierungs-Button
      this.showRegistrationUI();
    } catch (error) {
      console.error('[Nostr] Registration setup failed:', error);
    }
  }

  showRegistrationUI() {
    // Prüfe ob bereits ein Registrierungs-Button existiert
    if (document.getElementById('nostr-register-btn')) {
      return;
    }

    const container = document.createElement('div');
    container.id = 'nostr-register-container';
    container.innerHTML = `
      <div class="nostr-register-prompt">
        <p>🔗 Verknüpfe deinen Nostr-Account mit deinem WordPress-Profil</p>
        <button id="nostr-register-btn" class="nostr-btn nostr-btn-primary">
          Mit Nostr verknüpfen
        </button>
      </div>
    `;
    
    // Füge zum Body oder einem geeigneten Container hinzu
    const target = document.querySelector('.entry-content') || 
                   document.querySelector('main') || 
                   document.body;
    target.insertBefore(container, target.firstChild);
    
    // Click Handler
    document.getElementById('nostr-register-btn').onclick = async () => {
      await this.performRegistration();
    };
  }

  async performRegistration() {
    const btn = document.getElementById('nostr-register-btn');
    btn.disabled = true;
    btn.textContent = 'Registriere...';

    try {
      // NIP-07: getPublicKey() gibt hex-pubkey zurück
      const hexPubkey = await window.nostr.getPublicKey();
      
      // Sende hex-pubkey an WordPress
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
        // Entferne Registrierungs-Button
        document.getElementById('nostr-register-container')?.remove();
      } else {
        throw new Error(result.message || 'Registrierung fehlgeschlagen');
      }
    } catch (error) {
      console.error('[Nostr] Registration failed:', error);
      this.showError(error.message);
      btn.disabled = false;
      btn.textContent = 'Mit Nostr verknüpfen';
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
      <p>⚠️ Dein Nostr-Schlüssel stimmt nicht mit dem registrierten Schlüssel überein.</p>
      <p>Bitte prüfe, ob du die richtige Extension verwendest.</p>
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
      <p>✅ Dein Nostr-Account wurde erfolgreich verknüpft!</p>
    `;
    
    const target = document.querySelector('.entry-content') || 
                   document.querySelector('main') || 
                   document.body;
    target.insertBefore(success, target.firstChild);
    
    // Nach 5 Sekunden ausblenden
    setTimeout(() => success.remove(), 5000);
  }

  showVerifiedStatus() {
    // Zeige einen kleinen Verified-Badge an
    const badge = document.createElement('div');
    badge.className = 'nostr-verified-badge';
    badge.innerHTML = '✓ Nostr verifiziert';
    badge.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#4CAF50;color:white;padding:8px 16px;border-radius:4px;font-size:14px;z-index:9999;';
    document.body.appendChild(badge);
    
    setTimeout(() => badge.remove(), 3000);
  }

  showError(message) {
    const error = document.createElement('div');
    error.className = 'nostr-error';
    error.innerHTML = `<p>❌ Fehler: ${message}</p>`;
    
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

// Initialisierung wenn DOM bereit
document.addEventListener('DOMContentLoaded', () => {
  window.nostrWP = new NostrWPIntegration();
});