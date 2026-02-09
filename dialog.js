// Dialog logic for backup, password, domain approval and sign confirmation.

const params = new URLSearchParams(window.location.search);
const type = params.get('type');
const keyScope = normalizeKeyScope(params.get('scope'));
const passkeyBrokerUrl = String(params.get('passkeyBrokerUrl') || '').trim();
const passkeyBrokerOrigin = String(params.get('passkeyBrokerOrigin') || '').trim();
const passkeyBrokerRpId = String(params.get('passkeyBrokerRpId') || '').trim();
const passkeyIntent = String(params.get('passkeyIntent') || '').trim();
const PASSKEY_TIMEOUT_MS = 120000;

document.addEventListener('DOMContentLoaded', () => {
  switch (type) {
    case 'backup':
      showBackupDialog(params.get('npub'), params.get('nsec'));
      break;
    case 'password':
      showPasswordDialog(params.get('mode'));
      break;
    case 'domain':
      showDomainApprovalDialog(params.get('domain'));
      break;
    case 'confirm':
      showConfirmDialog(params.get('domain'), Number(params.get('kind')));
      break;
    default:
      document.getElementById('app').innerHTML = '<p>Unknown dialog type</p>';
  }
});

function showBackupDialog(npub, nsec) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog backup">
      <h2>Your Nostr keypair</h2>
      <p class="warning">
        Important: save your private key now. It will not be shown again after this dialog is closed.
      </p>

      <div class="key-box">
        <label>Public key (npub):</label>
        <code id="npub-display">${escapeHtml(npub)}</code>
        <button onclick="copyToClipboard('npub-display')" class="btn-secondary">Copy</button>
      </div>

      <div class="key-box nsec-box">
        <label>Private key (nsec) - keep secret:</label>
        <code id="nsec-display" class="blurred">${escapeHtml(nsec)}</code>
        <div class="btn-group">
          <button onclick="toggleVisibility('nsec-display')" class="btn-secondary">Show</button>
          <button onclick="copyToClipboard('nsec-display')" class="btn-secondary">Copy</button>
        </div>
      </div>

      <div class="actions">
        <button id="download" class="btn-primary">Save key as file</button>
        <label class="checkbox-label">
          <input type="checkbox" id="confirm-saved" />
          I saved my private key securely
        </label>
        <button id="close" class="btn-primary" disabled>Continue</button>
      </div>

      <p class="hint">There is no password reset for your private key.</p>
    </div>
  `;

  document.getElementById('confirm-saved').onchange = (e) => {
    document.getElementById('close').disabled = !e.target.checked;
  };

  document.getElementById('download').onclick = () => {
    const blob = new Blob(
      [`Nostr Backup\n===========\n\nnpub: ${npub}\nnsec: ${nsec}\n\nDO NOT SHARE.\n`],
      { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nostr-backup-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  document.getElementById('close').onclick = () => window.close();
}

function showPasswordDialog(mode) {
  const app = document.getElementById('app');
  const isCreate = mode === 'create';
  const isUnlockPasskey = mode === 'unlock-passkey';
  const passkeySupported = typeof window.PublicKeyCredential !== 'undefined';

  if (isUnlockPasskey) {
    app.innerHTML = `
      <div class="dialog password">
        <h2>Unlock with passkey</h2>
        <p>Confirm with your device passkey (biometric/PIN).</p>
        <p id="error" class="error" hidden></p>
        <div class="actions">
          <button id="unlock-passkey-submit" class="btn-primary">Unlock</button>
          <button id="cancel" class="btn-secondary">Cancel</button>
        </div>
      </div>
    `;

    document.getElementById('unlock-passkey-submit').onclick = async () => {
      const errorEl = document.getElementById('error');
      errorEl.hidden = true;
      try {
        if (!passkeySupported) {
          throw new Error('Passkey is not supported in this browser context');
        }
        const assertionResult = await runPasskeyAssertion({
          brokerUrl: passkeyBrokerUrl,
          brokerOrigin: passkeyBrokerOrigin,
          rpId: passkeyBrokerRpId,
          intent: passkeyIntent || 'unlock'
        });
        await chrome.storage.session.set({
          passwordResult: {
            passkey: true,
            credentialId: assertionResult?.credentialId || null
          }
        });
        window.close();
      } catch (err) {
        errorEl.textContent = mapPasskeyError(err, 'unlock');
        errorEl.hidden = false;
      }
    };

    document.getElementById('cancel').onclick = () => {
      chrome.storage.session.set({ passwordResult: null });
      window.close();
    };
    return;
  }

  app.innerHTML = `
    <div class="dialog password">
      <h2>${isCreate ? 'Set password' : 'Unlock extension'}</h2>
      <p>${isCreate
        ? 'This password protects your private key. Minimum 8 characters.'
        : 'Enter your password to continue.'}</p>

      <div class="input-group">
        <input type="password" id="password" placeholder="Password" autofocus />
      </div>

      ${isCreate ? `
        <div class="input-group">
          <input type="password" id="password-confirm" placeholder="Repeat password" />
        </div>
        <label class="checkbox-label">
          <input type="checkbox" id="no-password" />
          Store without password (less secure)
        </label>
        <p class="hint">Use only on private devices. Private key will be stored unencrypted.</p>
        <div class="actions">
          <button id="setup-passkey" class="btn-secondary" type="button" ${passkeySupported ? '' : 'disabled'}>
            Use passkey instead (recommended)
          </button>
        </div>
        <p class="hint">${passkeySupported
          ? 'Passkey unlock uses biometric/PIN and keeps UX simple across devices.'
          : 'Passkey is not available in this browser context.'}</p>
      ` : ''}

      <p id="error" class="error" hidden></p>

      <div class="actions">
        <button id="submit" class="btn-primary">${isCreate ? 'Save' : 'Unlock'}</button>
        <button id="cancel" class="btn-secondary">Cancel</button>
      </div>
    </div>
  `;

  const passwordEl = document.getElementById('password');
  const confirmEl = isCreate ? document.getElementById('password-confirm') : null;
  const noPasswordEl = isCreate ? document.getElementById('no-password') : null;

  if (isCreate && noPasswordEl) {
    const toggleInputs = () => {
      const disabled = noPasswordEl.checked;
      passwordEl.disabled = disabled;
      if (confirmEl) confirmEl.disabled = disabled;
    };
    noPasswordEl.onchange = toggleInputs;
    toggleInputs();
  }

  if (isCreate) {
    const passkeyBtn = document.getElementById('setup-passkey');
    if (passkeyBtn) {
      passkeyBtn.onclick = async () => {
        const errorEl = document.getElementById('error');
        errorEl.hidden = true;
        try {
          if (!passkeySupported) {
            throw new Error('Passkey is not supported in this browser context');
          }
          const credentialId = await createPasskeyCredential();
          await chrome.storage.session.set({
            passwordResult: {
              protection: 'passkey',
              credentialId
            }
          });
          window.close();
        } catch (err) {
          errorEl.textContent = mapPasskeyError(err, 'setup');
          errorEl.hidden = false;
        }
      };
    }
  }

  document.getElementById('submit').onclick = async () => {
    const pw = passwordEl.value;
    const errorEl = document.getElementById('error');

    if (isCreate) {
      if (noPasswordEl?.checked) {
        await chrome.storage.session.set({ passwordResult: { noPassword: true } });
        window.close();
        return;
      }

      const pw2 = confirmEl.value;
      if (pw !== pw2) {
        errorEl.textContent = 'Passwords do not match';
        errorEl.hidden = false;
        return;
      }
      if (pw.length < 8) {
        errorEl.textContent = 'Minimum 8 characters required';
        errorEl.hidden = false;
        return;
      }
    }

    if (!pw) {
      errorEl.textContent = 'Password required';
      errorEl.hidden = false;
      return;
    }

    await chrome.storage.session.set({ passwordResult: { password: pw } });
    window.close();
  };

  document.getElementById('cancel').onclick = () => {
    chrome.storage.session.set({ passwordResult: null });
    window.close();
  };

  passwordEl.onkeypress = (e) => {
    if (e.key === 'Enter') document.getElementById('submit').click();
  };
  if (confirmEl) {
    confirmEl.onkeypress = (e) => {
      if (e.key === 'Enter') document.getElementById('submit').click();
    };
  }
}

async function createPasskeyCredential() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const isFirefox = /\bfirefox\//i.test(navigator.userAgent);
  const publicKey = {
    challenge: challenge.buffer,
    rp: {
      name: 'WP Nostr Signer'
    },
    user: {
      id: userId.buffer,
      name: 'wp-nostr-user',
      displayName: 'WP Nostr User'
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 } // RS256
    ],
    timeout: PASSKEY_TIMEOUT_MS,
    attestation: 'none',
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'preferred',
      ...(isFirefox ? {} : { authenticatorAttachment: 'platform' })
    }
  };

  const credential = await navigator.credentials.create({
    publicKey
  });

  if (!credential || !credential.rawId) {
    throw new Error('Passkey setup was canceled');
  }

  return toBase64Url(credential.rawId);
}

async function runPasskeyAssertion(options = {}) {
  const brokerOptions = normalizeBrokerOptions(options);
  const credentialStorageKey = keyName('passkey_credential_id');
  const storage = await chrome.storage.local.get([credentialStorageKey]);
  const storedCredentialId = storage[credentialStorageKey];
  const knownCredentialId = String(storedCredentialId || '').trim();

  if (brokerOptions) {
    if (knownCredentialId) {
      try {
        return await runLocalPasskeyAssertion(knownCredentialId);
      } catch {
        return await runPasskeyAssertionViaBroker(brokerOptions);
      }
    }
    return await runPasskeyAssertionViaBroker(brokerOptions);
  }

  return await runLocalPasskeyAssertion(knownCredentialId);
}

async function runLocalPasskeyAssertion(knownCredentialId = '') {
  const isChromium = /\b(?:Chrome|Chromium|Edg)\//i.test(navigator.userAgent);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const request = {
    challenge: challenge.buffer,
    userVerification: 'preferred',
    timeout: PASSKEY_TIMEOUT_MS
  };
  if (isChromium) {
    // Hint Chromium towards local device passkeys (Windows Hello / Touch ID).
    request.hints = ['client-device'];
  }
  let assertion = null;

  if (knownCredentialId) {
    const descriptor = {
      type: 'public-key',
      id: fromBase64Url(knownCredentialId).buffer
    };
    if (isChromium) {
      descriptor.transports = ['internal'];
    }
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          ...request,
          allowCredentials: [descriptor]
        }
      });
    } catch (error) {
      if (!shouldRetryPasskeyWithoutAllowCredentials(error)) {
        throw error;
      }
      // Fallback for stale credential ids / authenticator migration.
      assertion = await navigator.credentials.get({
        publicKey: request
      });
    }
  } else {
    assertion = await navigator.credentials.get({
      publicKey: request
    });
  }

  if (!assertion || !assertion.rawId) {
    throw new Error('Passkey unlock failed');
  }

  const resolvedCredentialId = toBase64Url(assertion.rawId);
  const credentialStorageKey = keyName('passkey_credential_id');
  await chrome.storage.local.set({ [credentialStorageKey]: resolvedCredentialId });

  return { credentialId: resolvedCredentialId };
}

function shouldRetryPasskeyWithoutAllowCredentials(error) {
  const name = String(error?.name || '').trim();
  const message = String(error?.message || '').trim();
  if (name === 'NotAllowedError') return true;
  if (name === 'UnknownError') return true;
  if (name === 'InvalidStateError') return true;
  if (/unknown transient reason/i.test(message)) return true;
  return false;
}

function normalizeBrokerOptions(options) {
  const rawUrl = String(options?.brokerUrl || '').trim();
  if (!rawUrl) return null;

  try {
    const parsed = new URL(rawUrl);
    if (!/^https?:$/i.test(parsed.protocol)) return null;
    const origin = String(options?.brokerOrigin || '').trim() || parsed.origin;
    const rpId = String(options?.rpId || '').trim().toLowerCase() || parsed.hostname.toLowerCase();
    const intent = String(options?.intent || '').trim() || 'generic';
    return {
      url: parsed.href,
      origin,
      rpId,
      intent
    };
  } catch {
    return null;
  }
}

async function runPasskeyAssertionViaBroker(brokerOptions) {
  const requestId = createRequestId();
  const features = 'popup=yes,width=560,height=740,resizable=yes,scrollbars=yes';
  const brokerWindow = window.open(brokerOptions.url, 'wp_nostr_auth_broker', features);
  if (!brokerWindow) {
    throw new Error('Auth-Broker Fenster konnte nicht geoeffnet werden (Popup-Blocker?).');
  }

  return await new Promise((resolve, reject) => {
    let finished = false;
    let ready = false;

    const cleanup = (closeWindow = false) => {
      clearTimeout(readyTimeout);
      clearTimeout(resultTimeout);
      clearInterval(closedPoll);
      window.removeEventListener('message', onMessage);
      if (closeWindow) {
        try {
          brokerWindow.close();
        } catch {
          // ignore
        }
      }
    };

    const fail = (error) => {
      if (finished) return;
      finished = true;
      cleanup(true);
      reject(error instanceof Error ? error : new Error(String(error || 'Auth-Broker Fehler')));
    };

    const succeed = (result) => {
      if (finished) return;
      finished = true;
      cleanup(true);
      resolve(result);
    };

    const onMessage = (event) => {
      if (event.source !== brokerWindow) return;
      if (brokerOptions.origin && event.origin !== brokerOptions.origin) return;

      const data = event?.data;
      if (!data || typeof data !== 'object') return;

      if (data.type === 'NOSTR_AUTH_BROKER_READY') {
        ready = true;
        clearTimeout(readyTimeout);
        try {
          brokerWindow.postMessage({
            type: 'NOSTR_AUTH_BROKER_ASSERT_REQUEST',
            requestId,
            intent: brokerOptions.intent,
            rpId: brokerOptions.rpId
          }, brokerOptions.origin || '*');
        } catch (error) {
          fail(error);
        }
        return;
      }

      if (data.type !== 'NOSTR_AUTH_BROKER_ASSERT_RESULT') return;
      if (String(data.requestId || '') !== requestId) return;

      if (data.error) {
        fail(new Error(String(data.error)));
        return;
      }

      const credentialId = String(data?.result?.credentialId || '').trim();
      if (!credentialId) {
        fail(new Error('Auth-Broker Antwort enthaelt keine Credential-ID.'));
        return;
      }

      succeed({ credentialId });
    };

    window.addEventListener('message', onMessage);

    const readyTimeout = setTimeout(() => {
      fail(new Error('Auth-Broker antwortet nicht. Bitte Login auf der Primary Domain pruefen.'));
    }, 30000);

    const resultTimeout = setTimeout(() => {
      fail(new Error('Auth-Broker Passkey-Flow hat ein Timeout erreicht.'));
    }, PASSKEY_TIMEOUT_MS + 30000);

    const closedPoll = setInterval(() => {
      if (brokerWindow.closed) {
        const message = ready
          ? 'Passkey-Dialog wurde geschlossen, bevor die Freigabe abgeschlossen war.'
          : 'Auth-Broker Fenster wurde vor dem Start geschlossen.';
        fail(new Error(message));
      }
    }, 300);
  });
}

function mapPasskeyError(error, phase) {
  const rawMessage = String(error?.message || error || '');
  const name = String(error?.name || '').trim();

  if (/Auth-Broker/i.test(rawMessage)) {
    return rawMessage;
  }

  if (name === 'NotAllowedError') {
    if (phase === 'unlock') {
      return 'Passkey abgebrochen oder keine passende lokale Passkey-Identitaet gefunden. In Chrome bitte pruefen, ob fuer diese Extension bereits eine lokale Passkey-Identitaet (Windows Hello) existiert.';
    }
    return 'Passkey-Einrichtung abgebrochen oder nicht erlaubt. Bitte erneut versuchen und den lokalen Geraete-Passkey (z. B. Windows Hello) waehlen.';
  }

  if (name === 'UnknownError' || /unknown transient reason/i.test(rawMessage)) {
    return 'Temporarer Passkey-Fehler im Browser. Bitte Dialog erneut oeffnen und nochmal versuchen.';
  }

  if (name === 'SecurityError') {
    return 'Passkey ist in diesem Kontext nicht erlaubt (Sicherheitsrichtlinie). Bitte Seite/Extension neu laden.';
  }

  if (name === 'InvalidStateError') {
    return 'Passkey ist bereits registriert oder nicht im erwarteten Zustand. Bitte erneut versuchen.';
  }

  return rawMessage || 'Passkey operation failed';
}

function createRequestId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  }
  return `req-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeKeyScope(scope) {
  const value = String(scope || '').trim();
  if (!value || value === 'global') return 'global';
  if (!/^[a-zA-Z0-9:._-]{1,120}$/.test(value)) return 'global';
  return value;
}

function keyName(baseKey) {
  if (keyScope === 'global') return baseKey;
  return `${keyScope}::${baseKey}`;
}

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(input) {
  const base64 = String(input || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(String(input || '').length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function showDomainApprovalDialog(domain) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog domain">
      <h2>New domain</h2>
      <p>The website <strong>${escapeHtml(domain)}</strong> wants to access your Nostr identity.</p>
      <p>Do you trust this domain?</p>

      <div class="actions">
        <button id="allow" class="btn-primary">Allow</button>
        <button id="deny" class="btn-secondary">Deny</button>
        <label class="checkbox-label">
          <input type="checkbox" id="remember" checked />
          Remember decision for this domain
        </label>
      </div>
    </div>
  `;

  const respond = async (allowed) => {
    const remember = document.getElementById('remember').checked;

    if (remember) {
      const storageKey = allowed ? 'allowedDomains' : 'blockedDomains';
      const { [storageKey]: list = [] } = await chrome.storage.local.get(storageKey);
      if (!list.includes(domain)) {
        list.push(domain);
        await chrome.storage.local.set({ [storageKey]: list });
      }
    }

    await chrome.storage.local.set({
      domainApprovalResult: { domain, allowed }
    });
    window.close();
  };

  document.getElementById('allow').onclick = () => respond(true);
  document.getElementById('deny').onclick = () => respond(false);
}

function showConfirmDialog(domain, kind) {
  const kindNames = {
    0: 'Profile metadata',
    1: 'Text note',
    3: 'Contact list',
    4: 'Encrypted message',
    5: 'Encrypted event (NIP-17)',
    6: 'Repost',
    7: 'Reaction',
    9735: 'Zap request'
  };
  const kindName = kindNames[kind] || `Unknown (kind ${kind})`;

  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog confirm">
      <h2>Signing request</h2>
      <p><strong>${escapeHtml(domain)}</strong> wants to sign an event:</p>
      <div class="event-info">
        <span class="kind">${kindName}</span>
      </div>
      <p class="warning">This is a sensitive event type. Confirm only if you trust this domain.</p>

      <div class="actions">
        <button id="confirm" class="btn-primary">Sign</button>
        <button id="reject" class="btn-secondary">Reject</button>
      </div>
    </div>
  `;

  document.getElementById('confirm').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: true });
    window.close();
  };

  document.getElementById('reject').onclick = async () => {
    await chrome.storage.local.set({ signConfirmResult: false });
    window.close();
  };
}

// Helpers
window.copyToClipboard = function(elementId) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = window.event?.target;
    if (!btn) return;
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = original; }, 1500);
  });
};

window.toggleVisibility = function(elementId) {
  const el = document.getElementById(elementId);
  el.classList.toggle('blurred');
  const btn = window.event?.target;
  if (!btn) return;
  btn.textContent = el.classList.contains('blurred') ? 'Show' : 'Hide';
};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
