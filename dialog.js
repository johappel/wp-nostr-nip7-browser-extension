// Dialog logic for backup, password, domain approval and sign confirmation.

const params = new URLSearchParams(window.location.search);
const type = params.get('type');

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
        await runPasskeyAssertion();
        await chrome.storage.session.set({ passwordResult: { passkey: true } });
        window.close();
      } catch (err) {
        errorEl.textContent = err?.message || String(err) || 'Passkey unlock failed';
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
          errorEl.textContent = err?.message || String(err) || 'Passkey setup failed';
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

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: 'WP Nostr Signer'
      },
      user: {
        id: userId,
        name: 'wp-nostr-user',
        displayName: 'WP Nostr User'
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 } // RS256
      ],
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred'
      },
      timeout: 60000,
      attestation: 'none'
    }
  });

  if (!credential || !credential.rawId) {
    throw new Error('Passkey setup was canceled');
  }

  return toBase64Url(credential.rawId);
}

async function runPasskeyAssertion() {
  const { passkey_credential_id: storedCredentialId } = await chrome.storage.local.get(['passkey_credential_id']);
  const credentialId = String(storedCredentialId || '').trim();
  if (!credentialId) {
    throw new Error('No passkey is configured for this extension key');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCredentials = [{
    type: 'public-key',
    id: fromBase64Url(credentialId)
  }];

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000
    }
  });

  if (!assertion) {
    throw new Error('Passkey unlock failed');
  }
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
