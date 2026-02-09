// Dialog-Logik für Backup, Passwort, Domain-Freigabe und Signatur-Bestätigung.

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
      document.getElementById('app').innerHTML = '<p>Unbekannter Dialog-Typ</p>';
  }
});

function showBackupDialog(npub, nsec) {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog backup">
      <h2>Dein Nostr-Schlüsselpaar</h2>
      <p class="warning">
        Wichtig: Speichere deinen privaten Schlüssel jetzt. Nach dem Schließen wird er nicht erneut angezeigt.
      </p>

      <div class="key-box">
        <label>Öffentlicher Schlüssel (npub):</label>
        <code id="npub-display">${escapeHtml(npub)}</code>
        <button onclick="copyToClipboard('npub-display')" class="btn-secondary">Kopieren</button>
      </div>

      <div class="key-box nsec-box">
        <label>Privater Schlüssel (nsec) - geheim halten:</label>
        <code id="nsec-display" class="blurred">${escapeHtml(nsec)}</code>
        <div class="btn-group">
          <button onclick="toggleVisibility('nsec-display')" class="btn-secondary">Anzeigen</button>
          <button onclick="copyToClipboard('nsec-display')" class="btn-secondary">Kopieren</button>
        </div>
      </div>

      <div class="actions">
        <button id="download" class="btn-primary">Schlüssel als Datei speichern</button>
        <label class="checkbox-label">
          <input type="checkbox" id="confirm-saved" />
          Ich habe meinen privaten Schlüssel sicher gespeichert
        </label>
        <button id="close" class="btn-primary" disabled>Weiter</button>
      </div>

      <p class="hint">Für den privaten Schlüssel gibt es kein Zurücksetzen.</p>
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
        <h2>Mit Passkey entsperren</h2>
        <p>Bestätige mit deinem Geräte-Passkey (Biometrie/PIN).</p>
        <p id="error" class="error" hidden></p>
        <div class="actions">
          <button id="unlock-passkey-submit" class="btn-primary">Entsperren</button>
          <button id="cancel" class="btn-secondary">Abbrechen</button>
        </div>
      </div>
    `;

    document.getElementById('unlock-passkey-submit').onclick = async () => {
      const errorEl = document.getElementById('error');
      errorEl.hidden = true;
      try {
        if (!passkeySupported) {
          throw new Error('Passkey wird in diesem Browser-Kontext nicht unterstützt');
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
      <h2>${isCreate ? 'Passwort festlegen' : 'Extension entsperren'}</h2>
      <p>${isCreate
        ? 'Dieses Passwort schützt deinen privaten Schlüssel. Mindestens 8 Zeichen.'
        : 'Bitte Passwort eingeben, um fortzufahren.'}</p>

      <div class="input-group">
        <input type="password" id="password" placeholder="Passwort" autofocus />
      </div>

      ${isCreate ? `
        <div class="input-group">
          <input type="password" id="password-confirm" placeholder="Passwort wiederholen" />
        </div>
        <label class="checkbox-label">
          <input type="checkbox" id="no-password" />
          Ohne Passwort speichern (weniger sicher)
        </label>
        <p class="hint">Nur auf privaten Geräten verwenden. Der private Schlüssel wird unverschlüsselt gespeichert.</p>
        <div class="actions">
          <button id="setup-passkey" class="btn-secondary" type="button" ${passkeySupported ? '' : 'disabled'}>
            Stattdessen Passkey verwenden (empfohlen)
          </button>
        </div>
        <p class="hint">${passkeySupported
          ? 'Passkey-Entsperrung nutzt Biometrie/PIN und vereinfacht die Nutzung über Geräte hinweg.'
          : 'Passkey ist in diesem Browser-Kontext nicht verfügbar.'}</p>
      ` : ''}

      <p id="error" class="error" hidden></p>

      <div class="actions">
        <button id="submit" class="btn-primary">${isCreate ? 'Speichern' : 'Entsperren'}</button>
        <button id="cancel" class="btn-secondary">Abbrechen</button>
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
            throw new Error('Passkey wird in diesem Browser-Kontext nicht unterstützt');
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
        errorEl.textContent = 'Passwörter stimmen nicht überein';
        errorEl.hidden = false;
        return;
      }
      if (pw.length < 8) {
        errorEl.textContent = 'Mindestens 8 Zeichen erforderlich';
        errorEl.hidden = false;
        return;
      }
    }

    if (!pw) {
      errorEl.textContent = 'Passwort erforderlich';
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
  const passkeyIdentity = buildPasskeyIdentity(keyScope, userId);
  const publicKey = {
    challenge: challenge.buffer,
    rp: {
      name: 'WP Nostr Signer'
    },
    user: {
      id: userId.buffer,
      name: passkeyIdentity.name,
      displayName: passkeyIdentity.displayName
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
    throw new Error('Passkey-Einrichtung wurde abgebrochen');
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
    // Do NOT restrict transports to ['internal'] — Chrome and Firefox use
    // different credential stores on Windows.  When a credential was created
    // in Firefox it does not exist in Windows Hello, so Chrome would skip the
    // platform authenticator and only show cross-device options (USB / phone).
    // Omitting transports lets the browser probe all available authenticators
    // including Windows Hello.
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
      // Fallback: discoverable credential flow (no allowCredentials).
      // This lets Windows Hello / platform authenticator search its own store.
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
    throw new Error('Passkey-Entsperrung fehlgeschlagen');
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
    throw new Error('Auth-Broker-Fenster konnte nicht geöffnet werden (Popup-Blocker?).');
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
        fail(new Error('Auth-Broker-Antwort enthält keine Credential-ID.'));
        return;
      }

      succeed({ credentialId });
    };

    window.addEventListener('message', onMessage);

    const readyTimeout = setTimeout(() => {
      fail(new Error('Auth-Broker antwortet nicht. Bitte Login auf der Primary Domain prüfen.'));
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
      return 'Passkey abgebrochen oder keine passende lokale Passkey-Identität gefunden. In Chrome bitte prüfen, ob für diese Extension bereits eine lokale Passkey-Identität (Windows Hello) existiert.';
    }
    return 'Passkey-Einrichtung abgebrochen oder nicht erlaubt. Bitte erneut versuchen und den lokalen Geräte-Passkey (z. B. Windows Hello) wählen.';
  }

  if (name === 'UnknownError' || /unknown transient reason/i.test(rawMessage)) {
    return 'Temporärer Passkey-Fehler im Browser. Bitte Dialog erneut öffnen und noch einmal versuchen.';
  }

  if (name === 'SecurityError') {
    return 'Passkey ist in diesem Kontext nicht erlaubt (Sicherheitsrichtlinie). Bitte Seite/Extension neu laden.';
  }

  if (name === 'InvalidStateError') {
    return 'Passkey ist bereits registriert oder nicht im erwarteten Zustand. Bitte erneut versuchen.';
  }

  return rawMessage || 'Passkey-Vorgang fehlgeschlagen';
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

function buildPasskeyIdentity(scope, userIdBytes) {
  const normalizedScope = normalizeKeyScope(scope);
  const suffix = shortHex(userIdBytes, 2);
  const wpMatch = normalizedScope.match(/^wp:(.+):u:(\d+)$/i);

  let accountLabel = 'global';
  if (wpMatch) {
    const host = String(wpMatch[1] || '').toLowerCase().replace(/[^a-z0-9.:-]/g, '-');
    const wpUserId = String(wpMatch[2] || '').trim();
    accountLabel = `u${wpUserId}@${host || 'site'}`;
  } else if (normalizedScope !== 'global') {
    accountLabel = normalizedScope.toLowerCase().replace(/[^a-z0-9._-]/g, '-');
  }

  const compactLabel = accountLabel.slice(0, 36) || 'global';
  return {
    name: `wp-nostr-${compactLabel}-${suffix}`.slice(0, 64),
    displayName: `WP Nostr ${compactLabel} #${suffix}`.slice(0, 64)
  };
}

function shortHex(bytes, takeBytes = 2) {
  const source = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  const max = Math.max(1, Math.min(source.length, Number(takeBytes) || 2));
  return Array.from(source.subarray(0, max), (value) => value.toString(16).padStart(2, '0')).join('');
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
      <h2>Neue Domain</h2>
      <p>Die Website <strong>${escapeHtml(domain)}</strong> möchte auf deine Nostr-Identität zugreifen.</p>
      <p>Vertraust du dieser Domain?</p>

      <div class="actions">
        <button id="allow" class="btn-primary">Erlauben</button>
        <button id="deny" class="btn-secondary">Ablehnen</button>
        <label class="checkbox-label">
          <input type="checkbox" id="remember" checked />
          Entscheidung für diese Domain merken
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
    0: 'Profil-Metadaten',
    1: 'Textnotiz',
    3: 'Kontaktliste',
    4: 'Verschlüsselte Nachricht',
    5: 'Verschlüsseltes Event (NIP-17)',
    6: 'Repost',
    7: 'Reaction',
    9735: 'Zap-Anfrage'
  };
  const kindName = kindNames[kind] || `Unbekannt (Kind ${kind})`;

  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dialog confirm">
      <h2>Signaturanfrage</h2>
      <p><strong>${escapeHtml(domain)}</strong> möchte ein Event signieren:</p>
      <div class="event-info">
        <span class="kind">${kindName}</span>
      </div>
      <p class="warning">Das ist ein sensibler Event-Typ. Bestätige nur, wenn du dieser Domain vertraust.</p>

      <div class="actions">
        <button id="confirm" class="btn-primary">Signieren</button>
        <button id="reject" class="btn-secondary">Ablehnen</button>
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
    btn.textContent = 'Kopiert';
    setTimeout(() => { btn.textContent = original; }, 1500);
  });
};

window.toggleVisibility = function(elementId) {
  const el = document.getElementById(elementId);
  el.classList.toggle('blurred');
  const btn = window.event?.target;
  if (!btn) return;
  btn.textContent = el.classList.contains('blurred') ? 'Anzeigen' : 'Verbergen';
};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
