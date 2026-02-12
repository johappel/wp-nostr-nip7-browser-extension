// Dialog-Logik für Backup, Passwort, Domain-Freigabe und Signatur-Bestätigung.

const params = new URLSearchParams(window.location.search);
const type = params.get('type');
const keyScope = normalizeKeyScope(params.get('scope'));
const passkeyBrokerUrl = String(params.get('passkeyBrokerUrl') || '').trim();
const passkeyBrokerOrigin = String(params.get('passkeyBrokerOrigin') || '').trim();
const passkeyBrokerRpId = String(params.get('passkeyBrokerRpId') || '').trim();
const passkeyIntent = String(params.get('passkeyIntent') || '').trim();
const wpDisplayName = String(params.get('wpDisplayName') || '').trim();
const PASSKEY_TIMEOUT_MS = 120000;
const isFirefox = /\bFirefox\//i.test(navigator.userAgent);

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
      <h2>Dein Nostr-Schluesselpaar</h2>
      <p class="warning">
        Wichtig: Speichere deinen privaten Schluessel jetzt. Nach dem Schliessen wird er nicht erneut angezeigt.
      </p>

      <div class="key-box">
        <label>Oeffentlicher Schluessel (npub):</label>
        <code id="npub-display">${escapeHtml(npub)}</code>
        <button id="copy-npub" class="btn-secondary" type="button">Kopieren</button>
      </div>

      <div class="key-box nsec-box">
        <label>Privater Schluessel (nsec) - geheim halten:</label>
        <code id="nsec-display" class="blurred">${escapeHtml(nsec)}</code>
        <div class="btn-group">
          <button id="toggle-nsec" class="btn-secondary" type="button">Anzeigen</button>
          <button id="copy-nsec" class="btn-secondary" type="button">Kopieren</button>
        </div>
      </div>

      <div class="actions">
        <button id="download" class="btn-primary">Schluessel als Datei speichern</button>
        <label class="checkbox-label">
          <input type="checkbox" id="confirm-saved" />
          Ich habe meinen privaten Schluessel sicher gespeichert
        </label>
        <button id="close" class="btn-primary" disabled>Weiter</button>
      </div>

      <p class="hint">Fuer den privaten Schluessel gibt es kein Zuruecksetzen.</p>
    </div>
  `;

  document.getElementById('confirm-saved').onchange = (e) => {
    document.getElementById('close').disabled = !e.target.checked;
  };

  const npubEl = document.getElementById('npub-display');
  const nsecEl = document.getElementById('nsec-display');
  const copyNpubBtn = document.getElementById('copy-npub');
  const copyNsecBtn = document.getElementById('copy-nsec');
  const toggleNsecBtn = document.getElementById('toggle-nsec');

  copyNpubBtn.addEventListener('click', async () => {
    await copyTextWithFeedback(npubEl?.textContent || '', copyNpubBtn);
  });

  copyNsecBtn.addEventListener('click', async () => {
    await copyTextWithFeedback(nsecEl?.textContent || '', copyNsecBtn);
  });

  toggleNsecBtn.addEventListener('click', () => {
    nsecEl.classList.toggle('blurred');
    toggleNsecBtn.textContent = nsecEl.classList.contains('blurred') ? 'Anzeigen' : 'Verbergen';
  });

  document.getElementById('download').onclick = () => {
    const blob = new Blob(
      [`Nostr Backup\n===========\n\nnpub: ${npub}\nnsec: ${nsec}\n\n!! GEHEIM HALTEN – NIEMALS TEILEN !!\n\nWiederherstellen / anderer Browser:\n1. WP Nostr Signer Extension installieren\n2. Extension-Popup oeffnen (Klick auf das Extension-Icon)\n3. Im Bereich "Nostr-Schluessel" den nsec in das Import-Feld einfuegen\n4. "Importieren" klicken\n`],
      { type: 'text/plain' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const backupNamePart = wpDisplayName ? `-${wpDisplayName.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 24)}` : '';
    a.download = `nostr-backup${backupNamePart}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  document.getElementById('close').onclick = () => window.close();
}
function showPasswordDialog(mode) {
  const app = document.getElementById('app');
  const isCreate = mode === 'create';
  const isUnlockPasskey = mode === 'unlock-passkey';
  const isCreatePasskey = mode === 'create-passkey';
  const isCreatePassword = mode === 'create-password';
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

  // Dedicated passkey-creation dialog (used by CHANGE_PROTECTION → passkey)
  if (isCreatePasskey) {
    app.innerHTML = `
      <div class="dialog password">
        <h2>Passkey einrichten</h2>
        <p>Erstelle einen Passkey mit Biometrie oder PIN, um deinen Schl\u00fcssel zu sch\u00fctzen.</p>
        <p id="error" class="error" hidden></p>
        <div class="actions">
          <button id="setup-passkey-direct" class="btn-primary">\ud83d\udd10 Passkey erstellen</button>
          <button id="cancel" class="btn-secondary">Abbrechen</button>
        </div>
      </div>
    `;

    document.getElementById('setup-passkey-direct').onclick = async () => {
      const errorEl = document.getElementById('error');
      errorEl.hidden = true;
      try {
        if (!passkeySupported) {
          throw new Error('Passkey wird in diesem Browser-Kontext nicht unterst\u00fctzt');
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

    document.getElementById('cancel').onclick = () => {
      chrome.storage.session.set({ passwordResult: null });
      window.close();
    };
    return;
  }

  // Dedicated password-creation dialog (used by CHANGE_PROTECTION → password)
  if (isCreatePassword) {
    app.innerHTML = `
      <div class="dialog password">
        <h2>Passwort festlegen</h2>
        <p>W\u00e4hle ein Passwort, um deinen privaten Schl\u00fcssel zu sch\u00fctzen.</p>
        <div class="input-group">
          <input type="password" id="password" placeholder="Passwort (mind. 8 Zeichen)" autofocus />
        </div>
        <div class="input-group">
          <input type="password" id="password-confirm" placeholder="Passwort wiederholen" />
        </div>
        <p id="error" class="error" hidden></p>
        <div class="actions">
          <button id="submit" class="btn-primary">Mit Passwort speichern</button>
          <button id="cancel" class="btn-secondary">Abbrechen</button>
        </div>
      </div>
    `;

    const passwordEl = document.getElementById('password');
    const confirmEl = document.getElementById('password-confirm');

    document.getElementById('submit').onclick = async () => {
      const pw = passwordEl.value;
      const pw2 = confirmEl.value;
      const errorEl = document.getElementById('error');

      if (pw !== pw2) {
        errorEl.textContent = 'Passw\u00f6rter stimmen nicht \u00fcberein';
        errorEl.hidden = false;
        return;
      }
      if (pw.length < 8) {
        errorEl.textContent = 'Mindestens 8 Zeichen erforderlich';
        errorEl.hidden = false;
        return;
      }

      await chrome.storage.session.set({ passwordResult: { password: pw } });
      window.close();
    };

    passwordEl.onkeypress = (e) => { if (e.key === 'Enter') confirmEl.focus(); };
    confirmEl.onkeypress = (e) => { if (e.key === 'Enter') document.getElementById('submit').click(); };

    document.getElementById('cancel').onclick = () => {
      chrome.storage.session.set({ passwordResult: null });
      window.close();
    };
    return;
  }

  // This dialog is now only shown for first-time users (no existing scopes).
  // Returning users get their protection mode inherited automatically.
  app.innerHTML = `
    <div class="dialog password">
      <h2>${isCreate ? 'Schlüssel-Schutz festlegen' : 'Extension entsperren'}</h2>
      <p>${isCreate
        ? 'Wähle, wie dein privater Schlüssel geschützt werden soll:'
        : 'Bitte Passwort eingeben, um fortzufahren.'}</p>

      ${isCreate ? `
        <div class="protection-options">

          <div class="option-card ${passkeySupported ? '' : 'disabled'}">
            <button id="setup-passkey" class="btn-option" type="button" ${passkeySupported ? '' : 'disabled'}>
              🔐 Passkey verwenden (empfohlen)
            </button>
            <p class="hint">${passkeySupported
              ? 'Biometrie oder PIN – einfach und sicher. Funktioniert auf allen Websites.'
              : 'Passkey ist in diesem Browser nicht verfügbar.'}</p>
          </div>

          <div class="option-card">
            <div class="input-group">
              <input type="password" id="password" placeholder="Passwort (mind. 8 Zeichen)" />
            </div>
            <div class="input-group">
              <input type="password" id="password-confirm" placeholder="Passwort wiederholen" />
            </div>
            <div class="actions">
              <button id="submit" class="btn-primary" type="button">Mit Passwort speichern</button>
            </div>
          </div>

          <div class="option-card option-less-secure">
            <label class="checkbox-label">
              <input type="checkbox" id="no-password" />
              Ohne Passwort speichern
            </label>
            <p class="hint">Nur auf privaten Geräten. Der Schlüssel wird unverschlüsselt gespeichert.</p>
            <div class="actions">
              <button id="submit-no-pw" class="btn-secondary" type="button" disabled>
                Ohne Passwort fortfahren
              </button>
            </div>
          </div>
        </div>

      ` : `
        <div class="input-group">
          <input type="password" id="password" placeholder="Passwort" autofocus />
        </div>
      `}

      <p id="error" class="error" hidden></p>

      <div class="actions">
        ${!isCreate ? '<button id="submit" class="btn-primary">Entsperren</button>' : ''}
        <button id="cancel" class="btn-secondary">Abbrechen</button>
      </div>
    </div>
  `;

  const passwordEl = document.getElementById('password');
  const confirmEl = isCreate ? document.getElementById('password-confirm') : null;
  const noPasswordEl = isCreate ? document.getElementById('no-password') : null;
  const submitNoPwBtn = isCreate ? document.getElementById('submit-no-pw') : null;

  // "Ohne Passwort" checkbox toggles the submit button
  if (isCreate && noPasswordEl && submitNoPwBtn) {
    noPasswordEl.onchange = () => {
      submitNoPwBtn.disabled = !noPasswordEl.checked;
    };
  }

  // Submit for "Ohne Passwort" explicit button
  if (submitNoPwBtn) {
    submitNoPwBtn.onclick = async () => {
      await chrome.storage.session.set({ passwordResult: { noPassword: true } });
      window.close();
    };
  }

  // Passkey setup button
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

  // Submit for password mode
  const submitBtn = document.getElementById('submit');
  if (submitBtn) {
    submitBtn.onclick = async () => {
      const pw = passwordEl ? passwordEl.value : '';
      const errorEl = document.getElementById('error');

      if (isCreate) {
        const pw2 = confirmEl ? confirmEl.value : '';
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
  }

  document.getElementById('cancel').onclick = () => {
    chrome.storage.session.set({ passwordResult: null });
    window.close();
  };

  if (passwordEl) {
    passwordEl.onkeypress = (e) => {
      if (e.key === 'Enter' && submitBtn) submitBtn.click();
    };
  }
  if (confirmEl) {
    confirmEl.onkeypress = (e) => {
      if (e.key === 'Enter' && submitBtn) submitBtn.click();
    };
  }
}

async function createPasskeyCredential() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const passkeyIdentity = buildPasskeyIdentity(keyScope, userId, wpDisplayName);

  // Do NOT set rp.id explicitly – the browser derives the RP ID from the
  // extension origin (chrome-extension:// or moz-extension://) automatically.
  // Setting it explicitly fails: Chrome rejects extension IDs as invalid
  // domains, and Firefox's runtime.id ≠ moz-extension hostname → SecurityError.
  const baseOptions = {
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
    attestation: 'none'
  };

  // Strategy: one single attempt with relaxed constraints.
  // We avoid sequential retries because the browser's WebAuthn prompt consumes
  // the user activation – a second attempt without a fresh click will instantly
  // fail with NotAllowedError.
  // On non-Firefox Chromium we hint 'platform' to prefer Windows Hello / Touch ID
  // but do NOT require it (no authenticatorAttachment) so the browser can fall
  // back to other authenticators if needed.
  const publicKey = {
    ...baseOptions,
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'preferred'
    }
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!credential?.rawId) {
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
  // Do NOT set rpId explicitly – let the browser derive it from the extension
  // origin, same as during credential creation.  Explicit values cause
  // SecurityError (Firefox) or NotAllowedError (Chrome).
  const request = {
    challenge: challenge.buffer,
    userVerification: 'preferred',
    timeout: PASSKEY_TIMEOUT_MS
  };
  // hints is Chromium-only (Chrome 128+). Firefox does not support it.
  if (isChromium) {
    request.hints = ['client-device'];
  }

  // Use allowCredentials with stored credential ID when available – this is
  // more reliable in extension contexts than discoverable credential lookups.
  // Only ONE attempt: sequential retries fail because the browser consumes the
  // user activation on the first WebAuthn prompt.
  let assertion = null;
  if (knownCredentialId) {
    const descriptor = {
      type: 'public-key',
      id: fromBase64Url(knownCredentialId).buffer
    };
    assertion = await navigator.credentials.get({
      publicKey: { ...request, allowCredentials: [descriptor] }
    });
  } else {
    assertion = await navigator.credentials.get({ publicKey: request });
  }

  if (!assertion || !assertion.rawId) {
    throw new Error('Passkey-Entsperrung fehlgeschlagen');
  }

  const resolvedCredentialId = toBase64Url(assertion.rawId);
  const credentialStorageKey = keyName('passkey_credential_id');
  await chrome.storage.local.set({ [credentialStorageKey]: resolvedCredentialId });

  return { credentialId: resolvedCredentialId };
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
  const debugSuffix = name ? ` [${name}: ${rawMessage.slice(0, 80)}]` : '';

  if (/Auth-Broker/i.test(rawMessage)) {
    return rawMessage;
  }

  if (name === 'NotAllowedError') {
    if (phase === 'unlock') {
      return `Passkey abgebrochen oder keine passende lokale Passkey-Identität gefunden.${debugSuffix}`;
    }
    return `Passkey-Einrichtung abgebrochen oder nicht erlaubt. Bitte erneut versuchen und den lokalen Geräte-Passkey (z. B. Windows Hello) wählen.${debugSuffix}`;
  }

  if (name === 'UnknownError' || /unknown transient reason/i.test(rawMessage)) {
    const firefoxHint = isFirefox
      ? ' Firefox unterstützt Passkeys in Erweiterungen nur eingeschränkt – verwende alternativ das Passwort-Verfahren.'
      : '';
    return `Temporärer Passkey-Fehler im Browser.${firefoxHint} Bitte Dialog erneut öffnen und noch einmal versuchen.${debugSuffix}`;
  }

  if (name === 'SecurityError') {
    return `Passkey ist in diesem Kontext nicht erlaubt (Sicherheitsrichtlinie). Bitte Seite/Extension neu laden.${debugSuffix}`;
  }

  if (name === 'InvalidStateError') {
    return `Passkey ist bereits registriert oder nicht im erwarteten Zustand.${debugSuffix}`;
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

function buildPasskeyIdentity(scope, userIdBytes, humanName = '') {
  const normalizedScope = normalizeKeyScope(scope);
  const suffix = shortHex(userIdBytes, 2);
  const wpMatch = normalizedScope.match(/^wp:(.+):u:(\d+)$/i);
  const cleanName = String(humanName || '').trim().replace(/[^a-zA-Z0-9._\- ]/g, '').trim();

  let accountLabel = 'global';
  if (wpMatch) {
    const host = String(wpMatch[1] || '').toLowerCase().replace(/[^a-z0-9.:-]/g, '-');
    const wpUserId = String(wpMatch[2] || '').trim();
    // Include human-readable name when available: u2-joachim@host
    accountLabel = cleanName
      ? `u${wpUserId}-${cleanName}@${host || 'site'}`
      : `u${wpUserId}@${host || 'site'}`;
  } else if (normalizedScope !== 'global') {
    accountLabel = normalizedScope.toLowerCase().replace(/[^a-z0-9._-]/g, '-');
  }

  const compactLabel = accountLabel.slice(0, 48) || 'global';
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
async function copyTextWithFeedback(rawText, buttonEl = null) {
  const text = String(rawText || '').trim();
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const fallbackOk = legacyCopyText(text);
    if (!fallbackOk) return false;
  }

  if (buttonEl) {
    const original = buttonEl.textContent;
    buttonEl.textContent = 'Kopiert';
    setTimeout(() => {
      buttonEl.textContent = original;
    }, 1500);
  }
  return true;
}

function legacyCopyText(text) {
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
