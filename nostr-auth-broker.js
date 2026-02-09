(function () {
  'use strict';

  const config = window.nostrAuthBrokerConfig || {};
  const statusNode = document.getElementById('nostr-auth-broker-status');

  setStatus('Bereit. Warte auf Assertion-Anfrage...');
  postToOpener({
    type: 'NOSTR_AUTH_BROKER_READY',
    rpId: String(config.rpId || ''),
    origin: String(config.origin || '')
  });

  window.addEventListener('message', async (event) => {
    if (event.source !== window.opener) return;
    const data = event?.data;
    if (!data || typeof data !== 'object') return;
    if (data.type !== 'NOSTR_AUTH_BROKER_ASSERT_REQUEST') return;

    const requestId = String(data.requestId || '').trim() || `req-${Date.now()}`;
    const intent = String(data.intent || 'generic');

    try {
      setStatus('Lade WebAuthn-Challenge...');
      const challenge = await requestChallenge(intent);

      setStatus('Bitte Passkey bestaetigen...');
      const assertionPayload = await runAssertion(challenge.challengeOptions || {});

      setStatus('Verifiziere Assertion...');
      const verifyResult = await verifyAssertion(challenge.challengeId, assertionPayload);

      setStatus('Erfolgreich verifiziert. Du kannst das Fenster schliessen.');
      postToOpener({
        type: 'NOSTR_AUTH_BROKER_ASSERT_RESULT',
        requestId,
        result: {
          ...(verifyResult && typeof verifyResult === 'object' ? verifyResult : {}),
          credentialId: assertionPayload.credentialId
        }
      });
    } catch (error) {
      const message = mapError(error);
      setStatus(message);
      postToOpener({
        type: 'NOSTR_AUTH_BROKER_ASSERT_RESULT',
        requestId,
        error: message
      });
    }
  });

  async function requestChallenge(intent) {
    return await postJson('webauthn/assert/challenge', { intent });
  }

  async function verifyAssertion(challengeId, payload) {
    return await postJson('webauthn/assert/verify', {
      challengeId,
      credentialId: payload.credentialId,
      clientDataJSON: payload.clientDataJSON,
      authenticatorData: payload.authenticatorData,
      signature: payload.signature,
      userHandle: payload.userHandle
    });
  }

  async function runAssertion(options) {
    const challenge = fromBase64Url(options.challenge);
    const request = {
      challenge,
      userVerification: String(options.userVerification || 'preferred'),
      timeout: Number(options.timeout || 120000)
    };

    if (options.rpId) {
      request.rpId = String(options.rpId);
    }

    if (Array.isArray(options.allowCredentials) && options.allowCredentials.length > 0) {
      request.allowCredentials = options.allowCredentials
        .map((item) => {
          const id = String(item?.id || '').trim();
          if (!id) return null;
          const descriptor = {
            type: 'public-key',
            id: fromBase64Url(id)
          };
          if (Array.isArray(item?.transports) && item.transports.length > 0) {
            descriptor.transports = item.transports;
          }
          return descriptor;
        })
        .filter(Boolean);
    }

    const assertion = await navigator.credentials.get({ publicKey: request });
    if (!assertion || !assertion.response) {
      throw new Error('Passkey assertion failed');
    }

    return {
      credentialId: toBase64Url(assertion.rawId),
      clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
      authenticatorData: toBase64Url(assertion.response.authenticatorData),
      signature: toBase64Url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? toBase64Url(assertion.response.userHandle) : null
    };
  }

  async function postJson(path, payload) {
    const restBase = normalizeRestBase(config.restUrl);
    if (!restBase) {
      throw new Error('REST URL fehlt im Broker-Kontext.');
    }

    const response = await fetch(new URL(path.replace(/^\//, ''), restBase).toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WP-Nonce': String(config.nonce || '')
      },
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify(payload || {})
    });

    let result = {};
    try {
      result = await response.json();
    } catch {
      result = {};
    }

    if (!response.ok) {
      const error = new Error(String(result?.message || `HTTP ${response.status}`));
      error.code = String(result?.code || '');
      error.status = Number(response.status || 0);
      throw error;
    }
    return result;
  }

  function normalizeRestBase(restUrl) {
    const value = String(restUrl || '').trim();
    if (!value) return null;
    try {
      const url = new URL(value);
      return url.href.endsWith('/') ? url.href : `${url.href}/`;
    } catch {
      return null;
    }
  }

  function setStatus(text) {
    if (!statusNode) return;
    statusNode.textContent = String(text || '');
  }

  function postToOpener(payload) {
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(payload, '*');
      }
    } catch {
      // no-op
    }
  }

  function mapError(error) {
    const name = String(error?.name || '');
    const code = String(error?.code || '');
    const status = Number(error?.status || 0);
    const message = String(error?.message || error || '');

    if (name === 'NotAllowedError') {
      return 'Passkey wurde abgebrochen oder ist in diesem Kontext nicht verfuegbar.';
    }
    if (status === 501 && code === 'webauthn_verifier_unavailable') {
      return 'Server-Verifikation ist noch nicht aktiviert (Auth-Broker Dev/Verifier konfigurieren).';
    }
    if (status === 503 && code === 'auth_broker_disabled') {
      return 'Auth-Broker ist auf dem Server deaktiviert.';
    }
    return message || 'Auth-Broker Fehler';
  }

  function toBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function fromBase64Url(input) {
    const source = String(input || '').trim();
    if (!source) return new Uint8Array();
    const base64 = source.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
})();
