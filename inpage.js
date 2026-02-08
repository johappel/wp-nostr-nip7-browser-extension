// NIP-07 Standard API
window.nostr = {
  getPublicKey: async () => {
    return sendRequest('NOSTR_GET_PUBLIC_KEY');
  },
  
  signEvent: async (event) => {
    return sendRequest('NOSTR_SIGN_EVENT', event);
  },
  
  getRelays: async () => {
    return sendRequest('NOSTR_GET_RELAYS');
  },
  
  nip04: {
    encrypt: async (pubkey, plaintext) => {
      return sendRequest('NOSTR_NIP04_ENCRYPT', { pubkey, plaintext });
    },
    decrypt: async (pubkey, ciphertext) => {
      return sendRequest('NOSTR_NIP04_DECRYPT', { pubkey, ciphertext });
    }
  },
  
  nip44: {
    encrypt: async (pubkey, plaintext) => {
      return sendRequest('NOSTR_NIP44_ENCRYPT', { pubkey, plaintext });
    },
    decrypt: async (pubkey, ciphertext) => {
      return sendRequest('NOSTR_NIP44_DECRYPT', { pubkey, ciphertext });
    }
  }
};

function sendRequest(type, payload = null) {
  return new Promise((resolve, reject) => {
    const id = createRequestId();
    const handler = (e) => {
      const data = e?.data;
      if (!data || typeof data !== 'object') return;

      if (data.type === type + '_RESPONSE' && data._id === id) {
        window.removeEventListener('message', handler);
        if (data.error) reject(new Error(data.error));
        else resolve(data.result);
      }
    };
    window.addEventListener('message', handler);
    window.postMessage({ type, payload, _id: id }, '*');
  });
}

function createRequestId() {
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
