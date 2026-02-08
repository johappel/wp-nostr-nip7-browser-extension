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
    const id = crypto.randomUUID();
    const handler = (e) => {
      if (e.data.type === type + '_RESPONSE' && e.data._id === id) {
        window.removeEventListener('message', handler);
        if (e.data.error) reject(new Error(e.data.error));
        else resolve(e.data.result);
      }
    };
    window.addEventListener('message', handler);
    window.postMessage({ type, payload, _id: id }, '*');
  });
}