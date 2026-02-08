// Key manager with two storage modes:
// 1) password-protected (AES-GCM)
// 2) no-password (plain key in extension storage, weaker security)

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';

export class KeyManager {
  static STORAGE_KEY = 'encrypted_nsec';
  static SALT_KEY = 'encryption_salt';
  static IV_KEY = 'encryption_iv';
  static PLAIN_KEY = 'plain_nsec';
  static MODE_KEY = 'key_protection';

  static MODE_PASSWORD = 'password';
  static MODE_NONE = 'none';

  constructor(storage = chrome.storage.local) {
    this.storage = storage;
  }

  async hasKey() {
    const result = await this.storage.get([KeyManager.STORAGE_KEY, KeyManager.PLAIN_KEY]);
    return !!result[KeyManager.STORAGE_KEY] || !!result[KeyManager.PLAIN_KEY];
  }

  async isPasswordProtected() {
    const result = await this.storage.get([
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.PLAIN_KEY
    ]);

    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_PASSWORD) return true;
    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_NONE) return false;

    // Backward compatibility for older stored keys.
    if (result[KeyManager.STORAGE_KEY]) return true;
    if (result[KeyManager.PLAIN_KEY]) return false;
    return false;
  }

  /**
   * @param {string|null} password
   * @returns {Promise<{pubkey: string, npub: string, nsecBech32: string}>}
   */
  async generateKey(password = null) {
    const secretKey = generateSecretKey();
    const pubkey = getPublicKey(secretKey);
    const npub = nip19.npubEncode(pubkey);
    const nsecBech32 = nip19.nsecEncode(secretKey);

    await this.storeKey(secretKey, password);
    secretKey.fill(0);

    return { pubkey, npub, nsecBech32 };
  }

  /**
   * @param {Uint8Array} secretKey
   * @param {string|null} password
   */
  async storeKey(secretKey, password = null) {
    if (!password) {
      await this.storage.set({
        [KeyManager.PLAIN_KEY]: Array.from(secretKey),
        [KeyManager.MODE_KEY]: KeyManager.MODE_NONE,
        created: Date.now()
      });
      await this.storage.remove([KeyManager.STORAGE_KEY, KeyManager.SALT_KEY, KeyManager.IV_KEY]);
      return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, secretKey);

    await this.storage.set({
      [KeyManager.STORAGE_KEY]: Array.from(new Uint8Array(ciphertext)),
      [KeyManager.SALT_KEY]: Array.from(salt),
      [KeyManager.IV_KEY]: Array.from(iv),
      [KeyManager.MODE_KEY]: KeyManager.MODE_PASSWORD,
      created: Date.now()
    });
    await this.storage.remove(KeyManager.PLAIN_KEY);
  }

  /**
   * @param {string|null} password
   * @returns {Promise<Uint8Array|null>}
   */
  async getKey(password = null) {
    const result = await this.storage.get([
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.SALT_KEY,
      KeyManager.IV_KEY,
      KeyManager.PLAIN_KEY
    ]);

    const mode = result[KeyManager.MODE_KEY]
      || (result[KeyManager.STORAGE_KEY] ? KeyManager.MODE_PASSWORD : null)
      || (result[KeyManager.PLAIN_KEY] ? KeyManager.MODE_NONE : null);

    if (!mode) return null;

    if (mode === KeyManager.MODE_NONE) {
      if (!result[KeyManager.PLAIN_KEY]) return null;
      return new Uint8Array(result[KeyManager.PLAIN_KEY]);
    }

    if (!password) throw new Error('Password required');
    if (!result[KeyManager.STORAGE_KEY]) return null;

    const ciphertext = new Uint8Array(result[KeyManager.STORAGE_KEY]);
    const salt = new Uint8Array(result[KeyManager.SALT_KEY]);
    const iv = new Uint8Array(result[KeyManager.IV_KEY]);

    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);

    return new Uint8Array(decrypted);
  }

  /**
   * @param {object} eventTemplate
   * @param {string|null} password
   */
  async signEvent(eventTemplate, password = null) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    const signed = finalizeEvent(eventTemplate, secretKey);
    secretKey.fill(0);
    return signed;
  }

  /**
   * @param {string|null} password
   */
  async getPublicKey(password = null) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    const pubkey = getPublicKey(secretKey);
    secretKey.fill(0);
    return pubkey;
  }
}

export default KeyManager;
