// Key Manager – AES-GCM verschlüsselter Storage
// Extrahiert für bessere Testbarkeit

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';

export class KeyManager {
  // Storage Keys
  static STORAGE_KEY = 'encrypted_nsec';
  static SALT_KEY   = 'encryption_salt';
  static IV_KEY     = 'encryption_iv';
  
  constructor(storage = chrome.storage.local) {
    this.storage = storage;
  }

  async hasKey() {
    const result = await this.storage.get([KeyManager.STORAGE_KEY]);
    return !!result[KeyManager.STORAGE_KEY];
  }

  /**
   * Generiert einen neuen Schlüssel und speichert ihn verschlüsselt
   * @param {string} password - Passwort für Verschlüsselung
   * @returns {Promise<{pubkey: string, npub: string, nsecBech32: string}>}
   */
  async generateKey(password) {
    const secretKey = generateSecretKey();          // Uint8Array (32 bytes)
    const pubkey    = getPublicKey(secretKey);       // hex string
    const npub      = nip19.npubEncode(pubkey);
    const nsecBech32 = nip19.nsecEncode(secretKey);

    await this.storeKey(secretKey, password);
    secretKey.fill(0);                              // Memory wipe

    return { pubkey, npub, nsecBech32 };
  }

  /**
   * Speichert Secret Key AES-GCM verschlüsselt
   * @param {Uint8Array} secretKey - 32-byte secret key
   * @param {string} password - Passwort für Verschlüsselung
   */
  async storeKey(secretKey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));

    const enc      = new TextEncoder();
    const baseKey  = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey   = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, secretKey
    );

    await this.storage.set({
      [KeyManager.STORAGE_KEY]: Array.from(new Uint8Array(ciphertext)),
      [KeyManager.SALT_KEY]:    Array.from(salt),
      [KeyManager.IV_KEY]:      Array.from(iv),
      created: Date.now()
    });
  }

  /**
   * Entschlüsselt und lädt Secret Key
   * @param {string} password - Passwort für Entschlüsselung
   * @returns {Promise<Uint8Array|null>} - 32-byte secret key oder null
   */
  async getKey(password) {
    const result = await this.storage.get([
      KeyManager.STORAGE_KEY, KeyManager.SALT_KEY, KeyManager.IV_KEY
    ]);
    if (!result[KeyManager.STORAGE_KEY]) return null;

    const ciphertext = new Uint8Array(result[KeyManager.STORAGE_KEY]);
    const salt       = new Uint8Array(result[KeyManager.SALT_KEY]);
    const iv         = new Uint8Array(result[KeyManager.IV_KEY]);

    const enc     = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const aesKey  = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, aesKey, ciphertext
    );

    return new Uint8Array(decrypted); // 32-byte secret key
  }

  /**
   * Signiert ein Event
   * @param {object} eventTemplate - Event ohne id, pubkey, sig
   * @param {string} password - Passwort zum Entschlüsseln
   * @returns {Promise<object>} - Vollständiges signiertes Event
   */
  async signEvent(eventTemplate, password) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    // finalizeEvent fügt id, pubkey, sig hinzu und gibt vollständiges Event zurück
    const signed = finalizeEvent(eventTemplate, secretKey);
    secretKey.fill(0);

    return signed; // { id, pubkey, created_at, kind, tags, content, sig }
  }

  /**
   * Erfragt Public Key
   * @param {string} password - Passwort zum Entschlüsseln
   * @returns {Promise<string>} - Hex-String des Public Keys
   */
  async getPublicKey(password) {
    const secretKey = await this.getKey(password);
    if (!secretKey) throw new Error('No key found');

    const pubkey = getPublicKey(secretKey);
    secretKey.fill(0);
    
    return pubkey; // Hex-String (64 chars)
  }
}

export default KeyManager;