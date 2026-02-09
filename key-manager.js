// Key manager with two storage modes:
// 1) password-protected (AES-GCM)
// 2) no-password (plain key in extension storage, weaker security)

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';

export class KeyManager {
  static STORAGE_KEY = 'encrypted_nsec';
  static SALT_KEY = 'encryption_salt';
  static IV_KEY = 'encryption_iv';
  static PLAIN_KEY = 'plain_nsec';
  static PASSKEY_ID_KEY = 'passkey_credential_id';
  static MODE_KEY = 'key_protection';
  static CREATED_KEY = 'created';
  static LEGACY_MIGRATED_KEY = 'migrated_from_legacy_global';
  static LEGACY_GLOBAL_CONSUMED_KEY = 'legacy_global_consumed_scope';

  static MODE_PASSWORD = 'password';
  static MODE_PASSKEY = 'passkey';
  static MODE_NONE = 'none';

  constructor(storage = chrome.storage.local, namespace = '') {
    this.storage = storage;
    this.namespace = this.normalizeNamespace(namespace);
  }

  normalizeNamespace(namespace) {
    const value = String(namespace || '').trim();
    if (!value || value === 'global') return '';
    return value.replace(/[^a-zA-Z0-9:._-]/g, '_').slice(0, 120);
  }

  setNamespace(namespace) {
    this.namespace = this.normalizeNamespace(namespace);
  }

  getNamespace() {
    return this.namespace || 'global';
  }

  keyName(baseKey) {
    if (!this.namespace) return baseKey;
    return `${this.namespace}::${baseKey}`;
  }

  keyNames(baseKeys) {
    return baseKeys.map((baseKey) => this.keyName(baseKey));
  }

  mapFromStorage(result, baseKeys) {
    const mapped = {};
    for (const baseKey of baseKeys) {
      mapped[baseKey] = result[this.keyName(baseKey)];
    }
    return mapped;
  }

  async migrateFromLegacyGlobalIfNeeded() {
    if (!this.namespace) return;

    const scopedKeys = [
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.SALT_KEY,
      KeyManager.IV_KEY,
      KeyManager.PLAIN_KEY,
      KeyManager.PASSKEY_ID_KEY,
      KeyManager.CREATED_KEY,
      KeyManager.LEGACY_MIGRATED_KEY
    ];

    const scopedRaw = await this.storage.get(this.keyNames(scopedKeys));
    const scoped = this.mapFromStorage(scopedRaw, scopedKeys);

    if (scoped[KeyManager.LEGACY_MIGRATED_KEY]) return;

    const globalMeta = await this.storage.get([KeyManager.LEGACY_GLOBAL_CONSUMED_KEY]);
    const consumedScope = String(globalMeta[KeyManager.LEGACY_GLOBAL_CONSUMED_KEY] || '').trim();
    if (consumedScope && consumedScope !== this.namespace) {
      await this.storage.set({ [this.keyName(KeyManager.LEGACY_MIGRATED_KEY)]: true });
      return;
    }

    if (scoped[KeyManager.STORAGE_KEY] || scoped[KeyManager.PLAIN_KEY]) {
      await this.storage.set({ [this.keyName(KeyManager.LEGACY_MIGRATED_KEY)]: true });
      return;
    }

    const legacyRaw = await this.storage.get([
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.SALT_KEY,
      KeyManager.IV_KEY,
      KeyManager.PLAIN_KEY,
      KeyManager.PASSKEY_ID_KEY,
      KeyManager.CREATED_KEY
    ]);

    const hasLegacyKey = Boolean(legacyRaw[KeyManager.STORAGE_KEY] || legacyRaw[KeyManager.PLAIN_KEY]);
    if (!hasLegacyKey) {
      await this.storage.set({ [this.keyName(KeyManager.LEGACY_MIGRATED_KEY)]: true });
      return;
    }

    const updatePayload = {
      [this.keyName(KeyManager.LEGACY_MIGRATED_KEY)]: true,
      [KeyManager.LEGACY_GLOBAL_CONSUMED_KEY]: this.namespace
    };
    const copyKeys = [
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.SALT_KEY,
      KeyManager.IV_KEY,
      KeyManager.PLAIN_KEY,
      KeyManager.PASSKEY_ID_KEY,
      KeyManager.CREATED_KEY
    ];
    for (const key of copyKeys) {
      if (legacyRaw[key] !== undefined) {
        updatePayload[this.keyName(key)] = legacyRaw[key];
      }
    }

    await this.storage.set(updatePayload);
  }

  async hasKey() {
    const keys = [KeyManager.STORAGE_KEY, KeyManager.PLAIN_KEY];
    const raw = await this.storage.get(this.keyNames(keys));
    const result = this.mapFromStorage(raw, keys);
    return !!result[KeyManager.STORAGE_KEY] || !!result[KeyManager.PLAIN_KEY];
  }

  async isPasswordProtected() {
    const keys = [
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.PLAIN_KEY
    ];
    const raw = await this.storage.get(this.keyNames(keys));
    const result = this.mapFromStorage(raw, keys);

    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_PASSWORD) return true;
    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_PASSKEY) return false;
    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_NONE) return false;

    // Backward compatibility for older stored keys.
    if (result[KeyManager.STORAGE_KEY]) return true;
    if (result[KeyManager.PLAIN_KEY]) return false;
    return false;
  }

  async getProtectionMode() {
    const keys = [
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.PLAIN_KEY,
      KeyManager.PASSKEY_ID_KEY
    ];
    const raw = await this.storage.get(this.keyNames(keys));
    const result = this.mapFromStorage(raw, keys);

    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_PASSWORD) return KeyManager.MODE_PASSWORD;
    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_PASSKEY) return KeyManager.MODE_PASSKEY;
    if (result[KeyManager.MODE_KEY] === KeyManager.MODE_NONE) return KeyManager.MODE_NONE;

    if (result[KeyManager.STORAGE_KEY]) return KeyManager.MODE_PASSWORD;
    if (result[KeyManager.PLAIN_KEY] && result[KeyManager.PASSKEY_ID_KEY]) return KeyManager.MODE_PASSKEY;
    if (result[KeyManager.PLAIN_KEY]) return KeyManager.MODE_NONE;
    return null;
  }

  /**
   * @param {string|null} password
   * @returns {Promise<{pubkey: string, npub: string, nsecBech32: string}>}
   */
  async generateKey(password = null, options = {}) {
    const secretKey = generateSecretKey();
    const pubkey = getPublicKey(secretKey);
    const npub = nip19.npubEncode(pubkey);
    const nsecBech32 = nip19.nsecEncode(secretKey);

    await this.storeKey(secretKey, password, options);
    secretKey.fill(0);

    return { pubkey, npub, nsecBech32 };
  }

  /**
   * @param {Uint8Array} secretKey
   * @param {string|null} password
   */
  async storeKey(secretKey, password = null, options = {}) {
    const requestedMode = typeof options.mode === 'string' ? options.mode : null;
    const mode = requestedMode || (password ? KeyManager.MODE_PASSWORD : KeyManager.MODE_NONE);

    if (mode === KeyManager.MODE_PASSKEY) {
      const passkeyCredentialId = String(options.passkeyCredentialId || '').trim();
      if (!passkeyCredentialId) {
        throw new Error('Passkey credential id required');
      }

      await this.storage.set({
        [this.keyName(KeyManager.PLAIN_KEY)]: Array.from(secretKey),
        [this.keyName(KeyManager.PASSKEY_ID_KEY)]: passkeyCredentialId,
        [this.keyName(KeyManager.MODE_KEY)]: KeyManager.MODE_PASSKEY,
        [this.keyName(KeyManager.CREATED_KEY)]: Date.now()
      });
      await this.storage.remove(this.keyNames([KeyManager.STORAGE_KEY, KeyManager.SALT_KEY, KeyManager.IV_KEY]));
      return;
    }

    if (!password) {
      await this.storage.set({
        [this.keyName(KeyManager.PLAIN_KEY)]: Array.from(secretKey),
        [this.keyName(KeyManager.MODE_KEY)]: KeyManager.MODE_NONE,
        [this.keyName(KeyManager.CREATED_KEY)]: Date.now()
      });
      await this.storage.remove(this.keyNames([KeyManager.STORAGE_KEY, KeyManager.SALT_KEY, KeyManager.IV_KEY, KeyManager.PASSKEY_ID_KEY]));
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
      [this.keyName(KeyManager.STORAGE_KEY)]: Array.from(new Uint8Array(ciphertext)),
      [this.keyName(KeyManager.SALT_KEY)]: Array.from(salt),
      [this.keyName(KeyManager.IV_KEY)]: Array.from(iv),
      [this.keyName(KeyManager.MODE_KEY)]: KeyManager.MODE_PASSWORD,
      [this.keyName(KeyManager.CREATED_KEY)]: Date.now()
    });
    await this.storage.remove(this.keyNames([KeyManager.PLAIN_KEY, KeyManager.PASSKEY_ID_KEY]));
  }

  /**
   * @param {string|null} password
   * @returns {Promise<Uint8Array|null>}
   */
  async getKey(password = null) {
    const keys = [
      KeyManager.MODE_KEY,
      KeyManager.STORAGE_KEY,
      KeyManager.SALT_KEY,
      KeyManager.IV_KEY,
      KeyManager.PLAIN_KEY,
      KeyManager.PASSKEY_ID_KEY
    ];
    const raw = await this.storage.get(this.keyNames(keys));
    const result = this.mapFromStorage(raw, keys);

    const mode = result[KeyManager.MODE_KEY]
      || (result[KeyManager.STORAGE_KEY] ? KeyManager.MODE_PASSWORD : null)
      || (result[KeyManager.PLAIN_KEY] && result[KeyManager.PASSKEY_ID_KEY] ? KeyManager.MODE_PASSKEY : null)
      || (result[KeyManager.PLAIN_KEY] ? KeyManager.MODE_NONE : null);

    if (!mode) return null;

    if (mode === KeyManager.MODE_PASSKEY) {
      if (!result[KeyManager.PLAIN_KEY]) return null;
      return new Uint8Array(result[KeyManager.PLAIN_KEY]);
    }

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
