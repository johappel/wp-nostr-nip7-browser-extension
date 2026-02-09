import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager } from '../lib/key-manager.js';
import './setup.js'; // Importiert Mocks

describe('KeyManager', () => {
  let keyManager;
  const password = 'secure-password-123';

  beforeEach(() => {
    keyManager = new KeyManager(chrome.storage.local);
  });

  it('should generate and store a key securely', async () => {
    const { pubkey, npub, nsecBech32 } = await keyManager.generateKey(password);

    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(npub).toMatch(/^npub1/);
    expect(nsecBech32).toMatch(/^nsec1/);

    // Prüfe ob Storage Daten enthält
    const stored = await chrome.storage.local.get([KeyManager.STORAGE_KEY]);
    expect(stored[KeyManager.STORAGE_KEY]).toBeDefined();
  });

  it('should retrieve the key with correct password', async () => {
    await keyManager.generateKey(password);
    
    const secretKey = await keyManager.getKey(password);
    expect(secretKey).toBeInstanceOf(Uint8Array);
    expect(secretKey.length).toBe(32);
  });

  it('should support no-password mode when requested', async () => {
    const { pubkey } = await keyManager.generateKey(null);

    expect(await keyManager.isPasswordProtected()).toBe(false);

    const secretKey = await keyManager.getKey(null);
    expect(secretKey).toBeInstanceOf(Uint8Array);
    expect(secretKey.length).toBe(32);

    const pubkey2 = await keyManager.getPublicKey(null);
    expect(pubkey2).toBe(pubkey);
  });

  it('should support passkey mode when credential id is provided', async () => {
    const { pubkey } = await keyManager.generateKey(null, {
      mode: KeyManager.MODE_PASSKEY,
      passkeyCredentialId: 'test-passkey-credential-id'
    });

    expect(await keyManager.getProtectionMode()).toBe(KeyManager.MODE_PASSKEY);
    expect(await keyManager.isPasswordProtected()).toBe(false);

    const stored = await chrome.storage.local.get([KeyManager.PASSKEY_ID_KEY, KeyManager.PLAIN_KEY]);
    expect(stored[KeyManager.PASSKEY_ID_KEY]).toBe('test-passkey-credential-id');
    expect(stored[KeyManager.PLAIN_KEY]).toBeDefined();

    const pubkey2 = await keyManager.getPublicKey(null);
    expect(pubkey2).toBe(pubkey);
  });

  it('should fail to retrieve key with wrong password', async () => {
    await keyManager.generateKey(password);
    
    await expect(keyManager.getKey('wrong-password')).rejects.toThrow();
  });

  it('should sign an event correctly', async () => {
    const { pubkey } = await keyManager.generateKey(password);
    
    const eventTemplate = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: 'Hello Nostr'
    };

    const signedEvent = await keyManager.signEvent(eventTemplate, password);

    expect(signedEvent.pubkey).toBe(pubkey);
    expect(signedEvent.sig).toBeDefined();
    expect(signedEvent.id).toBeDefined();
  });

  it('should return public key', async () => {
    const { pubkey: originalPubkey } = await keyManager.generateKey(password);
    const retrievedPubkey = await keyManager.getPublicKey(password);
    
    expect(retrievedPubkey).toBe(originalPubkey);
  });

  it('should provide stored public key without unlock', async () => {
    const { pubkey: originalPubkey } = await keyManager.generateKey(password);
    const storedPubkey = await keyManager.getStoredPublicKey();
    expect(storedPubkey).toBe(originalPubkey);
  });

  it('should return false for hasKey if empty', async () => {
    expect(await keyManager.hasKey()).toBe(false);
  });

  it('should isolate keys per namespace scope', async () => {
    const scopeA = new KeyManager(chrome.storage.local, 'wp:forums.test:u:11');
    const scopeB = new KeyManager(chrome.storage.local, 'wp:forums.test:u:22');

    const { pubkey: pubkeyA } = await scopeA.generateKey('scope-a-password');
    expect(await scopeA.hasKey()).toBe(true);
    expect(await scopeB.hasKey()).toBe(false);

    const { pubkey: pubkeyB } = await scopeB.generateKey('scope-b-password');
    expect(await scopeB.hasKey()).toBe(true);
    expect(pubkeyA).not.toBe(pubkeyB);

    const stored = await chrome.storage.local.get([
      'wp:forums.test:u:11::' + KeyManager.MODE_KEY,
      'wp:forums.test:u:22::' + KeyManager.MODE_KEY
    ]);
    expect(stored['wp:forums.test:u:11::' + KeyManager.MODE_KEY]).toBe(KeyManager.MODE_PASSWORD);
    expect(stored['wp:forums.test:u:22::' + KeyManager.MODE_KEY]).toBe(KeyManager.MODE_PASSWORD);
  });

  it('should migrate legacy global key to first scope only', async () => {
    const legacy = new KeyManager(chrome.storage.local);
    const { pubkey: legacyPubkey } = await legacy.generateKey('legacy-password');

    const firstScope = new KeyManager(chrome.storage.local, 'wp:forums.test:u:101');
    await firstScope.migrateFromLegacyGlobalIfNeeded();
    expect(await firstScope.hasKey()).toBe(true);
    expect(await firstScope.getPublicKey('legacy-password')).toBe(legacyPubkey);

    const secondScope = new KeyManager(chrome.storage.local, 'wp:forums.test:u:202');
    await secondScope.migrateFromLegacyGlobalIfNeeded();
    expect(await secondScope.hasKey()).toBe(false);
  });
});
