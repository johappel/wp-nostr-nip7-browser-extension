import { describe, it, expect } from 'vitest';
import { generateSecretKey, getPublicKey } from 'nostr-tools';
import { handleNIP04Encrypt, handleNIP04Decrypt, handleNIP44Encrypt, handleNIP44Decrypt } from '../lib/crypto-handlers.js';

describe('CryptoHandlers', () => {
  // Sender
  const sk1 = generateSecretKey();
  const pk1 = getPublicKey(sk1);

  // Empfänger
  const sk2 = generateSecretKey();
  const pk2 = getPublicKey(sk2);

  const plaintext = 'Secret Message 123';

  describe('NIP-04', () => {
    it('should encrypt and decrypt correctly', async () => {
      // Sender verschlüsselt für Empfänger
      const ciphertext = await handleNIP04Encrypt(sk1, pk2, plaintext);
      expect(ciphertext).toContain('?iv=');

      // Empfänger entschlüsselt von Sender
      const decrypted = await handleNIP04Decrypt(sk2, pk1, ciphertext);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('NIP-44', () => {
    it('should encrypt and decrypt correctly', async () => {
      // Sender verschlüsselt für Empfänger
      // Hinweis: NIP-44 in nostr-tools v2 ist synchron, aber unsere Wrapper geben es ggf. async zurück
      // oder direkt. Wir nutzen await um sicher zu sein.
      const ciphertext = await handleNIP44Encrypt(sk1, pk2, plaintext);
      
      expect(typeof ciphertext).toBe('string');
      expect(ciphertext.length).toBeGreaterThan(0);

      const decrypted = await handleNIP44Decrypt(sk2, pk1, ciphertext);
      expect(decrypted).toBe(plaintext);
    });
  });
});
