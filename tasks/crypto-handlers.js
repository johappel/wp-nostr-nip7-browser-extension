import { nip04, nip44 } from 'nostr-tools';

/**
 * NIP-04 Encrypt (Legacy)
 */
export async function handleNIP04Encrypt(secretKey, pubkey, text) {
  return await nip04.encrypt(secretKey, pubkey, text);
}

/**
 * NIP-04 Decrypt (Legacy)
 */
export async function handleNIP04Decrypt(secretKey, pubkey, ciphertext) {
  return await nip04.decrypt(secretKey, pubkey, ciphertext);
}

/**
 * NIP-44 Encrypt (Modern)
 * nostr-tools v2 implementation
 */
export function handleNIP44Encrypt(secretKey, pubkey, text) {
  // NIP-44 encrypt ist in nostr-tools v2 oft synchron, aber wir geben es async zurück
  // um konsistent mit der API zu bleiben.
  return nip44.encrypt(secretKey, pubkey, text);
}

/**
 * NIP-44 Decrypt (Modern)
 */
export function handleNIP44Decrypt(secretKey, pubkey, ciphertext) {
  return nip44.decrypt(secretKey, pubkey, ciphertext);
}