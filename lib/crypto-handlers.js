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
 */
export function handleNIP44Encrypt(secretKey, pubkey, text) {
  const conversationKey = nip44.v2.utils.getConversationKey(secretKey, pubkey);
  return nip44.v2.encrypt(text, conversationKey);
}

/**
 * NIP-44 Decrypt (Modern)
 */
export function handleNIP44Decrypt(secretKey, pubkey, ciphertext) {
  const conversationKey = nip44.v2.utils.getConversationKey(secretKey, pubkey);
  return nip44.v2.decrypt(ciphertext, conversationKey);
}

// ============================================================
// NIP-44 Hilfsfunktionen für NIP-17 Gift Wrap
// ============================================================

/**
 * Berechnet den NIP-44 Conversation Key aus Secret Key und Public Key.
 * Wird für NIP-17 Gift Wrap Encryption benötigt.
 * @param {Uint8Array} secretKey - Der eigene Secret Key (32 Bytes)
 * @param {string} pubkey - Hex-String des Gegenübers (64 Zeichen)
 * @returns {Uint8Array} - Conversation Key (32 Bytes)
 */
export function getNip44ConversationKey(secretKey, pubkey) {
  return nip44.v2.utils.getConversationKey(secretKey, pubkey);
}

/**
 * NIP-44 Encrypt mit vorgegebenem Conversation Key.
 * Wird für NIP-17 Gift Wrap benötigt.
 * @param {string} plaintext - Der zu verschlüsselnde Text
 * @param {Uint8Array} conversationKey - Der Conversation Key (32 Bytes)
 * @returns {string} - Verschlüsselter Text (Base64)
 */
export function nip44EncryptWithKey(plaintext, conversationKey) {
  return nip44.v2.encrypt(plaintext, conversationKey);
}

/**
 * NIP-44 Decrypt mit vorgegebenem Conversation Key.
 * Wird für NIP-17 Gift Wrap Entschlüsselung benötigt.
 * @param {string} ciphertext - Der verschlüsselte Text (Base64)
 * @param {Uint8Array} conversationKey - Der Conversation Key (32 Bytes)
 * @returns {string} - Entschlüsselter Text
 */
export function nip44DecryptWithKey(ciphertext, conversationKey) {
  return nip44.v2.decrypt(ciphertext, conversationKey);
}
