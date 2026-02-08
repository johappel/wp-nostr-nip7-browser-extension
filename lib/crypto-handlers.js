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
