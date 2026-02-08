# TASK-04: NIP-04 & NIP-44 Encryption

## Ziel
Verschlüsselte Nachrichten entsprechend NIP-04 (Legacy) und NIP-44 (Recommended) Standard.

## Abhängigkeiten
- **TASK-03: Extension Key-Management & UI** muss abgeschlossen sein

## Ergebnis
- NIP-04 Encryption/Decryption funktioniert (Legacy)
- NIP-44 v2 Encryption/Decryption funktioniert (Recommended)

---

## Zu erstellende Datei

### lib/crypto-handlers.js

**Pfad:** `src/lib/crypto-handlers.js`

```javascript
import { nip04 } from 'nostr-tools';
import { v2 as nip44 } from 'nostr-tools/nip44';

export async function handleNIP04(request, keyManager, password) {
  const secretKey = await keyManager.getKey(password);
  if (!secretKey) throw new Error('Key not available');

  const { pubkey, plaintext, ciphertext } = request.payload || {};

  try {
    if (request.type === 'NOSTR_NIP04_ENCRYPT') {
      if (!pubkey || !plaintext) throw new Error('Missing pubkey or plaintext');
      return await nip04.encrypt(secretKey, pubkey, plaintext);
    } else {
      if (!pubkey || !ciphertext) throw new Error('Missing pubkey or ciphertext');
      return await nip04.decrypt(secretKey, pubkey, ciphertext);
    }
  } finally {
    secretKey.fill(0);
  }
}

export async function handleNIP44(request, keyManager, password) {
  const secretKey = await keyManager.getKey(password);
  if (!secretKey) throw new Error('Key not available');

  const { pubkey, plaintext, ciphertext } = request.payload || {};

  try {
    const conversationKey = nip44.utils.getConversationKey(secretKey, pubkey);

    if (request.type === 'NOSTR_NIP44_ENCRYPT') {
      if (!plaintext) throw new Error('Missing plaintext');
      return nip44.encrypt(plaintext, conversationKey);
    } else {
      if (!ciphertext) throw new Error('Missing ciphertext');
      return nip44.decrypt(ciphertext, conversationKey);
    }
  } finally {
    secretKey.fill(0);
  }
}

export default { handleNIP04, handleNIP44 };
```

### Integration in background.js

```javascript
import { handleNIP04, handleNIP44 } from './lib/crypto-handlers.js';

// Im handleMessage switch:
case 'NOSTR_NIP04_ENCRYPT':
case 'NOSTR_NIP04_DECRYPT':
  return handleNIP04(request, keyManager, cachedPassword);

case 'NOSTR_NIP44_ENCRYPT':
case 'NOSTR_NIP44_DECRYPT':
  return handleNIP44(request, keyManager, cachedPassword);
```

---

## Akzeptanzkriterien

- [ ] NIP-04 encrypt/decrypt Roundtrip funktioniert
- [ ] NIP-44 v2 encrypt/decrypt Roundtrip funktioniert
- [ ] Memory-Wipe nach jeder Operation
- [ ] NIP-07 konforme Rückgabe (String)
