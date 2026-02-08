# TASK-09: Unit Tests

## Ziel
Alle sicherheitskritischen und logischen Module mit Tests absichern.

## vitest.config.js

```javascript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.js']
  }
});
```

## Test-Dateien

### tests/key-manager.test.js

```javascript
import { describe, it, expect } from 'vitest';
import { KeyManager } from '../src/lib/key-manager.js';

describe('KeyManager', () => {
  it('generates key with correct format', async () => {
    const mockStorage = {
      data: {},
      async get(keys) {
        const result = {};
        keys.forEach(k => result[k] = this.data[k]);
        return result;
      },
      async set(items) {
        Object.assign(this.data, items);
      }
    };
    
    const km = new KeyManager(mockStorage);
    const result = await km.generateKey('test-password-12345');
    
    expect(result.pubkey).toMatch(/^[a-f0-9]{64}$/);
    expect(result.npub).toMatch(/^npub1/);
  });
});
```

### tests/nip07-conformity.test.js

```javascript
import { describe, it, expect } from 'vitest';
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools';

describe('NIP-07', () => {
  it('getPublicKey returns hex', () => {
    const key = generateSecretKey();
    const pubkey = getPublicKey(key);
    expect(pubkey).toMatch(/^[a-f0-9]{64}$/);
  });

  it('signEvent returns full event', () => {
    const key = generateSecretKey();
    const event = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: 'Test'
    };
    
    const signed = finalizeEvent(event, key);
    expect(signed).toHaveProperty('id');
    expect(signed).toHaveProperty('sig');
    expect(verifyEvent(signed)).toBe(true);
  });
});
```

## Akzeptanzkriterien

- [ ] Alle Tests laufen durch
- [ ] Coverage >= 80% für src/lib/
