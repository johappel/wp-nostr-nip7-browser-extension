import { describe, it, expect, beforeEach } from 'vitest';
import { checkDomainAccess, allowDomain, blockDomain, verifyWhitelistSignature, DOMAIN_STATUS } from '../lib/domain-access.js';
import './setup.js';

describe('DomainAccess', () => {
  const domain = 'example.com';

  it('should return PENDING for unknown domain', async () => {
    const status = await checkDomainAccess(domain);
    expect(status).toBe(DOMAIN_STATUS.PENDING);
  });

  it('should return ALLOWED for whitelisted domain', async () => {
    await allowDomain(domain);
    const status = await checkDomainAccess(domain);
    expect(status).toBe(DOMAIN_STATUS.ALLOWED);
  });

  it('should return BLOCKED for blocked domain', async () => {
    await blockDomain(domain);
    const status = await checkDomainAccess(domain);
    expect(status).toBe(DOMAIN_STATUS.BLOCKED);
  });

  it('should verify valid HMAC signature', async () => {
    const secret = 'my-secret-key';
    const domains = ['example.com', 'nostr.org'];
    const timestamp = Math.floor(Date.now() / 1000);
    
    // Erstelle valide Signatur (Simulation PHP-Seite)
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
    const payload = JSON.stringify(domains);
    const data = enc.encode(payload + '|' + timestamp);
    const signatureBuf = await crypto.subtle.sign('HMAC', key, data);
    const signatureHex = Array.from(new Uint8Array(signatureBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const isValid = await verifyWhitelistSignature(domains, timestamp, signatureHex, secret);
    expect(isValid).toBe(true);
  });

  it('should reject invalid HMAC signature', async () => {
    const secret = 'my-secret-key';
    const domains = ['example.com'];
    const timestamp = 1234567890;
    const fakeSignature = '0000000000000000000000000000000000000000000000000000000000000000';

    const isValid = await verifyWhitelistSignature(domains, timestamp, fakeSignature, secret);
    expect(isValid).toBe(false);
  });

  it('should reject if secret is missing', async () => {
    const isValid = await verifyWhitelistSignature(['a.com'], 123, 'sig', null);
    expect(isValid).toBe(false);
  });
});
