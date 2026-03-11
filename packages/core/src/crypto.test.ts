import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, generateVaultRef, hashToken, getTokenHashCandidates, generateSessionToken, hashBody } from './crypto.js';

function setMasterKey(hex: string) {
  process.env.VAULT_MASTER_KEY = hex;
}

function clearEnv() {
  delete process.env.VAULT_MASTER_KEY;
  delete process.env.TOKEN_HASH_PEPPER;
}

const VALID_KEY = randomBytes(32).toString('hex'); // 64-char hex

describe('crypto', () => {
  afterEach(() => clearEnv());

  describe('encrypt/decrypt roundtrip', () => {
    beforeEach(() => setMasterKey(VALID_KEY));

    it('should encrypt and decrypt a simple string', () => {
      const plaintext = 'sk-abc123secret';
      const { encrypted, iv, authTag } = encrypt(plaintext);
      const result = decrypt(encrypted, iv, authTag);
      expect(result).toBe(plaintext);
    });

    it('should encrypt and decrypt empty string', () => {
      const { encrypted, iv, authTag } = encrypt('');
      expect(decrypt(encrypted, iv, authTag)).toBe('');
    });

    it('should encrypt and decrypt unicode content', () => {
      const plaintext = '日本語テスト 🔑 émojis';
      const { encrypted, iv, authTag } = encrypt(plaintext);
      expect(decrypt(encrypted, iv, authTag)).toBe(plaintext);
    });

    it('should produce unique IVs for each encryption', () => {
      const a = encrypt('same-value');
      const b = encrypt('same-value');
      expect(a.iv.equals(b.iv)).toBe(false);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const a = encrypt('same-value');
      const b = encrypt('same-value');
      expect(a.encrypted.equals(b.encrypted)).toBe(false);
    });
  });

  describe('decrypt with wrong key', () => {
    it('should fail to decrypt with a different master key', () => {
      setMasterKey(VALID_KEY);
      const { encrypted, iv, authTag } = encrypt('secret');

      // Switch to different key
      const otherKey = randomBytes(32).toString('hex');
      setMasterKey(otherKey);

      expect(() => decrypt(encrypted, iv, authTag)).toThrow();
    });
  });

  describe('decrypt with tampered data', () => {
    beforeEach(() => setMasterKey(VALID_KEY));

    it('should fail if ciphertext is tampered', () => {
      const { encrypted, iv, authTag } = encrypt('secret');
      encrypted[0] ^= 0xff;
      expect(() => decrypt(encrypted, iv, authTag)).toThrow();
    });

    it('should fail if IV is tampered', () => {
      const { encrypted, iv, authTag } = encrypt('secret');
      iv[0] ^= 0xff;
      expect(() => decrypt(encrypted, iv, authTag)).toThrow();
    });

    it('should fail if authTag is tampered', () => {
      const { encrypted, iv, authTag } = encrypt('secret');
      authTag[0] ^= 0xff;
      expect(() => decrypt(encrypted, iv, authTag)).toThrow();
    });
  });

  describe('master key validation', () => {
    it('should throw if VAULT_MASTER_KEY is not set', () => {
      clearEnv();
      expect(() => encrypt('test')).toThrow('VAULT_MASTER_KEY must be a 64-character hex string');
    });

    it('should throw if VAULT_MASTER_KEY is too short', () => {
      setMasterKey('abcd1234');
      expect(() => encrypt('test')).toThrow('VAULT_MASTER_KEY must be a 64-character hex string');
    });
  });

  describe('generateVaultRef', () => {
    beforeEach(() => setMasterKey(VALID_KEY));

    it('should produce bk:// prefixed refs', () => {
      const ref = generateVaultRef('stripe');
      expect(ref).toMatch(/^bk:\/\/stripe-[a-f0-9]{24}$/);
    });

    it('should produce unique refs', () => {
      const a = generateVaultRef('test');
      const b = generateVaultRef('test');
      expect(a).not.toBe(b);
    });
  });

  describe('hashToken', () => {
    it('should produce v1 hash without pepper', () => {
      clearEnv();
      const hash = hashToken('my-token');
      expect(hash).toMatch(/^v1:[a-f0-9]{64}$/);
    });

    it('should produce v2 hash with pepper', () => {
      process.env.TOKEN_HASH_PEPPER = 'test-pepper';
      const hash = hashToken('my-token');
      expect(hash).toMatch(/^v2:[a-f0-9]{64}$/);
    });

    it('should produce deterministic hashes', () => {
      clearEnv();
      const a = hashToken('same-token');
      const b = hashToken('same-token');
      expect(a).toBe(b);
    });

    it('should produce different hashes for different tokens', () => {
      clearEnv();
      const a = hashToken('token-a');
      const b = hashToken('token-b');
      expect(a).not.toBe(b);
    });
  });

  describe('getTokenHashCandidates', () => {
    it('should include legacy and v1 without pepper', () => {
      clearEnv();
      const candidates = getTokenHashCandidates('token');
      expect(candidates.length).toBeGreaterThanOrEqual(2);
      expect(candidates.some(c => c.startsWith('v1:'))).toBe(true);
      // legacy unversioned hash
      expect(candidates.some(c => !c.startsWith('v1:') && !c.startsWith('v2:'))).toBe(true);
    });

    it('should include v2 hash when pepper is set', () => {
      process.env.TOKEN_HASH_PEPPER = 'pepper';
      const candidates = getTokenHashCandidates('token');
      expect(candidates.some(c => c.startsWith('v2:'))).toBe(true);
    });
  });

  describe('generateSessionToken', () => {
    it('should produce bk_ prefixed tokens', () => {
      const token = generateSessionToken();
      expect(token).toMatch(/^bk_/);
    });

    it('should produce unique tokens', () => {
      const a = generateSessionToken();
      const b = generateSessionToken();
      expect(a).not.toBe(b);
    });

    it('should be sufficiently long', () => {
      const token = generateSessionToken();
      expect(token.length).toBeGreaterThan(40);
    });
  });

  describe('hashBody', () => {
    it('should hash object deterministically', () => {
      const a = hashBody({ key: 'value' });
      const b = hashBody({ key: 'value' });
      expect(a).toBe(b);
    });

    it('should produce different hashes for different bodies', () => {
      const a = hashBody({ a: 1 });
      const b = hashBody({ b: 2 });
      expect(a).not.toBe(b);
    });

    it('should handle null/undefined', () => {
      const a = hashBody(null);
      const b = hashBody(undefined);
      expect(a).toBe(b); // both stringify to ''
    });
  });
});
