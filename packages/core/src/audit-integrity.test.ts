import { describe, it, expect } from 'vitest';
import {
  computeEntryHash,
  signEntryHash,
  verifyEntrySignature,
  createSignedEntry,
  verifyAuditChain,
  getChainTip,
  exportChainSummary,
  type ChainableAuditEntry,
  type SignedAuditEntry,
} from './audit-integrity.js';

const GENESIS_HASH = '0'.repeat(64);
const SIGNING_KEY = 'test-signing-key-for-audit';

function makeEntry(id: string, action: string): ChainableAuditEntry {
  return {
    id,
    timestamp: '2026-01-01T00:00:00Z',
    action,
  };
}

function buildChain(count: number, signingKey?: string): SignedAuditEntry[] {
  const entries: SignedAuditEntry[] = [];
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < count; i++) {
    const entry = createSignedEntry(
      makeEntry(`entry-${i}`, `action_${i}`),
      prevHash,
      signingKey,
    );
    entries.push(entry);
    prevHash = entry.entry_hash;
  }
  return entries;
}

describe('audit-integrity', () => {
  describe('computeEntryHash', () => {
    it('should produce deterministic hashes', () => {
      const entry = makeEntry('1', 'test');
      const a = computeEntryHash(entry, GENESIS_HASH);
      const b = computeEntryHash(entry, GENESIS_HASH);
      expect(a).toBe(b);
    });

    it('should produce different hashes for different prevHash', () => {
      const entry = makeEntry('1', 'test');
      const a = computeEntryHash(entry, GENESIS_HASH);
      const b = computeEntryHash(entry, 'a'.repeat(64));
      expect(a).not.toBe(b);
    });

    it('should produce different hashes for different content', () => {
      const a = computeEntryHash(makeEntry('1', 'action_a'), GENESIS_HASH);
      const b = computeEntryHash(makeEntry('1', 'action_b'), GENESIS_HASH);
      expect(a).not.toBe(b);
    });

    it('should exclude chain fields from hash', () => {
      const entry = makeEntry('1', 'test') as SignedAuditEntry;
      entry.prev_hash = 'should-be-excluded';
      entry.entry_hash = 'should-be-excluded';
      entry.signature = 'should-be-excluded';

      const clean = makeEntry('1', 'test');
      const hashWithFields = computeEntryHash(entry, GENESIS_HASH);
      const hashClean = computeEntryHash(clean, GENESIS_HASH);
      expect(hashWithFields).toBe(hashClean);
    });
  });

  describe('signEntryHash / verifyEntrySignature', () => {
    it('should sign and verify successfully', () => {
      const hash = computeEntryHash(makeEntry('1', 'test'), GENESIS_HASH);
      const signature = signEntryHash(hash, SIGNING_KEY);

      const signed: SignedAuditEntry = {
        ...makeEntry('1', 'test'),
        prev_hash: GENESIS_HASH,
        entry_hash: hash,
        signature,
      };
      expect(verifyEntrySignature(signed, SIGNING_KEY)).toBe(true);
    });

    it('should reject wrong signing key', () => {
      const hash = computeEntryHash(makeEntry('1', 'test'), GENESIS_HASH);
      const signature = signEntryHash(hash, SIGNING_KEY);

      const signed: SignedAuditEntry = {
        ...makeEntry('1', 'test'),
        prev_hash: GENESIS_HASH,
        entry_hash: hash,
        signature,
      };
      expect(verifyEntrySignature(signed, 'wrong-key')).toBe(false);
    });

    it('should reject tampered signature', () => {
      const hash = computeEntryHash(makeEntry('1', 'test'), GENESIS_HASH);
      const signature = signEntryHash(hash, SIGNING_KEY);

      const signed: SignedAuditEntry = {
        ...makeEntry('1', 'test'),
        prev_hash: GENESIS_HASH,
        entry_hash: hash,
        signature: signature.replace(/^./, 'x'),
      };
      expect(verifyEntrySignature(signed, SIGNING_KEY)).toBe(false);
    });

    it('should return false for missing signature', () => {
      const signed: SignedAuditEntry = {
        ...makeEntry('1', 'test'),
        prev_hash: GENESIS_HASH,
        entry_hash: 'abc',
      };
      expect(verifyEntrySignature(signed, SIGNING_KEY)).toBe(false);
    });
  });

  describe('createSignedEntry', () => {
    it('should create entry with hash chain fields', () => {
      const entry = createSignedEntry(makeEntry('1', 'test'), GENESIS_HASH);
      expect(entry.prev_hash).toBe(GENESIS_HASH);
      expect(entry.entry_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(entry.signature).toBeUndefined();
    });

    it('should include signature when signing key provided', () => {
      const entry = createSignedEntry(makeEntry('1', 'test'), GENESIS_HASH, SIGNING_KEY);
      expect(entry.signature).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('verifyAuditChain', () => {
    it('should validate empty chain', () => {
      const result = verifyAuditChain([]);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate a valid chain of 5 entries', () => {
      const chain = buildChain(5);
      const result = verifyAuditChain(chain);
      expect(result.valid).toBe(true);
      expect(result.lastValidIndex).toBe(4);
    });

    it('should validate a signed chain', () => {
      const chain = buildChain(3, SIGNING_KEY);
      const result = verifyAuditChain(chain, SIGNING_KEY);
      expect(result.valid).toBe(true);
    });

    it('should detect tampered entry content', () => {
      const chain = buildChain(3);
      chain[1].action = 'tampered_action';
      const result = verifyAuditChain(chain);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Content tampered');
      expect(result.lastValidIndex).toBe(0);
    });

    it('should detect broken chain linkage', () => {
      const chain = buildChain(3);
      chain[1].prev_hash = 'wrong_hash_' + '0'.repeat(53);
      const result = verifyAuditChain(chain);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Chain broken');
    });

    it('should detect invalid signature', () => {
      const chain = buildChain(3, SIGNING_KEY);
      chain[2].signature = 'f'.repeat(64);
      const result = verifyAuditChain(chain, SIGNING_KEY);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Invalid signature');
    });
  });

  describe('getChainTip', () => {
    it('should return genesis hash for empty chain', () => {
      expect(getChainTip([])).toBe(GENESIS_HASH);
    });

    it('should return last entry hash', () => {
      const chain = buildChain(3);
      expect(getChainTip(chain)).toBe(chain[2].entry_hash);
    });
  });

  describe('exportChainSummary', () => {
    it('should summarize an empty chain', () => {
      const summary = exportChainSummary([]);
      expect(summary.total_entries).toBe(0);
      expect(summary.first_entry_id).toBeNull();
      expect(summary.chain_root).toBe(GENESIS_HASH);
      expect(summary.verification.valid).toBe(true);
    });

    it('should summarize a valid chain', () => {
      const chain = buildChain(3);
      const summary = exportChainSummary(chain);
      expect(summary.total_entries).toBe(3);
      expect(summary.first_entry_id).toBe('entry-0');
      expect(summary.last_entry_id).toBe('entry-2');
      expect(summary.verification.valid).toBe(true);
    });
  });
});
