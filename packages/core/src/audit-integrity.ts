/**
 * Cryptographic Audit Log Integrity Module
 *
 * Implements a hash chain to ensure audit log integrity.
 * Each log entry includes a hash of its contents plus the previous entry's hash,
 * creating a tamper-evident chain similar to blockchain.
 */

import { createHash, createHmac } from 'node:crypto';

export interface ChainableAuditEntry {
  id: string;
  timestamp: string;
  action: string;
  user_id?: string;
  session_id?: string;
  vault_ref?: string;
  request_summary?: unknown;
  policy_result?: unknown;
  response_status?: number;
  [key: string]: unknown;
}

export interface SignedAuditEntry extends ChainableAuditEntry {
  prev_hash: string;
  entry_hash: string;
  signature?: string;
}

const HASH_ALGORITHM = 'sha256';
const GENESIS_HASH = '0'.repeat(64); // Initial hash for first entry in chain

/**
 * Compute the hash of an audit entry's contents (excluding chain fields)
 */
export function computeEntryHash(entry: ChainableAuditEntry, prevHash: string): string {
  // Create canonical representation (sorted keys, no chain fields)
  const canonical: Record<string, unknown> = {};
  const sortedKeys = Object.keys(entry).sort();

  for (const key of sortedKeys) {
    if (key !== 'prev_hash' && key !== 'entry_hash' && key !== 'signature') {
      canonical[key] = entry[key];
    }
  }

  // Include previous hash in the computation
  const payload = JSON.stringify({ ...canonical, _prev: prevHash });
  return createHash(HASH_ALGORITHM).update(payload).digest('hex');
}

/**
 * Sign an audit entry hash with an HMAC key (optional but recommended)
 */
export function signEntryHash(entryHash: string, signingKey: string): string {
  return createHmac(HASH_ALGORITHM, signingKey).update(entryHash).digest('hex');
}

/**
 * Verify an entry's signature
 */
export function verifyEntrySignature(
  entry: SignedAuditEntry,
  signingKey: string
): boolean {
  if (!entry.signature) {
    return false;
  }
  const expectedSig = signEntryHash(entry.entry_hash, signingKey);
  // Constant-time comparison
  if (expectedSig.length !== entry.signature.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < expectedSig.length; i++) {
    result |= expectedSig.charCodeAt(i) ^ entry.signature.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Create a signed audit entry with hash chain
 */
export function createSignedEntry(
  entry: ChainableAuditEntry,
  prevHash: string,
  signingKey?: string
): SignedAuditEntry {
  const entryHash = computeEntryHash(entry, prevHash);
  const signedEntry: SignedAuditEntry = {
    ...entry,
    prev_hash: prevHash,
    entry_hash: entryHash,
  };

  if (signingKey) {
    signedEntry.signature = signEntryHash(entryHash, signingKey);
  }

  return signedEntry;
}

/**
 * Verify the integrity of an audit log chain
 */
export function verifyAuditChain(
  entries: SignedAuditEntry[],
  signingKey?: string
): {
  valid: boolean;
  errors: string[];
  lastValidIndex: number;
} {
  const errors: string[] = [];
  let lastValidIndex = -1;

  if (entries.length === 0) {
    return { valid: true, errors: [], lastValidIndex: -1 };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // Verify chain linkage
    if (entry.prev_hash !== expectedPrevHash) {
      errors.push(
        `Entry ${i} (${entry.id}): Chain broken - expected prev_hash ${expectedPrevHash.slice(0, 16)}..., got ${entry.prev_hash.slice(0, 16)}...`
      );
      break;
    }

    // Verify entry hash
    const computedHash = computeEntryHash(entry, entry.prev_hash);
    if (computedHash !== entry.entry_hash) {
      errors.push(
        `Entry ${i} (${entry.id}): Content tampered - hash mismatch`
      );
      break;
    }

    // Verify signature if key provided
    if (signingKey && entry.signature) {
      if (!verifyEntrySignature(entry, signingKey)) {
        errors.push(
          `Entry ${i} (${entry.id}): Invalid signature - possible tampering`
        );
        break;
      }
    }

    lastValidIndex = i;
    expectedPrevHash = entry.entry_hash;
  }

  return {
    valid: errors.length === 0,
    errors,
    lastValidIndex,
  };
}

/**
 * Get the hash needed to chain the next entry
 */
export function getChainTip(entries: SignedAuditEntry[]): string {
  if (entries.length === 0) {
    return GENESIS_HASH;
  }
  return entries[entries.length - 1].entry_hash;
}

/**
 * Export chain verification summary for external auditors
 */
export function exportChainSummary(entries: SignedAuditEntry[]): {
  total_entries: number;
  first_entry_id: string | null;
  last_entry_id: string | null;
  chain_root: string;
  chain_tip: string;
  verification: ReturnType<typeof verifyAuditChain>;
} {
  const verification = verifyAuditChain(entries);

  return {
    total_entries: entries.length,
    first_entry_id: entries.length > 0 ? entries[0].id : null,
    last_entry_id: entries.length > 0 ? entries[entries.length - 1].id : null,
    chain_root: GENESIS_HASH,
    chain_tip: getChainTip(entries),
    verification,
  };
}
