import type Database from 'better-sqlite3';
import { createSignedEntry, verifyAuditChain, type SignedAuditEntry } from '@blindkey/core';

export interface AuditEntry {
  action: string;
  vault_ref?: string;
  path?: string;
  detail?: string;
  granted?: boolean;
  blocking_rule?: string;
}

export interface AuditRow {
  id: number;
  action: string;
  vault_ref: string | null;
  path: string | null;
  detail: string | null;
  granted: number | null;
  blocking_rule: string | null;
  created_at: string;
  prev_hash: string | null;
  entry_hash: string | null;
  signature: string | null;
}

const GENESIS_HASH = '0'.repeat(64);

export class LocalAuditService {
  constructor(private db: Database.Database) {}

  log(entry: AuditEntry): void {
    const nextId = this.db.prepare('SELECT IFNULL(MAX(id), 0) + 1 as next_id FROM audit_log').get() as { next_id: number };
    const timestamp = new Date().toISOString();
    const prevRow = this.db.prepare(
      'SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1'
    ).get() as { entry_hash?: string } | undefined;

    const prevHash = prevRow?.entry_hash ?? GENESIS_HASH;
    const signingKey = process.env.AUDIT_SIGNING_KEY;

    const signed = createSignedEntry(
      {
        id: String(nextId.next_id),
        timestamp,
        action: entry.action,
        vault_ref: entry.vault_ref,
        path: entry.path,
        detail: entry.detail,
        granted: entry.granted,
        blocking_rule: entry.blocking_rule,
      },
      prevHash,
      signingKey
    );

    this.db.prepare(`
      INSERT INTO audit_log (action, vault_ref, path, detail, granted, blocking_rule, created_at, prev_hash, entry_hash, signature)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.action,
      entry.vault_ref ?? null,
      entry.path ?? null,
      entry.detail ?? null,
      entry.granted !== undefined ? (entry.granted ? 1 : 0) : null,
      entry.blocking_rule ?? null,
      timestamp,
      signed.prev_hash,
      signed.entry_hash,
      signed.signature ?? null,
    );
  }

  recent(limit = 50): AuditRow[] {
    return this.db.prepare(
      'SELECT * FROM audit_log ORDER BY id DESC LIMIT ?'
    ).all(limit) as AuditRow[];
  }

  allAsc(): AuditRow[] {
    return this.db.prepare('SELECT * FROM audit_log ORDER BY id ASC').all() as AuditRow[];
  }

  verify(signingKey?: string): ReturnType<typeof verifyAuditChain> {
    const entries = this.allAsc()
      .filter((row) => row.prev_hash && row.entry_hash)
      .map((row) => ({
        id: String(row.id),
        timestamp: row.created_at,
        action: row.action,
        vault_ref: row.vault_ref ?? undefined,
        path: row.path ?? undefined,
        detail: row.detail ?? undefined,
        granted: row.granted === null ? undefined : row.granted === 1,
        blocking_rule: row.blocking_rule ?? undefined,
        prev_hash: row.prev_hash!,
        entry_hash: row.entry_hash!,
        signature: row.signature ?? undefined,
      })) as SignedAuditEntry[];

    return verifyAuditChain(entries, signingKey);
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM audit_log').get() as { cnt: number };
    return row.cnt;
  }
}
