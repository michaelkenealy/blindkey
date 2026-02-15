import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { FsOperation } from '@blindkey/core';
import { createSignedEntry } from '@blindkey/core';

export interface FsAuditInput {
  session_id: string;
  operation: FsOperation;
  path: string;
  granted: boolean;
  blocking_rule?: string;
  bytes_transferred?: number;
  file_hash?: string;
}

const GENESIS_HASH = '0'.repeat(64);

export class FsAuditService {
  constructor(private db: Pool) {}

  async log(entry: FsAuditInput): Promise<void> {
    const id = randomUUID();
    const timestamp = new Date().toISOString();

    const prevResult = await this.db.query<{ entry_hash: string | null }>(
      `SELECT entry_hash
       FROM fs_audit_log
       WHERE entry_hash IS NOT NULL
       ORDER BY created_at DESC, id DESC
       LIMIT 1`
    );

    const prevHash = prevResult.rows[0]?.entry_hash ?? GENESIS_HASH;
    const signingKey = process.env.AUDIT_SIGNING_KEY;

    const signed = createSignedEntry(
      {
        id,
        timestamp,
        action: entry.operation,
        session_id: entry.session_id,
        path: entry.path,
        granted: entry.granted,
        blocking_rule: entry.blocking_rule,
        bytes_transferred: entry.bytes_transferred,
        file_hash: entry.file_hash,
      },
      prevHash,
      signingKey
    );

    await this.db.query(
      `INSERT INTO fs_audit_log
        (id, session_id, operation, path, granted, blocking_rule, bytes_transferred, file_hash,
         created_at, prev_hash, entry_hash, signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        id,
        entry.session_id,
        entry.operation,
        entry.path,
        entry.granted,
        entry.blocking_rule ?? null,
        entry.bytes_transferred ?? null,
        entry.file_hash ?? null,
        timestamp,
        signed.prev_hash,
        signed.entry_hash,
        signed.signature ?? null,
      ]
    );
  }
}
