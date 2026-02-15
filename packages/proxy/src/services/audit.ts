import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { AuditAction } from '@blindkey/core';
import { createSignedEntry } from '@blindkey/core';

export interface AuditLogInput {
  user_id: string;
  session_id: string | null;
  vault_ref: string | null;
  action: AuditAction;
  request_summary?: Record<string, unknown>;
  policy_result?: Record<string, unknown>;
  response_status?: number;
  latency_ms?: number;
}

const GENESIS_HASH = '0'.repeat(64);

export class AuditService {
  constructor(private db: Pool) {}

  async log(entry: AuditLogInput): Promise<void> {
    const id = randomUUID();
    const timestamp = new Date().toISOString();

    const prevResult = await this.db.query<{ entry_hash: string | null }>(
      `SELECT entry_hash
       FROM audit_log
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
        action: entry.action,
        user_id: entry.user_id,
        session_id: entry.session_id ?? undefined,
        vault_ref: entry.vault_ref ?? undefined,
        request_summary: entry.request_summary,
        policy_result: entry.policy_result,
        response_status: entry.response_status,
        latency_ms: entry.latency_ms,
      },
      prevHash,
      signingKey
    );

    await this.db.query(
      `INSERT INTO audit_log
        (id, user_id, session_id, vault_ref, action, request_summary, policy_result, response_status, latency_ms,
         created_at, prev_hash, entry_hash, signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        id,
        entry.user_id,
        entry.session_id,
        entry.vault_ref,
        entry.action,
        entry.request_summary ? JSON.stringify(entry.request_summary) : null,
        entry.policy_result ? JSON.stringify(entry.policy_result) : null,
        entry.response_status ?? null,
        entry.latency_ms ?? null,
        timestamp,
        signed.prev_hash,
        signed.entry_hash,
        signed.signature ?? null,
      ]
    );
  }
}
