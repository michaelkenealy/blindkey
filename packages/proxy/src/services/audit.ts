import type { Pool } from 'pg';
import type { AuditAction } from '@blindkey/core';

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

export class AuditService {
  constructor(private db: Pool) {}

  async log(entry: AuditLogInput): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_log
        (user_id, session_id, vault_ref, action, request_summary, policy_result, response_status, latency_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        entry.user_id,
        entry.session_id,
        entry.vault_ref,
        entry.action,
        entry.request_summary ? JSON.stringify(entry.request_summary) : null,
        entry.policy_result ? JSON.stringify(entry.policy_result) : null,
        entry.response_status ?? null,
        entry.latency_ms ?? null,
      ]
    );
  }
}
