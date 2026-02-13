import type { Pool } from 'pg';
import type { FsOperation } from '@blindkey/core';

export interface FsAuditInput {
  session_id: string;
  operation: FsOperation;
  path: string;
  granted: boolean;
  blocking_rule?: string;
  bytes_transferred?: number;
  file_hash?: string;
}

export class FsAuditService {
  constructor(private db: Pool) {}

  async log(entry: FsAuditInput): Promise<void> {
    await this.db.query(
      `INSERT INTO fs_audit_log
        (session_id, operation, path, granted, blocking_rule, bytes_transferred, file_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        entry.session_id,
        entry.operation,
        entry.path,
        entry.granted,
        entry.blocking_rule ?? null,
        entry.bytes_transferred ?? null,
        entry.file_hash ?? null,
      ]
    );
  }
}
