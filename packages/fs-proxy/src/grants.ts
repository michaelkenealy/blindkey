import type { Pool } from 'pg';
import type { FilesystemGrant, FilesystemGrantInput, FsOperation } from '@blindkey/core';
import { checkGrant, type FsGrantCheckResult } from '@blindkey/core';

export class GrantService {
  constructor(private db: Pool) {}

  async getGrantsForSession(sessionId: string): Promise<FilesystemGrant[]> {
    const result = await this.db.query(
      `SELECT id, session_id, path, permissions, recursive, requires_approval, created_at
       FROM filesystem_grants WHERE session_id = $1`,
      [sessionId]
    );
    return result.rows as FilesystemGrant[];
  }

  async createGrants(sessionId: string, grants: FilesystemGrantInput[]): Promise<FilesystemGrant[]> {
    const results: FilesystemGrant[] = [];
    for (const grant of grants) {
      const result = await this.db.query(
        `INSERT INTO filesystem_grants (session_id, path, permissions, recursive, requires_approval)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, session_id, path, permissions, recursive, requires_approval, created_at`,
        [sessionId, grant.path, grant.permissions, grant.recursive ?? true, grant.requires_approval ?? false]
      );
      results.push(result.rows[0] as FilesystemGrant);
    }
    return results;
  }

  async checkAccess(sessionId: string, operation: FsOperation, path: string): Promise<FsGrantCheckResult> {
    const grants = await this.getGrantsForSession(sessionId);
    return checkGrant(grants, operation, path);
  }
}
