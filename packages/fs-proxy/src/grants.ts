import type { Pool } from 'pg';
import type { FilesystemGrant, FilesystemGrantInput, FsOperation } from '@blindkey/core';
import { checkGrant, type FsGrantCheckResult } from '@blindkey/core';
import { realpath } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';

async function resolveFromNearestExistingAncestor(targetPath: string): Promise<string> {
  let cursor = resolve(targetPath);
  const missingSegments: string[] = [];

  while (true) {
    try {
      const canonicalBase = await realpath(cursor);
      return missingSegments.reduceRight((acc, segment) => resolve(acc, segment), canonicalBase);
    } catch {
      const parent = dirname(cursor);
      if (parent === cursor) {
        throw new Error(`Unable to canonicalize path: ${targetPath}`);
      }
      missingSegments.push(basename(cursor));
      cursor = parent;
    }
  }
}

async function canonicalizeGrantPath(path: string): Promise<string> {
  return resolveFromNearestExistingAncestor(path);
}

async function canonicalizeRequestedPath(path: string, operation: FsOperation): Promise<string> {
  const resolved = resolve(path);

  try {
    return await realpath(resolved);
  } catch {
    if (operation === 'create' || operation === 'write') {
      return resolveFromNearestExistingAncestor(resolved);
    }
    return resolved;
  }
}

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

    const canonicalGrants = await Promise.all(
      grants.map(async (grant) => ({
        ...grant,
        path: await canonicalizeGrantPath(grant.path),
      }))
    );

    const canonicalRequestedPath = await canonicalizeRequestedPath(path, operation);
    return checkGrant(canonicalGrants, operation, canonicalRequestedPath);
  }
}
