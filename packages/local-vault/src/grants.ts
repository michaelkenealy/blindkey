import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import { checkGrant, type FsGrantCheckResult } from '@blindkey/core';
import type { FilesystemGrant, FilesystemGrantInput, FsOperation, FsPermission } from '@blindkey/core';

interface GrantRow {
  id: string;
  path: string;
  permissions: string;
  recursive: number;
  requires_approval: number;
  created_at: string;
}

function rowToGrant(row: GrantRow): FilesystemGrant {
  return {
    id: row.id,
    session_id: 'local',
    path: row.path,
    permissions: JSON.parse(row.permissions) as FsPermission[],
    recursive: row.recursive === 1,
    requires_approval: row.requires_approval === 1,
    created_at: new Date(row.created_at),
  };
}

export class LocalGrantService {
  constructor(private db: Database.Database) {}

  getAll(): FilesystemGrant[] {
    const rows = this.db.prepare(
      'SELECT * FROM filesystem_grants ORDER BY created_at'
    ).all() as GrantRow[];
    return rows.map(rowToGrant);
  }

  add(input: FilesystemGrantInput): FilesystemGrant {
    const id = randomUUID();

    // Upsert — if path already exists, update permissions
    this.db.prepare(`
      INSERT INTO filesystem_grants (id, path, permissions, recursive, requires_approval)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(path) DO UPDATE SET
        permissions = excluded.permissions,
        recursive = excluded.recursive,
        requires_approval = excluded.requires_approval
    `).run(
      id,
      input.path,
      JSON.stringify(input.permissions),
      input.recursive !== false ? 1 : 0,
      input.requires_approval ? 1 : 0,
    );

    const row = this.db.prepare(
      'SELECT * FROM filesystem_grants WHERE path = ?'
    ).get(input.path) as GrantRow;

    return rowToGrant(row);
  }

  remove(path: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM filesystem_grants WHERE path = ?'
    ).run(path);
    return result.changes > 0;
  }

  checkAccess(operation: FsOperation, path: string): FsGrantCheckResult {
    const grants = this.getAll();
    return checkGrant(grants, operation, path);
  }
}
