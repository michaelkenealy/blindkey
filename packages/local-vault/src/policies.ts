import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { FsPolicyRule } from '@blindkey/core';
import { DEFAULT_FS_POLICIES } from './fs-access.js';

export interface PolicyRow {
  id: string;
  type: string;
  config: string;
  enabled: number;
  created_at: string;
}

export class LocalPolicyService {
  constructor(private db: Database.Database) {}

  getAll(): PolicyRow[] {
    return this.db.prepare(
      'SELECT * FROM content_policies ORDER BY created_at'
    ).all() as PolicyRow[];
  }

  getEnabled(): FsPolicyRule[] {
    const rows = this.db.prepare(
      'SELECT * FROM content_policies WHERE enabled = 1 ORDER BY created_at'
    ).all() as PolicyRow[];
    return rows.map(r => JSON.parse(r.config) as FsPolicyRule);
  }

  add(rule: FsPolicyRule): PolicyRow {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO content_policies (id, type, config, enabled)
      VALUES (?, ?, ?, 1)
    `).run(id, rule.type, JSON.stringify(rule));

    return this.db.prepare(
      'SELECT * FROM content_policies WHERE id = ?'
    ).get(id) as PolicyRow;
  }

  remove(id: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM content_policies WHERE id = ?'
    ).run(id);
    return result.changes > 0;
  }

  toggle(id: string, enabled: boolean): void {
    this.db.prepare(
      'UPDATE content_policies SET enabled = ? WHERE id = ?'
    ).run(enabled ? 1 : 0, id);
  }

  /** Merge built-in DEFAULT_FS_POLICIES with user-added enabled rules. */
  getEffective(): FsPolicyRule[] {
    return [...DEFAULT_FS_POLICIES, ...this.getEnabled()];
  }
}
