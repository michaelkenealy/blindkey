import type Database from 'better-sqlite3';

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
}

export class LocalAuditService {
  constructor(private db: Database.Database) {}

  log(entry: AuditEntry): void {
    this.db.prepare(`
      INSERT INTO audit_log (action, vault_ref, path, detail, granted, blocking_rule)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      entry.action,
      entry.vault_ref ?? null,
      entry.path ?? null,
      entry.detail ?? null,
      entry.granted !== undefined ? (entry.granted ? 1 : 0) : null,
      entry.blocking_rule ?? null,
    );
  }

  recent(limit = 50): AuditRow[] {
    return this.db.prepare(
      'SELECT * FROM audit_log ORDER BY id DESC LIMIT ?'
    ).all(limit) as AuditRow[];
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM audit_log').get() as { cnt: number };
    return row.cnt;
  }
}
