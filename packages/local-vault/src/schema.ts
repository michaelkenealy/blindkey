import type Database from 'better-sqlite3';

function ensureColumn(db: Database.Database, table: string, column: string, definition: string): void {
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  } catch {
    // Column already exists on upgraded installations.
  }
}

export function initializeSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      vault_ref TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      service TEXT NOT NULL DEFAULT 'custom',
      secret_type TEXT NOT NULL DEFAULT 'api_key',
      encrypted_value BLOB NOT NULL,
      iv BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      allowed_domains TEXT,
      injection_ttl_seconds INTEGER NOT NULL DEFAULT 1800,
      metadata TEXT DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      rotated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS filesystem_grants (
      id TEXT PRIMARY KEY,
      path TEXT NOT NULL UNIQUE,
      permissions TEXT NOT NULL,
      recursive INTEGER NOT NULL DEFAULT 1,
      requires_approval INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS content_policies (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      config TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      vault_ref TEXT,
      path TEXT,
      detail TEXT,
      granted INTEGER,
      blocking_rule TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_local_audit_log_created_at ON audit_log (created_at);
  `);

  ensureColumn(db, 'audit_log', 'prev_hash', 'TEXT');
  ensureColumn(db, 'audit_log', 'entry_hash', 'TEXT');
  ensureColumn(db, 'audit_log', 'signature', 'TEXT');

  db.exec('CREATE INDEX IF NOT EXISTS idx_local_audit_log_entry_hash ON audit_log (entry_hash);');
}
