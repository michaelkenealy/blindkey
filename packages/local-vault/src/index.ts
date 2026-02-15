import Database from 'better-sqlite3';
import { loadMasterKey, getDbPath, getVaultDir } from './master-key.js';
import { initializeSchema } from './schema.js';
import { SQLiteVaultBackend } from './store.js';
import { LocalGrantService } from './grants.js';
import { LocalAuditService } from './audit.js';
import { LocalPolicyService } from './policies.js';

export { SQLiteVaultBackend } from './store.js';
export { LocalGrantService } from './grants.js';
export { LocalAuditService } from './audit.js';
export { LocalPolicyService } from './policies.js';
export type { AuditEntry, AuditRow } from './audit.js';
export type { PolicyRow } from './policies.js';
export { loadMasterKey, getDbPath, getVaultDir } from './master-key.js';
export { DEFAULT_FS_POLICIES, checkFsAccess } from './fs-access.js';

export interface LocalVault {
  db: Database.Database;
  store: SQLiteVaultBackend;
  grants: LocalGrantService;
  audit: LocalAuditService;
  policies: LocalPolicyService;
}

/**
 * Initialize the local vault. Loads the master key, opens SQLite,
 * creates tables if needed, and returns ready-to-use services.
 */
export async function createLocalVault(): Promise<LocalVault> {
  await loadMasterKey();

  const dbPath = getDbPath();
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  initializeSchema(db);

  const store = new SQLiteVaultBackend(db);
  const grants = new LocalGrantService(db);
  const audit = new LocalAuditService(db);
  const policies = new LocalPolicyService(db);

  return { db, store, grants, audit, policies };
}
