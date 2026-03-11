import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { initializeSchema } from './schema.js';
import { SQLiteVaultBackend } from './store.js';
import { LocalGrantService } from './grants.js';
import { LocalAuditService } from './audit.js';

const VALID_KEY = randomBytes(32).toString('hex');

function createTestDb() {
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  initializeSchema(db);
  return db;
}

describe('local-vault', () => {
  let db: Database.Database;
  let store: SQLiteVaultBackend;

  beforeEach(() => {
    process.env.VAULT_MASTER_KEY = VALID_KEY;
    db = createTestDb();
    store = new SQLiteVaultBackend(db);
  });

  afterEach(() => {
    db.close();
    delete process.env.VAULT_MASTER_KEY;
    delete process.env.AUDIT_SIGNING_KEY;
  });

  describe('SQLiteVaultBackend', () => {
    it('should store and retrieve a secret', async () => {
      const { vaultRef } = await store.storeSecret({
        user_id: 'local',
        name: 'test-key',
        service: 'stripe',
        secret_type: 'api_key',
        plaintext_value: 'sk_live_secret123',
      });

      expect(vaultRef).toMatch(/^bk:\/\/stripe-/);

      const result = await store.getSecret(vaultRef);
      expect(result).not.toBeNull();
      expect(result!.plaintext).toBe('sk_live_secret123');
      expect(result!.secret.name).toBe('test-key');
      expect(result!.secret.service).toBe('stripe');
      expect(result!.secret.secret_type).toBe('api_key');
    });

    it('should return null for non-existent secret', async () => {
      const result = await store.getSecret('bk://nonexistent-abc123');
      expect(result).toBeNull();
    });

    it('should list secrets without exposing plaintext', async () => {
      await store.storeSecret({
        user_id: 'local',
        name: 'key-1',
        service: 'stripe',
        secret_type: 'api_key',
        plaintext_value: 'secret1',
      });
      await store.storeSecret({
        user_id: 'local',
        name: 'key-2',
        service: 'openai',
        secret_type: 'api_key',
        plaintext_value: 'secret2',
      });

      const list = await store.listSecrets([]);
      expect(list).toHaveLength(2);
      // Metadata only — no plaintext field
      expect(list[0]).not.toHaveProperty('plaintext');
      expect(list[0]).toHaveProperty('vault_ref');
      expect(list[0]).toHaveProperty('name');
    });

    it('should rotate a secret', async () => {
      const { vaultRef } = await store.storeSecret({
        user_id: 'local',
        name: 'rotate-me',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'old-value',
      });

      await store.rotateSecret(vaultRef, 'new-value');

      const result = await store.getSecret(vaultRef);
      expect(result!.plaintext).toBe('new-value');
    });

    it('should throw when rotating non-existent secret', async () => {
      await expect(store.rotateSecret('bk://nonexistent-abc', 'val')).rejects.toThrow('Secret not found');
    });

    it('should delete a secret', async () => {
      const { vaultRef } = await store.storeSecret({
        user_id: 'local',
        name: 'delete-me',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'value',
      });

      await store.deleteSecret(vaultRef);
      expect(await store.getSecret(vaultRef)).toBeNull();
    });

    it('should look up by name', () => {
      // storeSecret is async but the db write is synchronous in better-sqlite3
      store.storeSecret({
        user_id: 'local',
        name: 'by-name',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'value',
      });

      // getSecretByName is synchronous
      const result = store.getSecretByName('by-name');
      expect(result).not.toBeNull();
      expect(result!.plaintext).toBe('value');
    });

    it('should return null for non-existent name', () => {
      expect(store.getSecretByName('nope')).toBeNull();
    });

    it('should delete by name', async () => {
      await store.storeSecret({
        user_id: 'local',
        name: 'del-name',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'value',
      });

      expect(store.deleteSecretByName('del-name')).toBe(true);
      expect(store.deleteSecretByName('del-name')).toBe(false);
    });

    it('should enforce unique names', async () => {
      await store.storeSecret({
        user_id: 'local',
        name: 'unique',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'v1',
      });

      await expect(store.storeSecret({
        user_id: 'local',
        name: 'unique',
        service: 'test',
        secret_type: 'api_key',
        plaintext_value: 'v2',
      })).rejects.toThrow();
    });

    it('should store and retrieve allowed_domains', async () => {
      const { vaultRef } = await store.storeSecret({
        user_id: 'local',
        name: 'with-domains',
        service: 'stripe',
        secret_type: 'api_key',
        plaintext_value: 'secret',
        allowed_domains: ['api.stripe.com', '*.stripe.com'],
      });

      const result = await store.getSecret(vaultRef);
      expect(result!.secret.allowed_domains).toEqual(['api.stripe.com', '*.stripe.com']);
    });

    it('should store and retrieve metadata', async () => {
      const { vaultRef } = await store.storeSecret({
        user_id: 'local',
        name: 'with-meta',
        service: 'custom',
        secret_type: 'custom_header',
        plaintext_value: 'secret',
        metadata: { header_name: 'X-API-Key' },
      });

      const result = await store.getSecret(vaultRef);
      expect(result!.secret.metadata).toEqual({ header_name: 'X-API-Key' });
    });
  });

  describe('LocalGrantService', () => {
    let grants: LocalGrantService;

    beforeEach(() => {
      grants = new LocalGrantService(db);
    });

    it('should add and list grants', () => {
      grants.add({ path: '/home/user/project', permissions: ['read', 'list'], recursive: true });
      const all = grants.getAll();
      expect(all).toHaveLength(1);
      expect(all[0].path).toBe('/home/user/project');
      expect(all[0].permissions).toEqual(['read', 'list']);
      expect(all[0].recursive).toBe(true);
    });

    it('should upsert on same path', () => {
      grants.add({ path: '/data', permissions: ['read'] });
      grants.add({ path: '/data', permissions: ['read', 'write'] });
      const all = grants.getAll();
      expect(all).toHaveLength(1);
      expect(all[0].permissions).toEqual(['read', 'write']);
    });

    it('should remove grants', () => {
      grants.add({ path: '/data', permissions: ['read'] });
      expect(grants.remove('/data')).toBe(true);
      expect(grants.getAll()).toHaveLength(0);
      expect(grants.remove('/data')).toBe(false);
    });

    it('should check access correctly', () => {
      grants.add({ path: '/project', permissions: ['read', 'list'], recursive: true });
      expect(grants.checkAccess('read', '/project/src/index.ts').granted).toBe(true);
      expect(grants.checkAccess('write', '/project/src/index.ts').granted).toBe(false);
    });
  });

  describe('LocalAuditService', () => {
    let audit: LocalAuditService;

    beforeEach(() => {
      audit = new LocalAuditService(db);
    });

    it('should log and retrieve audit entries', () => {
      audit.log({ action: 'secret_created', vault_ref: 'bk://test-123' });
      const entries = audit.recent(10);
      expect(entries).toHaveLength(1);
      expect(entries[0].action).toBe('secret_created');
    });

    it('should count entries', () => {
      audit.log({ action: 'a' });
      audit.log({ action: 'b' });
      expect(audit.count()).toBe(2);
    });

    it('should create and verify hash chain', () => {
      audit.log({ action: 'secret_created', vault_ref: 'bk://a' });
      audit.log({ action: 'secret_rotated', vault_ref: 'bk://a' });
      audit.log({ action: 'fs_read', path: '/test', granted: true });

      const result = audit.verify();
      expect(result.valid).toBe(true);
      expect(result.lastValidIndex).toBe(2);
    });

    it('should verify signed chain with AUDIT_SIGNING_KEY', () => {
      process.env.AUDIT_SIGNING_KEY = 'test-audit-key';

      audit.log({ action: 'secret_created' });
      audit.log({ action: 'secret_deleted' });

      const result = audit.verify('test-audit-key');
      expect(result.valid).toBe(true);
    });

    it('should log access denied entries', () => {
      audit.log({
        action: 'fs_write',
        path: '/home/user/.env',
        granted: false,
        blocking_rule: 'fs_block_patterns',
      });

      const entries = audit.recent();
      expect(entries[0].granted).toBe(0); // SQLite stores as integer
      expect(entries[0].blocking_rule).toBe('fs_block_patterns');
    });
  });
});
