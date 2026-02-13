import type Database from 'better-sqlite3';
import { encrypt, decrypt, generateVaultRef } from '@blindkey/core';
import type { VaultBackend, DecryptedSecret, SecretStoreInput, SecretMetadata, Secret, SecretType } from '@blindkey/core';

interface SecretRow {
  vault_ref: string;
  name: string;
  service: string;
  secret_type: string;
  encrypted_value: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  allowed_domains: string | null;
  injection_ttl_seconds: number;
  metadata: string;
  created_at: string;
  rotated_at: string;
}

function rowToSecret(row: SecretRow): Secret {
  return {
    id: row.vault_ref,
    user_id: 'local',
    vault_ref: row.vault_ref,
    name: row.name,
    service: row.service,
    secret_type: row.secret_type as SecretType,
    encrypted_value: Buffer.from(row.encrypted_value),
    iv: Buffer.from(row.iv),
    auth_tag: Buffer.from(row.auth_tag),
    created_at: new Date(row.created_at),
    rotated_at: new Date(row.rotated_at),
    expires_at: null,
    metadata: JSON.parse(row.metadata || '{}'),
    allowed_domains: row.allowed_domains ? JSON.parse(row.allowed_domains) : null,
    injection_ttl_seconds: row.injection_ttl_seconds,
  };
}

function rowToMetadata(row: SecretRow): SecretMetadata {
  return {
    id: row.vault_ref,
    vault_ref: row.vault_ref,
    name: row.name,
    service: row.service,
    secret_type: row.secret_type as SecretType,
    created_at: new Date(row.created_at),
    rotated_at: new Date(row.rotated_at),
    expires_at: null,
    metadata: JSON.parse(row.metadata || '{}'),
    allowed_domains: row.allowed_domains ? JSON.parse(row.allowed_domains) : null,
    injection_ttl_seconds: row.injection_ttl_seconds,
  };
}

export class SQLiteVaultBackend implements VaultBackend {
  constructor(private db: Database.Database) {}

  async getSecret(vaultRef: string): Promise<DecryptedSecret | null> {
    const row = this.db.prepare(
      'SELECT * FROM secrets WHERE vault_ref = ?'
    ).get(vaultRef) as SecretRow | undefined;

    if (!row) return null;

    const plaintext = decrypt(
      Buffer.from(row.encrypted_value),
      Buffer.from(row.iv),
      Buffer.from(row.auth_tag)
    );

    return { secret: rowToSecret(row), plaintext };
  }

  async storeSecret(input: SecretStoreInput): Promise<{ vaultRef: string }> {
    const vaultRef = generateVaultRef(input.service);
    const { encrypted, iv, authTag } = encrypt(input.plaintext_value);

    this.db.prepare(`
      INSERT INTO secrets (vault_ref, name, service, secret_type, encrypted_value, iv, auth_tag,
                           allowed_domains, injection_ttl_seconds, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      vaultRef,
      input.name,
      input.service,
      input.secret_type,
      encrypted,
      iv,
      authTag,
      input.allowed_domains ? JSON.stringify(input.allowed_domains) : null,
      input.injection_ttl_seconds ?? 1800,
      JSON.stringify(input.metadata ?? {}),
    );

    return { vaultRef };
  }

  async rotateSecret(vaultRef: string, newValue: string): Promise<void> {
    const { encrypted, iv, authTag } = encrypt(newValue);
    const result = this.db.prepare(`
      UPDATE secrets SET encrypted_value = ?, iv = ?, auth_tag = ?, rotated_at = datetime('now')
      WHERE vault_ref = ?
    `).run(encrypted, iv, authTag, vaultRef);

    if (result.changes === 0) {
      throw new Error(`Secret not found: ${vaultRef}`);
    }
  }

  async deleteSecret(vaultRef: string): Promise<void> {
    this.db.prepare('DELETE FROM secrets WHERE vault_ref = ?').run(vaultRef);
  }

  async listSecrets(vaultRefs: string[]): Promise<SecretMetadata[]> {
    if (vaultRefs.length === 0) {
      const rows = this.db.prepare('SELECT * FROM secrets ORDER BY created_at DESC').all() as SecretRow[];
      return rows.map(rowToMetadata);
    }

    const placeholders = vaultRefs.map(() => '?').join(', ');
    const rows = this.db.prepare(
      `SELECT * FROM secrets WHERE vault_ref IN (${placeholders}) ORDER BY created_at DESC`
    ).all(...vaultRefs) as SecretRow[];

    return rows.map(rowToMetadata);
  }

  /** Look up a secret by its human-readable name. */
  getSecretByName(name: string): DecryptedSecret | null {
    const row = this.db.prepare(
      'SELECT * FROM secrets WHERE name = ?'
    ).get(name) as SecretRow | undefined;

    if (!row) return null;

    const plaintext = decrypt(
      Buffer.from(row.encrypted_value),
      Buffer.from(row.iv),
      Buffer.from(row.auth_tag)
    );

    return { secret: rowToSecret(row), plaintext };
  }

  /** Delete a secret by its human-readable name. */
  deleteSecretByName(name: string): boolean {
    const result = this.db.prepare('DELETE FROM secrets WHERE name = ?').run(name);
    return result.changes > 0;
  }
}
