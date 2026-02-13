import type { Pool } from 'pg';
import { decrypt, encrypt, generateVaultRef } from '@blindkey/core';
import type {
  VaultBackend,
  DecryptedSecret,
  SecretStoreInput,
  SecretMetadata,
  Secret,
} from '@blindkey/core';

export class PostgresVaultBackend implements VaultBackend {
  constructor(private db: Pool) {}

  async getSecret(vaultRef: string): Promise<DecryptedSecret | null> {
    const result = await this.db.query(
      `SELECT id, user_id, vault_ref, name, service, secret_type,
              encrypted_value, iv, auth_tag, created_at, rotated_at,
              expires_at, metadata, allowed_domains, injection_ttl_seconds
       FROM secrets WHERE vault_ref = $1`,
      [vaultRef]
    );
    if (result.rows.length === 0) return null;

    const secret = result.rows[0] as Secret;

    if (secret.expires_at && new Date(secret.expires_at) < new Date()) {
      return null;
    }

    const plaintext = decrypt(secret.encrypted_value, secret.iv, secret.auth_tag);
    return { secret, plaintext };
  }

  async storeSecret(input: SecretStoreInput): Promise<{ vaultRef: string }> {
    const vaultRef = generateVaultRef(input.service);
    const { encrypted, iv, authTag } = encrypt(input.plaintext_value);

    await this.db.query(
      `INSERT INTO secrets
        (user_id, vault_ref, name, service, secret_type,
         encrypted_value, iv, auth_tag, metadata, allowed_domains, injection_ttl_seconds)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        input.user_id,
        vaultRef,
        input.name,
        input.service,
        input.secret_type,
        encrypted,
        iv,
        authTag,
        JSON.stringify(input.metadata ?? {}),
        input.allowed_domains ?? null,
        input.injection_ttl_seconds ?? 1800,
      ]
    );

    return { vaultRef };
  }

  async rotateSecret(vaultRef: string, newValue: string): Promise<void> {
    const { encrypted, iv, authTag } = encrypt(newValue);
    await this.db.query(
      `UPDATE secrets SET encrypted_value = $1, iv = $2, auth_tag = $3, rotated_at = now()
       WHERE vault_ref = $4`,
      [encrypted, iv, authTag, vaultRef]
    );
  }

  async deleteSecret(vaultRef: string): Promise<void> {
    await this.db.query('DELETE FROM secrets WHERE vault_ref = $1', [vaultRef]);
  }

  async listSecrets(vaultRefs: string[]): Promise<SecretMetadata[]> {
    if (vaultRefs.length === 0) return [];

    const placeholders = vaultRefs.map((_, i) => `$${i + 1}`).join(', ');
    const result = await this.db.query(
      `SELECT id, vault_ref, name, service, secret_type,
              created_at, rotated_at, expires_at, metadata,
              allowed_domains, injection_ttl_seconds
       FROM secrets WHERE vault_ref IN (${placeholders})`,
      vaultRefs
    );
    return result.rows as SecretMetadata[];
  }
}
