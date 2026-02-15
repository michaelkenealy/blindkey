/**
 * @blindkey/aquaman-backend
 *
 * Backend adapter implementing Aquaman's CredentialStore interface,
 * backed by Blindkey's local vault.
 *
 * Aquaman CredentialStore interface:
 *   get(service: string, key: string): Promise<string | null>
 *   set(service: string, key: string, value: string, metadata?: Record<string, string>): Promise<void>
 *   delete(service: string, key: string): Promise<boolean>
 *   list(service?: string): Promise<Array<{ service: string; key: string }>>
 *   exists(service: string, key: string): Promise<boolean>
 */

import { createLocalVault, type LocalVault } from '@blindkey/local-vault';
import { scanContent, type ScanRule, type ScanResult } from '@blindkey/content-scanner';
import { GrantManager, type FsOperation, type FsAccessCheck } from '@blindkey/fs-gate';

// ── Aquaman CredentialStore Interface ──

export interface CredentialStore {
  get(service: string, key: string): Promise<string | null>;
  set(service: string, key: string, value: string, metadata?: Record<string, string>): Promise<void>;
  delete(service: string, key: string): Promise<boolean>;
  list(service?: string): Promise<Array<{ service: string; key: string }>>;
  exists(service: string, key: string): Promise<boolean>;
}

export interface BlindkeyStoreOptions {
  /** Path to vault directory (uses default if not specified) */
  vaultDir?: string;
}

// ── Blindkey CredentialStore Implementation ──

export class BlindkeyStore implements CredentialStore {
  private vault: LocalVault | null = null;
  private readonly grantManager = new GrantManager();

  constructor(_options: BlindkeyStoreOptions = {}) {}

  private async ensureVault(): Promise<LocalVault> {
    if (!this.vault) {
      this.vault = await createLocalVault();
    }
    return this.vault;
  }

  // ── CredentialStore Interface ──

  async get(service: string, key: string): Promise<string | null> {
    const vault = await this.ensureVault();
    // Secrets are stored with a compound name: service/key
    const compoundName = `${service}/${key}`;
    const result = vault.store.getSecretByName(compoundName);
    if (result) return result.plaintext;

    // Fallback: try matching by service field + name
    const secrets = await vault.store.listSecrets([]);
    const match = secrets.find(s => s.service === service && s.name === key);
    if (!match) return null;

    const decrypted = await vault.store.getSecret(match.vault_ref);
    return decrypted?.plaintext ?? null;
  }

  async set(
    service: string,
    key: string,
    value: string,
    metadata?: Record<string, string>,
  ): Promise<void> {
    const vault = await this.ensureVault();

    // Check for existing secret by service + name
    const secrets = await vault.store.listSecrets([]);
    const existing = secrets.find(s => s.service === service && s.name === key);

    if (existing) {
      await vault.store.rotateSecret(existing.vault_ref, value);
      return;
    }

    await vault.store.storeSecret({
      user_id: 'local',
      name: key,
      service,
      secret_type: 'api_key',
      plaintext_value: value,
      metadata: metadata as Record<string, unknown>,
    });
  }

  async delete(service: string, key: string): Promise<boolean> {
    const vault = await this.ensureVault();
    const secrets = await vault.store.listSecrets([]);
    const match = secrets.find(s => s.service === service && s.name === key);
    if (!match) return false;

    await vault.store.deleteSecret(match.vault_ref);
    return true;
  }

  async list(service?: string): Promise<Array<{ service: string; key: string }>> {
    const vault = await this.ensureVault();
    const secrets = await vault.store.listSecrets([]);
    return secrets
      .filter(s => !service || s.service === service)
      .map(s => ({ service: s.service, key: s.name }));
  }

  async exists(service: string, key: string): Promise<boolean> {
    const vault = await this.ensureVault();
    const secrets = await vault.store.listSecrets([]);
    return secrets.some(s => s.service === service && s.name === key);
  }

  // ── Static Factory (matches Aquaman backend pattern) ──

  static async isAvailable(): Promise<boolean> {
    try {
      await createLocalVault();
      return true;
    } catch {
      return false;
    }
  }

  // ── Blindkey Extensions (unique features) ──

  /**
   * Check if a filesystem operation is permitted on the given path.
   * Powered by @blindkey/fs-gate.
   */
  checkFilesystemAccess(operation: FsOperation, path: string): FsAccessCheck {
    return this.grantManager.checkAccess(operation, path);
  }

  /**
   * Grant filesystem access to a path with specified permissions.
   */
  grantFilesystemAccess(
    path: string,
    permissions: Array<'read' | 'write' | 'create' | 'delete' | 'list'>,
    options?: { recursive?: boolean },
  ): void {
    this.grantManager.grant({
      path,
      permissions,
      recursive: options?.recursive !== false,
    });
  }

  /**
   * Revoke filesystem access for a path.
   */
  revokeFilesystemAccess(path: string): boolean {
    return this.grantManager.revoke(path);
  }

  /**
   * List all active filesystem grants.
   */
  listFilesystemGrants() {
    return this.grantManager.listGrants();
  }

  /**
   * Scan content for hardcoded secrets and sensitive data.
   * Powered by @blindkey/content-scanner.
   */
  scanContent(content: string, customRules?: ScanRule[]): ScanResult {
    return scanContent(content, customRules);
  }
}

/**
 * Factory function matching Aquaman's createXxxStore() convention.
 */
export function createBlindkeyStore(options?: BlindkeyStoreOptions): BlindkeyStore {
  return new BlindkeyStore(options);
}

export default BlindkeyStore;

// Re-export useful types from the extension libraries
export type { ScanRule, ScanResult } from '@blindkey/content-scanner';
export type { FsOperation, FsAccessCheck, FsGrant } from '@blindkey/fs-gate';
