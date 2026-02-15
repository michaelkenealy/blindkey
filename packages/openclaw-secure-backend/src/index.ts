/**
 * @blindkey/openclaw-secure-backend
 *
 * Backend adapter implementing OpenClaw-Secure's SecretBackend interface,
 * backed by Blindkey's local vault.
 *
 * OpenClaw-Secure interface:
 *   name: string
 *   available(): Promise<boolean>
 *   get(key: string): Promise<string | null>
 *   set(key: string, value: string): Promise<void>
 *   delete(key: string): Promise<void>
 *   list(): Promise<string[]>
 */

import { createLocalVault, type LocalVault } from '@blindkey/local-vault';
import { scanContent, type ScanRule, type ScanResult } from '@blindkey/content-scanner';
import { GrantManager, type FsOperation, type FsAccessCheck } from '@blindkey/fs-gate';

// ── OpenClaw-Secure SecretBackend Interface ──

export interface SecretBackend {
  readonly name: string;
  available(): Promise<boolean>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  list(): Promise<string[]>;
}

export interface BackendOptions {
  /** Service name to scope secrets under (default: 'openclaw') */
  service?: string;
}

// ── Blindkey Backend Implementation ──

export class BlindkeyBackend implements SecretBackend {
  readonly name = 'blindkey';

  private vault: LocalVault | null = null;
  private readonly service: string;
  private readonly grantManager = new GrantManager();

  constructor(options: BackendOptions = {}) {
    this.service = options.service ?? 'openclaw';
  }

  private async ensureVault(): Promise<LocalVault> {
    if (!this.vault) {
      this.vault = await createLocalVault();
    }
    return this.vault;
  }

  // ── SecretBackend Interface ──

  async available(): Promise<boolean> {
    try {
      await this.ensureVault();
      return true;
    } catch {
      return false;
    }
  }

  async get(key: string): Promise<string | null> {
    const vault = await this.ensureVault();
    const result = vault.store.getSecretByName(key);
    return result?.plaintext ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    const vault = await this.ensureVault();

    // Check if secret already exists - update via rotate
    const existing = vault.store.getSecretByName(key);
    if (existing) {
      await vault.store.rotateSecret(existing.secret.vault_ref, value);
      return;
    }

    await vault.store.storeSecret({
      user_id: 'local',
      name: key,
      service: this.service,
      secret_type: 'api_key',
      plaintext_value: value,
    });
  }

  async delete(key: string): Promise<void> {
    const vault = await this.ensureVault();
    vault.store.deleteSecretByName(key);
  }

  async list(): Promise<string[]> {
    const vault = await this.ensureVault();
    const secrets = await vault.store.listSecrets([]);
    return secrets
      .filter(s => s.service === this.service)
      .map(s => s.name);
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

export default BlindkeyBackend;

// Re-export useful types from the extension libraries
export type { ScanRule, ScanResult } from '@blindkey/content-scanner';
export type { FsOperation, FsAccessCheck, FsGrant } from '@blindkey/fs-gate';
