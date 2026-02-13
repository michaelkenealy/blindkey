import type { VaultBackend, DecryptedSecret, SecretStoreInput, SecretMetadata } from '@blindkey/core';

interface CacheEntry {
  decrypted: DecryptedSecret;
  fetched_at: number;
  ttl_seconds: number;
}

export class CachingVaultService implements VaultBackend {
  private cache = new Map<string, CacheEntry>();

  constructor(private backend: VaultBackend) {}

  async getSecret(vaultRef: string): Promise<DecryptedSecret | null> {
    const cached = this.cache.get(vaultRef);
    if (cached) {
      const ageMs = Date.now() - cached.fetched_at;
      if (ageMs < cached.ttl_seconds * 1000) {
        return cached.decrypted;
      }
      this.cache.delete(vaultRef);
    }

    const result = await this.backend.getSecret(vaultRef);
    if (!result) return null;

    this.cache.set(vaultRef, {
      decrypted: result,
      fetched_at: Date.now(),
      ttl_seconds: result.secret.injection_ttl_seconds ?? 1800,
    });

    return result;
  }

  async storeSecret(input: SecretStoreInput): Promise<{ vaultRef: string }> {
    return this.backend.storeSecret(input);
  }

  async rotateSecret(vaultRef: string, newValue: string): Promise<void> {
    this.cache.delete(vaultRef);
    return this.backend.rotateSecret(vaultRef, newValue);
  }

  async deleteSecret(vaultRef: string): Promise<void> {
    this.cache.delete(vaultRef);
    return this.backend.deleteSecret(vaultRef);
  }

  async listSecrets(vaultRefs: string[]): Promise<SecretMetadata[]> {
    return this.backend.listSecrets(vaultRefs);
  }

  invalidate(vaultRef: string): void {
    this.cache.delete(vaultRef);
  }

  clearCache(): void {
    this.cache.clear();
  }
}
