import type { DecryptedSecret, SecretStoreInput, SecretMetadata } from './types.js';

export interface VaultBackend {
  getSecret(vaultRef: string): Promise<DecryptedSecret | null>;
  storeSecret(input: SecretStoreInput): Promise<{ vaultRef: string }>;
  rotateSecret(vaultRef: string, newValue: string): Promise<void>;
  deleteSecret(vaultRef: string): Promise<void>;
  listSecrets(vaultRefs: string[]): Promise<SecretMetadata[]>;
}
