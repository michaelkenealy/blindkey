import type { DecryptedSecret, SecretStoreInput, SecretMetadata } from './types.js';

export interface NamedRef {
  name: string;
  vault_ref: string;
  provider: string;
  created_at: Date;
}

export interface VaultBackend {
  getSecret(vaultRef: string): Promise<DecryptedSecret | null>;
  storeSecret(input: SecretStoreInput): Promise<{ vaultRef: string }>;
  rotateSecret(vaultRef: string, newValue: string): Promise<void>;
  deleteSecret(vaultRef: string): Promise<void>;
  listSecrets(vaultRefs: string[]): Promise<SecretMetadata[]>;
  getRef(name: string): Promise<NamedRef | null>;
  setRef(name: string, vaultRef: string, provider: string): Promise<void>;
  deleteRef(name: string): Promise<boolean>;
  listRefs(): Promise<NamedRef[]>;
}
