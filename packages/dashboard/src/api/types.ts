/**
 * Unified BlindKey dashboard client types.
 * Both Docker (JWT-auth, /v1/...) and Local (bridge, /api/...) adapters
 * implement the BlindKeyClient interface.
 */

export type BlindKeyMode = 'local' | 'docker' | 'detecting';

// ── Item types (common shape used by all UI components) ──

export interface SecretItem {
  id: string;
  vault_ref: string;
  name: string;
  service: string;
  secret_type: string;
  created_at: string;
  rotated_at: string;
  expires_at: string | null;
  metadata: Record<string, unknown>;
  allowed_domains: string[] | null;
  injection_ttl_seconds: number;
}

export interface GrantItem {
  id: string;
  path: string;
  permissions: string[];
  recursive: boolean;
  requires_approval: boolean;
  created_at: string;
}

export interface AuditItem {
  id: number;
  action: string;
  vault_ref: string | null;
  path: string | null;
  detail: string | null;
  granted: number | null;
  blocking_rule: string | null;
  created_at: string;
}

export interface PolicyItem {
  id: string;
  type: string;
  config: string;
  enabled: number;
  created_at: string;
}

// ── Input types ──

export interface CreateSecretInput {
  name: string;
  service: string;
  secret_type: string;
  plaintext_value: string;
  allowed_domains?: string[];
  injection_ttl_seconds?: number;
}

export interface UpdateSecretInput {
  allowed_domains?: string[] | null;
  injection_ttl_seconds?: number;
}

export interface CreateGrantInput {
  path: string;
  permissions: string[];
  recursive?: boolean;
  requires_approval?: boolean;
}

// ── Client interface ──

export interface BlindKeyClient {
  readonly mode: BlindKeyMode;

  // Auth
  isLoggedIn(): boolean;
  login(email: string, password: string): Promise<{ requires_totp?: boolean; totp_token?: string }>;
  register(email: string, password: string): Promise<void>;
  verifyTotp(totpToken: string, code: string): Promise<void>;
  logout(): void;

  // TOTP
  setupTotp(): Promise<{ otpauth_uri: string; secret: string }>;
  confirmTotp(code: string): Promise<{ totp_enabled: boolean }>;
  disableTotp(code: string): Promise<{ totp_enabled: boolean }>;
  getTotpStatus(): Promise<{ totp_enabled: boolean }>;

  // Secrets
  fetchSecrets(): Promise<SecretItem[]>;
  createSecret(input: CreateSecretInput): Promise<SecretItem>;
  deleteSecret(id: string): Promise<void>;
  rotateSecret(id: string, plaintextValue: string): Promise<SecretItem>;
  updateSecret(id: string, updates: UpdateSecretInput): Promise<SecretItem>;

  // Grants
  fetchGrants(): Promise<GrantItem[]>;
  createGrant(input: CreateGrantInput): Promise<GrantItem>;
  deleteGrant(id: string): Promise<void>;

  // Audit
  fetchAuditLog(limit?: number): Promise<AuditItem[]>;
  fetchAuditCount(): Promise<number>;

  // Policies
  fetchPolicies(): Promise<PolicyItem[]>;
  addPolicy(rule: { type: string; [key: string]: unknown }): Promise<PolicyItem>;
  removePolicy(id: string): Promise<boolean>;
  togglePolicy(id: string, enabled: boolean): Promise<void>;
}
