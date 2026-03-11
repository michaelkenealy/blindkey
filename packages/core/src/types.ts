// ── TTL Tiers ──

export type TTLTier = 'high' | 'medium' | 'low' | 'custom';

export const TTL_PRESETS: Record<Exclude<TTLTier, 'custom'>, number> = {
  high: 900,      // 15 min — banking, payment, identity
  medium: 3600,   // 60 min — email, calendar, social (default)
  low: 14400,     // 4 hours — weather, public data, read-only APIs
};

/** Resolve a TTL tier name or custom seconds to a number. */
export function resolveTTL(tierOrSeconds: string): number {
  if (tierOrSeconds in TTL_PRESETS) {
    return TTL_PRESETS[tierOrSeconds as keyof typeof TTL_PRESETS];
  }
  const n = parseInt(tierOrSeconds, 10);
  if (isNaN(n) || n <= 0) {
    throw new Error(`Invalid TTL: "${tierOrSeconds}". Use high, medium, low, or a number of seconds.`);
  }
  return n;
}

// ── Secret Types ──

export type SecretType = 'api_key' | 'oauth_token' | 'basic_auth' | 'custom_header' | 'query_param';

export interface Secret {
  id: string;
  user_id: string;
  vault_ref: string;
  name: string;
  service: string;
  secret_type: SecretType;
  encrypted_value: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  created_at: Date;
  rotated_at: Date;
  expires_at: Date | null;
  metadata: Record<string, unknown>;
  allowed_domains: string[] | null;
  injection_ttl_seconds: number;
}

export interface SecretCreateInput {
  name: string;
  service: string;
  secret_type: SecretType;
  plaintext_value: string;
  metadata?: Record<string, unknown>;
  allowed_domains?: string[];
  injection_ttl_seconds?: number;
}

export interface SecretMetadata {
  id: string;
  vault_ref: string;
  name: string;
  service: string;
  secret_type: SecretType;
  created_at: Date;
  rotated_at: Date;
  expires_at: Date | null;
  metadata: Record<string, unknown>;
  allowed_domains: string[] | null;
  injection_ttl_seconds: number;
}

export interface DecryptedSecret {
  secret: Secret;
  plaintext: string;
}

export interface SecretStoreInput {
  user_id: string;
  name: string;
  service: string;
  secret_type: SecretType;
  plaintext_value: string;
  allowed_domains?: string[];
  injection_ttl_seconds?: number;
  metadata?: Record<string, unknown>;
}

// ── Session Types ──

export interface AgentSession {
  id: string;
  user_id: string;
  token_hash: string;
  allowed_secrets: string[];
  policy_set_id: string | null;
  expires_at: Date;
  revoked_at: Date | null;
  metadata: SessionMetadata;
  created_at: Date;
}

export interface SessionMetadata {
  agent_name?: string;
  purpose?: string;
  [key: string]: unknown;
}

export interface SessionCreateInput {
  allowed_secrets: string[];
  policy_set_id?: string;
  ttl_seconds?: number;
  metadata?: SessionMetadata;
}

export interface SessionCreateResult {
  session: AgentSession;
  session_token: string;
}

// ── Policy Types ──

export type PolicyRuleType =
  | 'endpoint_allowlist'
  | 'method_restriction'
  | 'rate_limit'
  | 'payload_cap'
  | 'regex_blocklist'
  | 'human_approval'
  | 'time_of_day'
  | 'ip_restriction';

export interface EndpointAllowlistRule {
  type: 'endpoint_allowlist';
  endpoints: Array<{ method: string; path: string }>;
}

export interface MethodRestrictionRule {
  type: 'method_restriction';
  allowed_methods: string[];
}

export interface RateLimitRule {
  type: 'rate_limit';
  max_requests: number;
  window_seconds: number;
}

export interface PayloadCapRule {
  type: 'payload_cap';
  field: string;
  max: number;
  currency_field?: string;
}

export interface RegexBlocklistRule {
  type: 'regex_blocklist';
  patterns: string[];
}

export interface HumanApprovalRule {
  type: 'human_approval';
  condition: string;
  timeout_seconds: number;
  on_timeout: 'deny' | 'allow';
}

export type PolicyRule =
  | EndpointAllowlistRule
  | MethodRestrictionRule
  | RateLimitRule
  | PayloadCapRule
  | RegexBlocklistRule
  | HumanApprovalRule;

export interface PolicySet {
  id: string;
  user_id: string;
  name: string;
  rules: PolicyRule[];
  created_at: Date;
}

export interface PolicySetCreateInput {
  name: string;
  rules: PolicyRule[];
}

// ── Proxy Request Types ──

export interface ProxyRequest {
  vault_ref: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

// ── Audit Types ──

export type AuditAction =
  | 'request_allowed'
  | 'request_denied'
  | 'session_created'
  | 'session_revoked'
  | 'secret_created'
  | 'secret_rotated'
  | 'secret_deleted';

export interface AuditEntry {
  id: string;
  user_id: string;
  session_id: string | null;
  vault_ref: string | null;
  action: AuditAction;
  request_summary: Record<string, unknown> | null;
  policy_result: Record<string, unknown> | null;
  response_status: number | null;
  latency_ms: number | null;
  created_at: Date;
}

// ── User Types ──

export interface User {
  id: string;
  email: string;
  password_hash: string;
  created_at: Date;
}

export interface UserCreateInput {
  email: string;
  password: string;
}

// ── Credential Injection Config ──

export interface InjectionConfig {
  secret_type: SecretType;
  header_name?: string;
  query_param_name?: string;
}

// ── Filesystem Grant Types ──

export type FsPermission = 'read' | 'write' | 'create' | 'delete' | 'list';

export interface FilesystemGrant {
  id: string;
  session_id: string;
  path: string;
  permissions: FsPermission[];
  recursive: boolean;
  requires_approval: boolean;
  created_at: Date;
}

export interface FilesystemGrantInput {
  path: string;
  permissions: FsPermission[];
  recursive?: boolean;
  requires_approval?: boolean;
}

export type FsOperation = 'read' | 'write' | 'create' | 'delete' | 'list' | 'info';

export interface FsRequest {
  operation: FsOperation;
  path: string;
  content?: string;
  mode?: 'overwrite' | 'append';
  encoding?: string;
  recursive?: boolean;
}

export interface FsAuditEntry {
  id: string;
  session_id: string;
  operation: FsOperation;
  path: string;
  granted: boolean;
  blocking_rule: string | null;
  bytes_transferred: number | null;
  file_hash: string | null;
  created_at: Date;
}

// ── Filesystem Policy Types ──

export interface FsBlockPatternsRule {
  type: 'fs_block_patterns';
  patterns: string[];
}

export interface FsSizeLimitRule {
  type: 'fs_size_limit';
  max_read_bytes: number;
  max_write_bytes: number;
}

export interface FsExtensionAllowlistRule {
  type: 'fs_extension_allowlist';
  extensions: string[];
}

export interface FsContentScanRule {
  type: 'fs_content_scan';
  on: 'write';
  block_if_contains: Array<{ pattern: string; message: string }>;
}

export type FsPolicyRule =
  | FsBlockPatternsRule
  | FsSizeLimitRule
  | FsExtensionAllowlistRule
  | FsContentScanRule;
