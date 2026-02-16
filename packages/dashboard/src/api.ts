// ─── BlindKey API Client ───
// Thin fetch wrapper with JWT token management for the dashboard.

const TOKEN_KEY = 'bk_token';

let token: string | null = localStorage.getItem(TOKEN_KEY);

// ── Auth helpers ──

export function getToken(): string | null {
  return token;
}

export function isLoggedIn(): boolean {
  return token !== null;
}

export function clearToken(): void {
  token = null;
  localStorage.removeItem(TOKEN_KEY);
}

function setToken(t: string): void {
  token = t;
  localStorage.setItem(TOKEN_KEY, t);
}

// ── Fetch wrapper ──

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> | undefined),
  };
  // Only set Content-Type for requests with a body
  if (options.body) {
    headers['Content-Type'] = 'application/json';
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`/v1${path}`, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    throw new ApiError(401, 'Session expired. Please log in again.');
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const body = await res.json();

  if (!res.ok) {
    throw new ApiError(res.status, body.message ?? 'Request failed');
  }

  return body as T;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

// ── Auth ──

interface AuthResponse {
  user: { id: string; email: string; created_at: string };
  token: string;
}

interface LoginResponse {
  // Normal login (no 2FA)
  user?: { id: string; email: string; created_at: string };
  token?: string;
  // 2FA required
  requires_totp?: boolean;
  totp_token?: string;
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const data = await api<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (data.token) {
    setToken(data.token);
  }
  return data;
}

export async function verifyTotp(totpToken: string, code: string): Promise<AuthResponse> {
  const data = await api<AuthResponse>('/auth/verify-totp', {
    method: 'POST',
    body: JSON.stringify({ totp_token: totpToken, code }),
  });
  setToken(data.token);
  return data;
}

export async function register(email: string, password: string): Promise<AuthResponse> {
  const data = await api<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setToken(data.token);
  return data;
}

// ── TOTP Setup ──

export async function setupTotp(): Promise<{ otpauth_uri: string; secret: string }> {
  return api<{ otpauth_uri: string; secret: string }>('/auth/setup-totp', { method: 'POST' });
}

export async function confirmTotp(code: string): Promise<{ totp_enabled: boolean }> {
  return api<{ totp_enabled: boolean }>('/auth/confirm-totp', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export async function disableTotp(code: string): Promise<{ totp_enabled: boolean }> {
  return api<{ totp_enabled: boolean }>('/auth/disable-totp', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export async function getTotpStatus(): Promise<{ totp_enabled: boolean }> {
  return api<{ totp_enabled: boolean }>('/auth/totp-status');
}

// ── Secrets ──

export interface SecretMetadata {
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

export async function fetchSecrets(): Promise<SecretMetadata[]> {
  const data = await api<{ secrets: SecretMetadata[] }>('/secrets');
  return data.secrets;
}

export async function createSecret(input: {
  name: string;
  service: string;
  secret_type: string;
  plaintext_value: string;
  allowed_domains?: string[];
  injection_ttl_seconds?: number;
}): Promise<SecretMetadata> {
  return api<SecretMetadata>('/secrets', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function deleteSecret(id: string): Promise<void> {
  await api<void>(`/secrets/${id}`, { method: 'DELETE' });
}

export async function updateSecret(
  id: string,
  updates: { allowed_domains?: string[] | null; injection_ttl_seconds?: number },
): Promise<SecretMetadata> {
  return api<SecretMetadata>(`/secrets/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(updates),
  });
}

export async function rotateSecret(id: string, plaintextValue: string): Promise<SecretMetadata> {
  return api<SecretMetadata>(`/secrets/${id}/rotate`, {
    method: 'POST',
    body: JSON.stringify({ plaintext_value: plaintextValue }),
  });
}

// ── Filesystem Grants ──

export interface GrantMetadata {
  id: string;
  path: string;
  permissions: string[];
  recursive: boolean;
  requires_approval: boolean;
  created_at: string;
}

export async function fetchGrants(): Promise<GrantMetadata[]> {
  const data = await api<{ grants: GrantMetadata[] }>('/grants');
  return data.grants;
}

export async function createGrant(input: {
  path: string;
  permissions: string[];
  recursive?: boolean;
  requires_approval?: boolean;
}): Promise<GrantMetadata> {
  return api<GrantMetadata>('/grants', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export async function deleteGrant(id: string): Promise<void> {
  await api<void>(`/grants/${id}`, { method: 'DELETE' });
}
