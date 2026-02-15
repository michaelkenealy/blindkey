/**
 * Dashboard API client for the local vault bridge server.
 * All calls go to /api/... (proxied by Vite to port 3401).
 * No authentication needed — local single-user mode.
 */

// ── Types ──

export interface VaultGrant {
  id: string;
  path: string;
  permissions: string[];
  recursive: boolean;
  requires_approval: boolean;
  created_at: string;
}

export interface AuditRow {
  id: number;
  action: string;
  vault_ref: string | null;
  path: string | null;
  detail: string | null;
  granted: number | null;
  blocking_rule: string | null;
  created_at: string;
}

export interface PolicyRow {
  id: string;
  type: string;
  config: string;
  enabled: number;
  created_at: string;
}

// ── Fetch wrapper ──

async function bridge<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  const res = await fetch(`/api${path}`, { ...options, headers });
  const body = await res.json();

  if (!res.ok) {
    throw new Error(body.error ?? 'Bridge request failed');
  }

  return body as T;
}

// ── Grants ──

export async function fetchGrants(): Promise<VaultGrant[]> {
  const data = await bridge<{ grants: VaultGrant[] }>('/grants');
  return data.grants;
}

export async function addGrant(input: {
  path: string;
  permissions?: string[];
  recursive?: boolean;
  requires_approval?: boolean;
}): Promise<VaultGrant> {
  const data = await bridge<{ grant: VaultGrant }>('/grants', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  return data.grant;
}

export async function removeGrant(path: string): Promise<boolean> {
  const data = await bridge<{ success: boolean }>(`/grants/${encodeURIComponent(path)}`, {
    method: 'DELETE',
  });
  return data.success;
}

// ── Audit ──

export async function fetchAuditLog(limit = 100): Promise<AuditRow[]> {
  const data = await bridge<{ entries: AuditRow[] }>(`/audit?limit=${limit}`);
  return data.entries;
}

export async function fetchAuditCount(): Promise<number> {
  const data = await bridge<{ count: number }>('/audit/count');
  return data.count;
}

// ── Policies ──

export async function fetchPolicies(): Promise<PolicyRow[]> {
  const data = await bridge<{ policies: PolicyRow[] }>('/policies');
  return data.policies;
}

export async function addPolicy(rule: {
  type: string;
  [key: string]: unknown;
}): Promise<PolicyRow> {
  const data = await bridge<{ policy: PolicyRow }>('/policies', {
    method: 'POST',
    body: JSON.stringify(rule),
  });
  return data.policy;
}

export async function removePolicy(id: string): Promise<boolean> {
  const data = await bridge<{ success: boolean }>(`/policies/${id}`, {
    method: 'DELETE',
  });
  return data.success;
}

export async function togglePolicy(id: string, enabled: boolean): Promise<void> {
  await bridge<{ success: boolean }>(`/policies/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
}
