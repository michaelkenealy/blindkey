/**
 * Local-mode adapter — calls the local-api server (/v1/...) directly.
 * No authentication needed. Always "logged in" as the local user.
 */

import type {
  BlindKeyClient, SecretItem, GrantItem, AuditItem, PolicyItem,
  CreateSecretInput, CreateGrantInput,
} from './types';

/** Simple fetch wrapper for /v1/* endpoints (no JWT needed in local mode). */
async function localApi<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  const res = await fetch(`/v1${path}`, { ...options, headers });

  if (res.status === 204) return undefined as T;

  const body = await res.json();

  if (!res.ok) {
    throw new Error(body.message ?? 'Request failed');
  }

  return body as T;
}

export function createLocalClient(): BlindKeyClient {
  return {
    mode: 'local',

    // ── Auth (always authenticated in local mode) ──
    isLoggedIn: () => true,
    login: async () => ({}),
    register: async () => {},
    verifyTotp: async () => {},
    logout: () => {},

    // ── TOTP (not available in local mode) ──
    setupTotp: async () => ({ otpauth_uri: '', secret: '' }),
    confirmTotp: async () => ({ totp_enabled: false }),
    disableTotp: async () => ({ totp_enabled: false }),
    getTotpStatus: async () => ({ totp_enabled: false }),

    // ── Secrets ──
    fetchSecrets: async (): Promise<SecretItem[]> => {
      const data = await localApi<{ secrets: SecretItem[] }>('/secrets');
      return data.secrets;
    },

    createSecret: async (input: CreateSecretInput): Promise<SecretItem> => {
      return localApi<SecretItem>('/secrets', {
        method: 'POST',
        body: JSON.stringify(input),
      });
    },

    deleteSecret: async (id) => {
      await localApi<void>(`/secrets/${id}`, { method: 'DELETE' });
    },

    rotateSecret: async (id, plaintextValue): Promise<SecretItem> => {
      return localApi<SecretItem>(`/secrets/${id}/rotate`, {
        method: 'POST',
        body: JSON.stringify({ plaintext_value: plaintextValue }),
      });
    },

    updateSecret: async () => {
      throw new Error('Update not supported in local mode');
    },

    // ── Grants ──
    fetchGrants: async (): Promise<GrantItem[]> => {
      const data = await localApi<{ grants: GrantItem[] }>('/grants');
      return data.grants;
    },

    createGrant: async (input: CreateGrantInput): Promise<GrantItem> => {
      return localApi<GrantItem>('/grants', {
        method: 'POST',
        body: JSON.stringify(input),
      });
    },

    deleteGrant: async (id) => {
      await localApi<void>(`/grants/${id}`, { method: 'DELETE' });
    },

    // ── Audit ──
    fetchAuditLog: async (limit = 100): Promise<AuditItem[]> => {
      const data = await localApi<{ entries: AuditItem[] }>(`/audit?limit=${limit}`);
      return data.entries;
    },

    fetchAuditCount: async (): Promise<number> => {
      const data = await localApi<{ count: number }>('/audit/count');
      return data.count;
    },

    // ── Policies ──
    fetchPolicies: async (): Promise<PolicyItem[]> => {
      const data = await localApi<{ policies: PolicyItem[] }>('/policies');
      return data.policies;
    },

    addPolicy: async (rule): Promise<PolicyItem> => {
      const data = await localApi<{ policy: PolicyItem }>('/policies', {
        method: 'POST',
        body: JSON.stringify(rule),
      });
      return data.policy;
    },

    removePolicy: async (id): Promise<boolean> => {
      const data = await localApi<{ success: boolean }>(`/policies/${id}`, {
        method: 'DELETE',
      });
      return data.success;
    },

    togglePolicy: async (id, enabled): Promise<void> => {
      await localApi<{ success: boolean }>(`/policies/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      });
    },
  };
}
