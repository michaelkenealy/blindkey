/**
 * Docker-mode adapter — wraps the JWT-authenticated API client (api.ts)
 * into the unified BlindKeyClient interface.
 */

import * as api from '../api';
import type {
  BlindKeyClient, SecretItem, GrantItem, AuditItem, PolicyItem,
  CreateSecretInput, UpdateSecretInput, CreateGrantInput,
} from './types';

export function createDockerClient(): BlindKeyClient {
  return {
    mode: 'docker',

    // ── Auth ──
    isLoggedIn: () => api.isLoggedIn(),

    login: async (email, password) => {
      const result = await api.login(email, password);
      return { requires_totp: result.requires_totp, totp_token: result.totp_token };
    },

    register: async (email, password) => {
      await api.register(email, password);
    },

    verifyTotp: async (totpToken, code) => {
      await api.verifyTotp(totpToken, code);
    },

    logout: () => api.clearToken(),

    // ── TOTP ──
    setupTotp: () => api.setupTotp(),
    confirmTotp: (code) => api.confirmTotp(code),
    disableTotp: (code) => api.disableTotp(code),
    getTotpStatus: () => api.getTotpStatus(),

    // ── Secrets ──
    fetchSecrets: async (): Promise<SecretItem[]> => {
      const secrets = await api.fetchSecrets();
      return secrets as SecretItem[];
    },

    createSecret: async (input: CreateSecretInput): Promise<SecretItem> => {
      const result = await api.createSecret(input);
      return result as SecretItem;
    },

    deleteSecret: async (id) => {
      await api.deleteSecret(id);
    },

    rotateSecret: async (id, plaintextValue): Promise<SecretItem> => {
      const result = await api.rotateSecret(id, plaintextValue);
      return result as SecretItem;
    },

    updateSecret: async (id, updates: UpdateSecretInput): Promise<SecretItem> => {
      const result = await api.updateSecret(id, updates);
      return result as SecretItem;
    },

    // ── Grants ──
    fetchGrants: async (): Promise<GrantItem[]> => {
      const grants = await api.fetchGrants();
      return grants as GrantItem[];
    },

    createGrant: async (input: CreateGrantInput): Promise<GrantItem> => {
      const grant = await api.createGrant(input);
      return grant as GrantItem;
    },

    deleteGrant: async (id) => {
      await api.deleteGrant(id);
    },

    // ── Audit (Docker API has different schema — return empty for now) ──
    fetchAuditLog: async (): Promise<AuditItem[]> => [],
    fetchAuditCount: async () => 0,

    // ── Policies (Docker API has different schema — return empty for now) ──
    fetchPolicies: async (): Promise<PolicyItem[]> => [],
    addPolicy: async () => { throw new Error('Policies not available in Docker mode'); },
    removePolicy: async () => false,
    togglePolicy: async () => {},
  };
}
