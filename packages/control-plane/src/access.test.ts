import { describe, expect, it } from 'vitest';
import { evaluateProxyAccess } from './access.js';
import type { Budget, ProviderCredential, UsageEvent, VirtualKey } from './types.js';

const credential: ProviderCredential = {
  id: 'credential_1',
  workspaceId: 'workspace_1',
  vaultRef: 'bk://openai-abc123',
  provider: 'openai',
  environment: 'production',
  bindingType: 'api_key',
  allowedDomains: ['api.openai.com'],
  createdAt: new Date('2026-01-01T00:00:00Z'),
  rotatedAt: new Date('2026-01-01T00:00:00Z'),
};

const virtualKey: VirtualKey = {
  id: 'vk_1',
  workspaceId: 'workspace_1',
  keyPrefix: 'bk_prod_123',
  name: 'R&D report agent',
  providerCredentialId: 'credential_1',
  subjectType: 'agent',
  subjectId: 'agent_1',
  environment: 'production',
  allowedModels: ['gpt-5.4-mini'],
  allowedDomains: [],
  policySetIds: [],
  budgetIds: ['budget_1'],
  revokedAt: null,
  createdAt: new Date('2026-01-01T00:00:00Z'),
};

const budget: Budget = {
  id: 'budget_1',
  workspaceId: 'workspace_1',
  subjectType: 'virtual_key',
  subjectId: 'vk_1',
  window: 'day',
  amountCents: 500,
  currency: 'USD',
  hardLimit: true,
  createdAt: new Date('2026-01-01T00:00:00Z'),
};

const usage: UsageEvent = {
  id: 'usage_1',
  workspaceId: 'workspace_1',
  virtualKeyId: 'vk_1',
  provider: 'openai',
  model: 'gpt-5.4-mini',
  costCents: 450,
  status: 'allowed',
  occurredAt: new Date('2026-05-03T10:00:00Z'),
};

describe('proxy access evaluation', () => {
  it('allows a request that matches binding, domain, model, and budget', () => {
    const decision = evaluateProxyAccess({
      workspaceId: 'workspace_1',
      virtualKey,
      providerCredential: credential,
      url: 'https://api.openai.com/v1/responses',
      method: 'POST',
      model: 'gpt-5.4-mini',
      projectedCostCents: 25,
      now: new Date('2026-05-03T11:00:00Z'),
    }, [budget], [usage]);

    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBeNull();
  });

  it('blocks a request to an unapproved domain', () => {
    const decision = evaluateProxyAccess({
      workspaceId: 'workspace_1',
      virtualKey,
      providerCredential: credential,
      url: 'https://evil.example/v1/responses',
      method: 'POST',
      model: 'gpt-5.4-mini',
      projectedCostCents: 1,
    }, [budget], []);

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('domain_not_allowed');
  });

  it('blocks a request that would exceed a hard budget', () => {
    const decision = evaluateProxyAccess({
      workspaceId: 'workspace_1',
      virtualKey,
      providerCredential: credential,
      url: 'https://api.openai.com/v1/responses',
      method: 'POST',
      model: 'gpt-5.4-mini',
      projectedCostCents: 100,
      now: new Date('2026-05-03T11:00:00Z'),
    }, [budget], [usage]);

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('budget_exceeded:budget_1');
  });
});
