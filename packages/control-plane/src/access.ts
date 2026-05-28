import type { Budget, ProviderCredential, ProxyAccessDecision, ProxyAccessRequest, UsageEvent, VirtualKey } from './types.js';
import { wouldExceedHardBudget } from './budget.js';

function hostnameAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) return false;
  return allowedDomains.some((domain) => {
    const normalized = domain.toLowerCase();
    const actual = hostname.toLowerCase();
    if (normalized.startsWith('*.')) {
      const suffix = normalized.slice(1);
      return actual.endsWith(suffix) || actual === normalized.slice(2);
    }
    return actual === normalized;
  });
}

export function validateVirtualKeyBinding(
  virtualKey: VirtualKey,
  providerCredential: ProviderCredential,
): ProxyAccessDecision {
  const checks = ['workspace_match', 'credential_binding', 'not_revoked'];

  if (virtualKey.workspaceId !== providerCredential.workspaceId) {
    return { allowed: false, reason: 'workspace_mismatch', checks };
  }
  if (virtualKey.providerCredentialId !== providerCredential.id) {
    return { allowed: false, reason: 'credential_mismatch', checks };
  }
  if (virtualKey.revokedAt) {
    return { allowed: false, reason: 'virtual_key_revoked', checks };
  }
  return { allowed: true, reason: null, checks };
}

export function evaluateProxyAccess(
  request: ProxyAccessRequest,
  budgets: Budget[] = [],
  usageEvents: UsageEvent[] = [],
): ProxyAccessDecision {
  const checks: string[] = [];
  const binding = validateVirtualKeyBinding(request.virtualKey, request.providerCredential);
  checks.push(...binding.checks);
  if (!binding.allowed) return binding;

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return { allowed: false, reason: 'invalid_url', checks };
  }

  checks.push('domain_allowlist');
  const allowedDomains = request.virtualKey.allowedDomains.length > 0
    ? request.virtualKey.allowedDomains
    : request.providerCredential.allowedDomains;
  if (!hostnameAllowed(url.hostname, allowedDomains)) {
    return { allowed: false, reason: 'domain_not_allowed', checks };
  }

  checks.push('model_allowlist');
  if (request.model && request.virtualKey.allowedModels.length > 0 && !request.virtualKey.allowedModels.includes(request.model)) {
    return { allowed: false, reason: 'model_not_allowed', checks };
  }

  checks.push('hard_budget');
  const scopedBudgets = budgets.filter((budget) => request.virtualKey.budgetIds.includes(budget.id));
  const exceeded = wouldExceedHardBudget(
    scopedBudgets,
    usageEvents,
    request.projectedCostCents ?? 0,
    request.now ?? new Date(),
  );
  if (exceeded) {
    return { allowed: false, reason: `budget_exceeded:${exceeded.budget.id}`, checks };
  }

  return { allowed: true, reason: null, checks };
}
