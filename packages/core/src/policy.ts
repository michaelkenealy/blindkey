import type {
  PolicyRule,
  PolicySet,
  ProxyRequest,
  EndpointAllowlistRule,
  MethodRestrictionRule,
  PayloadCapRule,
  RegexBlocklistRule,
} from './types.js';
import { PolicyDeniedError } from './errors.js';
import { safeRegexTest, SafeRegexError } from './safe-regex.js';

export interface PolicyEvalResult {
  allowed: boolean;
  checked: string[];
  blocking_policy: string | null;
  message: string | null;
}

function matchEndpointPath(pattern: string, actual: string): boolean {
  // Support trailing wildcard: /v1/charges/* matches /v1/charges/ch_123
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return actual === prefix || actual.startsWith(prefix + '/');
  }
  return actual === pattern;
}

function extractUrlPath(fullUrl: string): string {
  try {
    const url = new URL(fullUrl);
    return url.pathname;
  } catch {
    return fullUrl;
  }
}

function getNestedValue(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function evaluateEndpointAllowlist(rule: EndpointAllowlistRule, request: ProxyRequest): boolean {
  const path = extractUrlPath(request.url);
  return rule.endpoints.some(
    (ep) =>
      ep.method.toUpperCase() === request.method.toUpperCase() &&
      matchEndpointPath(ep.path, path)
  );
}

function evaluateMethodRestriction(rule: MethodRestrictionRule, request: ProxyRequest): boolean {
  return rule.allowed_methods
    .map((m) => m.toUpperCase())
    .includes(request.method.toUpperCase());
}

function evaluatePayloadCap(rule: PayloadCapRule, request: ProxyRequest): boolean {
  const value = getNestedValue(request.body, rule.field);
  if (typeof value !== 'number') return true; // field not present, skip
  return value <= rule.max;
}

function evaluateRegexBlocklist(rule: RegexBlocklistRule, request: ProxyRequest): boolean {
  const bodyStr = JSON.stringify(request.body ?? '');
  // Use safe regex evaluation to prevent ReDoS attacks
  return !rule.patterns.some((pattern) => {
    try {
      return safeRegexTest(pattern, bodyStr);
    } catch (e) {
      if (e instanceof SafeRegexError) {
        // Unsafe pattern - treat as non-matching and log
        console.warn(`[SECURITY] Blocked unsafe regex pattern in policy: ${e.message}`);
        return false;
      }
      throw e;
    }
  });
}

export function evaluatePolicy(policySet: PolicySet, request: ProxyRequest): PolicyEvalResult {
  const checked: string[] = [];

  for (const rule of policySet.rules) {
    checked.push(rule.type);

    let allowed: boolean;
    switch (rule.type) {
      case 'endpoint_allowlist':
        allowed = evaluateEndpointAllowlist(rule, request);
        break;
      case 'method_restriction':
        allowed = evaluateMethodRestriction(rule, request);
        break;
      case 'payload_cap':
        allowed = evaluatePayloadCap(rule, request);
        break;
      case 'regex_blocklist':
        allowed = evaluateRegexBlocklist(rule, request);
        break;
      case 'rate_limit':
        // Rate limits are enforced at the proxy layer via Redis, not here
        allowed = true;
        break;
      case 'human_approval':
        // Human approval is handled separately by the proxy
        allowed = true;
        break;
      default:
        allowed = true;
    }

    if (!allowed) {
      return {
        allowed: false,
        checked,
        blocking_policy: rule.type,
        message: `Blocked by ${rule.type} policy`,
      };
    }
  }

  return {
    allowed: true,
    checked,
    blocking_policy: null,
    message: null,
  };
}

export function enforcePolicy(policySet: PolicySet, request: ProxyRequest): void {
  const result = evaluatePolicy(policySet, request);
  if (!result.allowed) {
    throw new PolicyDeniedError(result.blocking_policy!, result.message ?? undefined);
  }
}
