import type {
  EndpointAllowlistRule,
  HumanApprovalRule,
  MethodRestrictionRule,
  PayloadCapRule,
  PolicyRule,
  RateLimitRule,
  RegexBlocklistRule,
} from './types.js';
import { ValidationError } from './errors.js';
import { validateRegexPattern } from './safe-regex.js';

const ALLOWED_HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

type UnknownRecord = Record<string, unknown>;

function asObject(value: unknown, path: string): UnknownRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ValidationError(`${path} must be an object`);
  }
  return value as UnknownRecord;
}

function asNonEmptyString(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ValidationError(`${path} must be a non-empty string`);
  }
  return value.trim();
}

function asPositiveInteger(value: unknown, path: string): number {
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new ValidationError(`${path} must be a positive integer`);
  }
  return value as number;
}

function asNonNegativeNumber(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new ValidationError(`${path} must be a non-negative number`);
  }
  return value;
}

function asStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || !value.every((entry) => typeof entry === 'string' && entry.trim().length > 0)) {
    throw new ValidationError(`${path} must be a non-empty array of strings`);
  }
  return value.map((entry) => entry.trim());
}

function validateEndpointAllowlistRule(rule: UnknownRecord): EndpointAllowlistRule {
  if (!Array.isArray(rule.endpoints) || rule.endpoints.length === 0) {
    throw new ValidationError('endpoint_allowlist.endpoints must be a non-empty array');
  }

  const endpoints = rule.endpoints.map((endpoint, index) => {
    const ep = asObject(endpoint, `endpoint_allowlist.endpoints[${index}]`);
    const method = asNonEmptyString(ep.method, `endpoint_allowlist.endpoints[${index}].method`).toUpperCase();
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      throw new ValidationError(`endpoint_allowlist.endpoints[${index}].method is not supported`);
    }

    const path = asNonEmptyString(ep.path, `endpoint_allowlist.endpoints[${index}].path`);
    if (!path.startsWith('/')) {
      throw new ValidationError(`endpoint_allowlist.endpoints[${index}].path must start with /`);
    }

    return { method, path };
  });

  return { type: 'endpoint_allowlist', endpoints };
}

function validateMethodRestrictionRule(rule: UnknownRecord): MethodRestrictionRule {
  const allowed_methods = asStringArray(rule.allowed_methods, 'method_restriction.allowed_methods')
    .map((m) => m.toUpperCase());

  for (const method of allowed_methods) {
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      throw new ValidationError(`method_restriction.allowed_methods contains unsupported method: ${method}`);
    }
  }

  return { type: 'method_restriction', allowed_methods };
}

function validateRateLimitRule(rule: UnknownRecord): RateLimitRule {
  const max_requests = asPositiveInteger(rule.max_requests, 'rate_limit.max_requests');
  const window_seconds = asPositiveInteger(rule.window_seconds, 'rate_limit.window_seconds');

  if (window_seconds > 86_400) {
    throw new ValidationError('rate_limit.window_seconds must be <= 86400');
  }

  return { type: 'rate_limit', max_requests, window_seconds };
}

function validatePayloadCapRule(rule: UnknownRecord): PayloadCapRule {
  const field = asNonEmptyString(rule.field, 'payload_cap.field');
  const max = asNonNegativeNumber(rule.max, 'payload_cap.max');

  const currency_field = rule.currency_field === undefined
    ? undefined
    : asNonEmptyString(rule.currency_field, 'payload_cap.currency_field');

  return { type: 'payload_cap', field, max, currency_field };
}

function validateRegexBlocklistRule(rule: UnknownRecord): RegexBlocklistRule {
  const patterns = asStringArray(rule.patterns, 'regex_blocklist.patterns');

  for (const pattern of patterns) {
    const result = validateRegexPattern(pattern);
    if (!result.safe) {
      throw new ValidationError(`regex_blocklist pattern is unsafe: ${result.reason}`);
    }
  }

  return { type: 'regex_blocklist', patterns };
}

function validateHumanApprovalRule(rule: UnknownRecord): HumanApprovalRule {
  const condition = asNonEmptyString(rule.condition, 'human_approval.condition');
  const timeout_seconds = asPositiveInteger(rule.timeout_seconds, 'human_approval.timeout_seconds');
  if (timeout_seconds > 3600) {
    throw new ValidationError('human_approval.timeout_seconds must be <= 3600');
  }

  const on_timeout = rule.on_timeout;
  if (on_timeout !== 'deny' && on_timeout !== 'allow') {
    throw new ValidationError('human_approval.on_timeout must be "deny" or "allow"');
  }

  return { type: 'human_approval', condition, timeout_seconds, on_timeout };
}

export function validatePolicyRules(rules: unknown): PolicyRule[] {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new ValidationError('rules must be a non-empty array');
  }

  return rules.map((value, index) => {
    const rule = asObject(value, `rules[${index}]`);
    const type = asNonEmptyString(rule.type, `rules[${index}].type`);

    switch (type) {
      case 'endpoint_allowlist':
        return validateEndpointAllowlistRule(rule);
      case 'method_restriction':
        return validateMethodRestrictionRule(rule);
      case 'rate_limit':
        return validateRateLimitRule(rule);
      case 'payload_cap':
        return validatePayloadCapRule(rule);
      case 'regex_blocklist':
        return validateRegexBlocklistRule(rule);
      case 'human_approval':
        return validateHumanApprovalRule(rule);
      default:
        throw new ValidationError(`Unsupported policy rule type: ${type}`);
    }
  });
}
