import { DomainNotAllowedError } from '@blindkey/core';
import type { Secret } from '@blindkey/core';

/**
 * Validates that the target URL's hostname is in the secret's allowed_domains list.
 *
 * Semantics:
 * - null  → no restriction (all domains allowed)
 * - []    → block all requests (strict lockdown)
 * - ['api.stripe.com'] → only that domain
 * - ['*.stripe.com']   → wildcard subdomain match
 */
export function validateTargetDomain(secret: Secret, targetUrl: string): void {
  const allowedDomains = secret.allowed_domains;

  // null means no restriction
  if (allowedDomains === null || allowedDomains === undefined) {
    return;
  }

  // Empty array means block everything
  if (allowedDomains.length === 0) {
    throw new DomainNotAllowedError('<all-blocked>', secret.vault_ref);
  }

  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    throw new DomainNotAllowedError('<invalid-url>', secret.vault_ref);
  }

  const normalized = allowedDomains.map((d) => d.toLowerCase().trim());

  const isAllowed = normalized.some((domain) => {
    if (domain.startsWith('*.')) {
      const suffix = domain.slice(2);
      return hostname === suffix || hostname.endsWith('.' + suffix);
    }
    return hostname === domain;
  });

  if (!isAllowed) {
    throw new DomainNotAllowedError(hostname, secret.vault_ref);
  }
}
