import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { DomainNotAllowedError, EgressDeniedError } from '@blindkey/core';
import type { Secret } from '@blindkey/core';

const ALLOW_INSECURE_HTTP = process.env.BLINDKEY_ALLOW_INSECURE_HTTP === 'true';
const ALLOW_PRIVATE_EGRESS = process.env.BLINDKEY_ALLOW_PRIVATE_EGRESS === 'true';

function normalizeAllowedDomains(input: string[]): string[] {
  return input.map((d) => d.toLowerCase().trim());
}

function isHostnameAllowed(hostname: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((domain) => {
    if (domain.startsWith('*.')) {
      const suffix = domain.slice(2);
      return hostname === suffix || hostname.endsWith('.' + suffix);
    }
    return hostname === domain;
  });
}

function parseIpv4(ip: string): number[] {
  return ip.split('.').map((part) => Number.parseInt(part, 10));
}

function isPrivateIpv4(ip: string): boolean {
  const [a, b] = parseIpv4(ip);
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === '::1') return true;
  if (normalized === '::') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  if (normalized.startsWith('fe80:')) return true;
  return false;
}

function assertIpAllowed(ip: string, target: string): void {
  const version = isIP(ip);
  if (version === 4 && isPrivateIpv4(ip) && !ALLOW_PRIVATE_EGRESS) {
    throw new EgressDeniedError(target, `resolved to private IPv4 address ${ip}`);
  }
  if (version === 6 && isPrivateIpv6(ip) && !ALLOW_PRIVATE_EGRESS) {
    throw new EgressDeniedError(target, `resolved to private IPv6 address ${ip}`);
  }
}

async function assertDnsResolvesPublic(hostname: string, target: string): Promise<void> {
  try {
    const results = await lookup(hostname, { all: true, verbatim: true });
    if (results.length === 0) {
      throw new EgressDeniedError(target, 'hostname resolution returned no addresses');
    }

    for (const result of results) {
      assertIpAllowed(result.address, target);
    }
  } catch (err) {
    if (err instanceof EgressDeniedError) {
      throw err;
    }
    throw new EgressDeniedError(target, `DNS resolution failed for hostname ${hostname}`);
  }
}

/**
 * Validates target URL against domain allowlist and SSRF egress controls.
 */
export async function validateTargetDomain(secret: Secret, targetUrl: string): Promise<void> {
  const allowedDomains = secret.allowed_domains;

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new DomainNotAllowedError('<invalid-url>', secret.vault_ref);
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'https:' && !(ALLOW_INSECURE_HTTP && protocol === 'http:')) {
    throw new EgressDeniedError(targetUrl, 'only https targets are allowed');
  }

  if (parsed.username || parsed.password) {
    throw new EgressDeniedError(targetUrl, 'URL userinfo is not allowed');
  }

  const hostname = parsed.hostname.toLowerCase();

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new EgressDeniedError(targetUrl, 'localhost targets are blocked');
  }

  const literalIpVersion = isIP(hostname);
  if (literalIpVersion !== 0) {
    assertIpAllowed(hostname, targetUrl);
  }

  // null means no domain restriction (egress controls still apply)
  if (allowedDomains !== null && allowedDomains !== undefined) {
    if (allowedDomains.length === 0) {
      throw new DomainNotAllowedError('<all-blocked>', secret.vault_ref);
    }

    const normalized = normalizeAllowedDomains(allowedDomains);
    if (!isHostnameAllowed(hostname, normalized)) {
      throw new DomainNotAllowedError(hostname, secret.vault_ref);
    }
  }

  if (literalIpVersion === 0) {
    await assertDnsResolvesPublic(hostname, targetUrl);
  }
}
