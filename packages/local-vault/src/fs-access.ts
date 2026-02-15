import { evaluateFsPolicy, type FsRequest, type FsPolicyRule } from '@blindkey/core';
import type { LocalVault } from './index.js';

/** Default filesystem policies applied to all operations. */
export const DEFAULT_FS_POLICIES: FsPolicyRule[] = [
  {
    type: 'fs_block_patterns',
    patterns: [
      '**/.env', '**/.env.*', '**/*.pem', '**/*.key',
      '**/id_rsa*', '**/id_ed25519*', '**/credentials*',
      '**/.git/config', '**/.aws/**', '**/.ssh/**',
      '**/.gnupg/**', '**/.npmrc', '**/.pypirc',
      '**/.docker/config.json', '**/.kube/config',
    ],
  },
  {
    type: 'fs_size_limit',
    max_read_bytes: 10 * 1024 * 1024,
    max_write_bytes: 5 * 1024 * 1024,
  },
  {
    type: 'fs_content_scan',
    on: 'write',
    block_if_contains: [
      {
        pattern: '(?i)(api[_-]?key|secret[_-]?key|password|token)\\s*[:=]\\s*["\']?[A-Za-z0-9_\\-]{16,}',
        message: 'Content appears to contain hardcoded secrets or API keys',
      },
      {
        pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
        message: 'Content appears to contain SSN-format data',
      },
    ],
  },
];

/**
 * Check filesystem access for an operation. Checks grants first, then policies.
 * Returns { allowed, reason? }.
 */
export async function checkFsAccess(
  vault: LocalVault,
  operation: string,
  path: string,
): Promise<{ allowed: boolean; reason?: string }> {
  // 1. Check grants
  const grantResult = vault.grants.checkAccess(operation as FsRequest['operation'], path);
  if (!grantResult.granted) {
    vault.audit.log({ action: `fs_${operation}`, path, granted: false, blocking_rule: 'no_grant' });
    return { allowed: false, reason: grantResult.reason ?? 'No filesystem grant' };
  }

  // 2. Check policies (block patterns, size limits)
  const effectivePolicies = vault.policies
    ? vault.policies.getEffective()
    : DEFAULT_FS_POLICIES;
  const fsReq: FsRequest = { operation: operation as FsRequest['operation'], path };
  const policyResult = evaluateFsPolicy(effectivePolicies, fsReq);
  if (!policyResult.allowed) {
    vault.audit.log({
      action: `fs_${operation}`,
      path,
      granted: false,
      blocking_rule: policyResult.blocking_rule ?? undefined,
    });
    return { allowed: false, reason: policyResult.message ?? 'Blocked by policy' };
  }

  return { allowed: true };
}
