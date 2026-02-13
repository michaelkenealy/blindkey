import type { FsPolicyRule } from '@blindkey/core';

/**
 * Default block patterns for sensitive files and directories.
 * These are always applied unless explicitly overridden.
 */
export const DEFAULT_BLOCK_PATTERNS: string[] = [
  '**/.env',
  '**/.env.*',
  '**/*.pem',
  '**/*.key',
  '**/id_rsa*',
  '**/id_ed25519*',
  '**/credentials*',
  '**/.git/config',
  '**/.aws/**',
  '**/.ssh/**',
  '**/.gnupg/**',
  '**/.npmrc',
  '**/.pypirc',
  '**/.docker/config.json',
  '**/.kube/config',
];

/**
 * Default filesystem policy rules applied to all sessions.
 */
export const DEFAULT_FS_POLICIES: FsPolicyRule[] = [
  {
    type: 'fs_block_patterns',
    patterns: DEFAULT_BLOCK_PATTERNS,
  },
  {
    type: 'fs_size_limit',
    max_read_bytes: 10 * 1024 * 1024,   // 10MB
    max_write_bytes: 5 * 1024 * 1024,    // 5MB
  },
  {
    type: 'fs_content_scan',
    on: 'write',
    block_if_contains: [
      {
        pattern: '(?i)(api[_-]?key|secret[_-]?key|password|token)\\s*[:=]\\s*["\']?[A-Za-z0-9_\\-]{16,}',
        message: 'File appears to contain hardcoded secrets or API keys',
      },
      {
        pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
        message: 'File appears to contain SSN-format data',
      },
    ],
  },
];
