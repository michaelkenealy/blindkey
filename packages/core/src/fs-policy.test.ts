import { describe, it, expect } from 'vitest';
import { checkGrant, evaluateFsPolicy, type FsGrantCheckResult } from './fs-policy.js';
import type { FilesystemGrant, FsPolicyRule, FsRequest } from './types.js';

function makeGrant(overrides: Partial<FilesystemGrant> & { path: string }): FilesystemGrant {
  return {
    id: 'grant-1',
    session_id: 'sess-1',
    permissions: ['read'],
    recursive: false,
    requires_approval: false,
    created_at: new Date(),
    ...overrides,
  };
}

describe('fs-policy', () => {
  describe('checkGrant', () => {
    it('should grant exact path match with correct permission', () => {
      const grants = [makeGrant({ path: '/home/user/file.txt', permissions: ['read'] })];
      const result = checkGrant(grants, 'read', '/home/user/file.txt');
      expect(result.granted).toBe(true);
    });

    it('should deny when no matching grant exists', () => {
      const grants = [makeGrant({ path: '/home/user/other.txt', permissions: ['read'] })];
      const result = checkGrant(grants, 'read', '/home/user/file.txt');
      expect(result.granted).toBe(false);
      expect(result.reason).toContain('No filesystem grant');
    });

    it('should deny when permission does not match', () => {
      const grants = [makeGrant({ path: '/home/user/file.txt', permissions: ['read'] })];
      const result = checkGrant(grants, 'write', '/home/user/file.txt');
      expect(result.granted).toBe(false);
    });

    it('should grant recursive subdirectory access', () => {
      const grants = [makeGrant({ path: '/home/user/project', permissions: ['read', 'list'], recursive: true })];
      expect(checkGrant(grants, 'read', '/home/user/project/src/index.ts').granted).toBe(true);
      expect(checkGrant(grants, 'list', '/home/user/project/src').granted).toBe(true);
    });

    it('should deny subdirectory access without recursive flag', () => {
      const grants = [makeGrant({ path: '/home/user/project', permissions: ['read'] })];
      expect(checkGrant(grants, 'read', '/home/user/project/src/index.ts').granted).toBe(false);
    });

    it('should map info operation to read permission', () => {
      const grants = [makeGrant({ path: '/home/user/file.txt', permissions: ['read'] })];
      expect(checkGrant(grants, 'info', '/home/user/file.txt').granted).toBe(true);
    });
  });

  describe('evaluateFsPolicy', () => {
    describe('fs_block_patterns', () => {
      const rules: FsPolicyRule[] = [
        { type: 'fs_block_patterns', patterns: ['**/.env', '**/.ssh/**', '**/*.pem'] },
      ];

      it('should block .env files', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/home/user/.env' });
        expect(result.allowed).toBe(false);
        expect(result.blocking_rule).toBe('fs_block_patterns');
      });

      it('should block .ssh subdirectories', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/home/user/.ssh/id_rsa' });
        expect(result.allowed).toBe(false);
      });

      it('should block .pem files', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/home/user/cert.pem' });
        expect(result.allowed).toBe(false);
      });

      it('should allow non-matching paths', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/home/user/src/index.ts' });
        expect(result.allowed).toBe(true);
      });
    });

    describe('fs_size_limit', () => {
      const rules: FsPolicyRule[] = [
        { type: 'fs_size_limit', max_read_bytes: 1000, max_write_bytes: 500 },
      ];

      it('should block reads exceeding limit', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/file' }, 1500);
        expect(result.allowed).toBe(false);
        expect(result.blocking_rule).toBe('fs_size_limit');
      });

      it('should allow reads within limit', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/file' }, 500);
        expect(result.allowed).toBe(true);
      });

      it('should block writes exceeding limit', () => {
        const result = evaluateFsPolicy(rules, { operation: 'write', path: '/file' }, 600);
        expect(result.allowed).toBe(false);
      });

      it('should block creates exceeding write limit', () => {
        const result = evaluateFsPolicy(rules, { operation: 'create', path: '/file' }, 600);
        expect(result.allowed).toBe(false);
      });

      it('should allow when no contentSize provided', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/file' });
        expect(result.allowed).toBe(true);
      });
    });

    describe('fs_extension_allowlist', () => {
      const rules: FsPolicyRule[] = [
        { type: 'fs_extension_allowlist', extensions: ['.ts', '.js', '.json'] },
      ];

      it('should allow writes to permitted extensions', () => {
        const result = evaluateFsPolicy(rules, { operation: 'write', path: '/src/index.ts' });
        expect(result.allowed).toBe(true);
      });

      it('should block writes to non-permitted extensions', () => {
        const result = evaluateFsPolicy(rules, { operation: 'write', path: '/src/config.yaml' });
        expect(result.allowed).toBe(false);
        expect(result.blocking_rule).toBe('fs_extension_allowlist');
      });

      it('should not apply to read operations', () => {
        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/src/config.yaml' });
        expect(result.allowed).toBe(true);
      });

      it('should be case-insensitive', () => {
        const result = evaluateFsPolicy(rules, { operation: 'write', path: '/src/index.TS' });
        expect(result.allowed).toBe(true);
      });
    });

    describe('fs_content_scan', () => {
      const rules: FsPolicyRule[] = [
        {
          type: 'fs_content_scan',
          on: 'write',
          block_if_contains: [
            { pattern: 'sk-[A-Za-z0-9]{20,}', message: 'OpenAI key detected' },
            { pattern: '\\d{3}-\\d{2}-\\d{4}', message: 'SSN detected' },
          ],
        },
      ];

      it('should block writes containing API keys', () => {
        const result = evaluateFsPolicy(rules, {
          operation: 'write',
          path: '/file.ts',
          content: 'const key = "sk-abcdefghijklmnopqrstuvwxyz"',
        });
        expect(result.allowed).toBe(false);
        expect(result.message).toContain('OpenAI key');
      });

      it('should block writes containing SSN', () => {
        const result = evaluateFsPolicy(rules, {
          operation: 'write',
          path: '/file.ts',
          content: 'SSN: 123-45-6789',
        });
        expect(result.allowed).toBe(false);
        expect(result.message).toContain('SSN');
      });

      it('should allow clean content', () => {
        const result = evaluateFsPolicy(rules, {
          operation: 'write',
          path: '/file.ts',
          content: 'const greeting = "hello world";',
        });
        expect(result.allowed).toBe(true);
      });

      it('should not scan read operations', () => {
        const result = evaluateFsPolicy(rules, {
          operation: 'read',
          path: '/file.ts',
          content: 'sk-abcdefghijklmnopqrstuvwxyz',
        });
        expect(result.allowed).toBe(true);
      });
    });

    describe('multiple rules', () => {
      it('should evaluate rules in order and stop at first block', () => {
        const rules: FsPolicyRule[] = [
          { type: 'fs_block_patterns', patterns: ['**/.env'] },
          { type: 'fs_size_limit', max_read_bytes: 100, max_write_bytes: 50 },
        ];

        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/app/.env' }, 50);
        expect(result.blocking_rule).toBe('fs_block_patterns');
      });

      it('should allow when all rules pass', () => {
        const rules: FsPolicyRule[] = [
          { type: 'fs_block_patterns', patterns: ['**/.env'] },
          { type: 'fs_size_limit', max_read_bytes: 1000, max_write_bytes: 500 },
        ];

        const result = evaluateFsPolicy(rules, { operation: 'read', path: '/app/index.ts' }, 100);
        expect(result.allowed).toBe(true);
      });
    });
  });
});
