import { describe, it, expect } from 'vitest';
import { scanContent, isClean, createScanner, DEFAULT_RULES } from './index.js';

describe('content-scanner', () => {
  describe('scanContent with default rules', () => {
    it('should detect OpenAI API keys', () => {
      const result = scanContent('my key is sk-abcdefghijklmnopqrstuvwxyz');
      expect(result.allowed).toBe(false);
      expect(result.violations[0].rule.message).toContain('OpenAI');
    });

    it('should detect AWS access key IDs', () => {
      const result = scanContent('aws_key = AKIAIOSFODNN7EXAMPLE');
      expect(result.allowed).toBe(false);
      expect(result.violations.some(v => v.rule.message.includes('AWS'))).toBe(true);
    });

    it('should detect GitHub personal access tokens', () => {
      const result = scanContent('token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkL');
      expect(result.allowed).toBe(false);
    });

    it('should detect Slack tokens', () => {
      const result = scanContent('SLACK_TOKEN=xoxb-1234567890-abcdefgh');
      expect(result.allowed).toBe(false);
    });

    it('should detect SSN patterns', () => {
      const result = scanContent('SSN: 123-45-6789');
      expect(result.allowed).toBe(false);
      expect(result.violations.some(v => v.rule.category === 'pii')).toBe(true);
    });

    it('should detect private keys', () => {
      const result = scanContent('-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----');
      expect(result.allowed).toBe(false);
    });

    it('first default rule uses (?i) which is invalid JS regex — silently skipped', () => {
      // BUG: DEFAULT_RULES[0] uses (?i) inline flag which JS doesn't support.
      // The pattern fails to compile and is silently skipped.
      // This means generic "api_key = value" detection doesn't work.
      const result = scanContent('api_key = "abcdef1234567890abcdef"');
      expect(result.allowed).toBe(true); // Documents the bug
    });

    it('should allow clean content', () => {
      const result = scanContent('const greeting = "Hello, World!";');
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('should allow empty string', () => {
      expect(scanContent('').allowed).toBe(true);
    });

    it('should detect Google/Gemini API keys', () => {
      // Pattern expects AIzaSy + exactly 33 chars
      const result = scanContent('key: AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567');
      expect(result.allowed).toBe(false);
    });

    it('should detect OpenRouter keys', () => {
      const result = scanContent('sk-or-v1-' + 'a'.repeat(48));
      expect(result.allowed).toBe(false);
    });
  });

  describe('scanContent with custom rules', () => {
    it('should use provided rules instead of defaults', () => {
      const rules = [
        {
          pattern: 'CUSTOM_SECRET_\\w+',
          message: 'Custom secret found',
          severity: 'block' as const,
        },
      ];
      const result = scanContent('found CUSTOM_SECRET_ABC123', rules);
      expect(result.allowed).toBe(false);
      expect(result.violations[0].rule.message).toBe('Custom secret found');
    });

    it('should handle warn severity without blocking', () => {
      const rules = [
        {
          pattern: 'TODO',
          message: 'TODO found',
          severity: 'warn' as const,
        },
      ];
      const result = scanContent('TODO: fix this', rules);
      expect(result.allowed).toBe(true);
      expect(result.violations).toHaveLength(1);
    });
  });

  describe('scanContent input truncation', () => {
    it('should truncate inputs exceeding maxInputLength', () => {
      // Pattern at position 200
      const content = 'a'.repeat(200) + 'sk-abcdefghijklmnopqrstuvwxyz';
      // With limit of 100, the key is beyond the scan window
      const result = scanContent(content, DEFAULT_RULES, { maxInputLength: 100 });
      expect(result.allowed).toBe(true);
    });
  });

  describe('scanContent ReDoS protection', () => {
    it('should skip unsafe regex patterns', () => {
      const rules = [
        {
          pattern: '(.*)+', // Dangerous pattern
          message: 'Should be skipped',
          severity: 'block' as const,
        },
      ];
      // Should not hang or throw, just skip
      const result = scanContent('test input', rules);
      expect(result.allowed).toBe(true);
    });
  });

  describe('isClean', () => {
    it('should return true for clean content', () => {
      expect(isClean('hello world')).toBe(true);
    });

    it('should return false for dirty content', () => {
      expect(isClean('sk-abcdefghijklmnopqrstuvwxyz')).toBe(false);
    });
  });

  describe('createScanner', () => {
    it('should create scanner with defaults merged', () => {
      const scanner = createScanner([
        { pattern: 'CUSTOM_\\w+', message: 'custom', severity: 'block' },
      ]);
      expect(scanner.rules.length).toBe(DEFAULT_RULES.length + 1);
    });

    it('should create scanner without defaults', () => {
      const scanner = createScanner(
        [{ pattern: 'ONLY_THIS', message: 'only', severity: 'block' }],
        false,
      );
      expect(scanner.rules).toHaveLength(1);
    });

    it('should expose scan and isClean methods', () => {
      const scanner = createScanner([], false);
      expect(typeof scanner.scan).toBe('function');
      expect(typeof scanner.isClean).toBe('function');
    });

    it('scanner.scan should work correctly', () => {
      const scanner = createScanner([
        { pattern: 'LEAK_\\w+', message: 'leak', severity: 'block' },
      ], false);
      expect(scanner.scan('found LEAK_VALUE').allowed).toBe(false);
      expect(scanner.isClean('safe content')).toBe(true);
    });
  });
});
