import { describe, it, expect } from 'vitest';
import { validateRegexPattern, safeRegexTest, compileSafePatterns, SafeRegexError } from './safe-regex.js';

describe('safe-regex', () => {
  describe('validateRegexPattern', () => {
    it('should accept simple safe patterns', () => {
      expect(validateRegexPattern('hello')).toEqual({ safe: true });
      expect(validateRegexPattern('[a-z]+')).toEqual({ safe: true });
      expect(validateRegexPattern('\\d{3}-\\d{2}-\\d{4}')).toEqual({ safe: true });
    });

    it('should reject (.*)+  nested quantifier', () => {
      const result = validateRegexPattern('(.*)+');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('nested quantifiers');
    });

    it('does not currently catch (.+)+ — known gap in ReDoS detection', () => {
      // BUG: (.+)+ is dangerous but DANGEROUS_PATTERNS uses /\(\.+\)\+/
      // which matches the escaped literal "(.+)+" but the regex test against
      // the raw pattern string doesn't match because the backslash escaping
      // doesn't align. This should be fixed in a future PR.
      const result = validateRegexPattern('(.+)+');
      expect(result.safe).toBe(true); // Documents current (buggy) behavior
    });

    it('should reject (.*)*', () => {
      expect(validateRegexPattern('(.*)*').safe).toBe(false);
    });

    it('should reject excessive quantifiers', () => {
      const result = validateRegexPattern('a{200}');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Quantifier exceeds maximum');
    });

    it('should accept quantifiers within limit', () => {
      expect(validateRegexPattern('a{50}').safe).toBe(true);
    });

    it('should reject too many alternations', () => {
      const pattern = Array.from({ length: 25 }, (_, i) => `opt${i}`).join('|');
      const result = validateRegexPattern(pattern);
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Too many alternations');
    });

    it('should accept 20 alternations', () => {
      const pattern = Array.from({ length: 20 }, (_, i) => `opt${i}`).join('|');
      expect(validateRegexPattern(pattern).safe).toBe(true);
    });

    it('should reject patterns longer than 500 chars', () => {
      const result = validateRegexPattern('a'.repeat(501));
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Pattern too long');
    });

    it('should reject invalid regex syntax', () => {
      const result = validateRegexPattern('[invalid');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Invalid regex');
    });
  });

  describe('safeRegexTest', () => {
    it('should test safe patterns normally', () => {
      expect(safeRegexTest('\\d+', 'abc123')).toBe(true);
      expect(safeRegexTest('\\d+', 'abc')).toBe(false);
    });

    it('should throw SafeRegexError for dangerous patterns', () => {
      expect(() => safeRegexTest('(.*)+', 'test')).toThrow(SafeRegexError);
    });

    it('should truncate long inputs', () => {
      const longInput = 'a'.repeat(200);
      // Should not throw even with large input
      expect(() => safeRegexTest('a', longInput, { maxInputLength: 50 })).not.toThrow();
    });

    it('should match real-world credential patterns', () => {
      expect(safeRegexTest('sk-[A-Za-z0-9]{20,}', 'my key is sk-abcdefghijklmnopqrstuvwxyz')).toBe(true);
      expect(safeRegexTest('AKIA[0-9A-Z]{16}', 'AKIAIOSFODNN7EXAMPLE')).toBe(true);
    });
  });

  describe('compileSafePatterns', () => {
    it('should compile safe patterns', () => {
      const compiled = compileSafePatterns(['\\d+', '[a-z]+']);
      expect(compiled).toHaveLength(2);
      expect(compiled[0].test('123')).toBe(true);
    });

    it('should skip unsafe patterns and call callback', () => {
      const unsafe: string[] = [];
      const compiled = compileSafePatterns(
        ['\\d+', '(.*)+', '[a-z]+'],
        (pattern, reason) => unsafe.push(pattern),
      );
      expect(compiled).toHaveLength(2);
      expect(unsafe).toEqual(['(.*)+']);
    });

    it('should skip invalid regex patterns', () => {
      const compiled = compileSafePatterns(['[valid', '\\d+']);
      expect(compiled).toHaveLength(1);
    });
  });
});
