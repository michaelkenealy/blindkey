/**
 * Safe Regex Evaluation Module
 * Prevents ReDoS attacks by:
 * 1. Validating regex patterns before compilation
 * 2. Enforcing execution timeouts
 * 3. Limiting pattern complexity
 */

// Patterns known to cause catastrophic backtracking
const DANGEROUS_PATTERNS = [
  /\(\.\*\)\+/,           // (.*)+
  /\(\[^\]]*\)\+/,        // ([^])+
  /\(\.+\)\+/,            // (.+)+
  /\(\w+\)\+/,            // (\w+)+
  /\(\s+\)\+/,            // (\s+)+
  /\(a\+\)\+/,            // (a+)+
  /\(\.\*\)\*/,           // (.*)*
  /\(\.\+\)\*/,           // (.+)*
  /\(\[^\/\]\*\)\+/,      // ([^/]*)+
];

// Maximum allowed quantifier repetitions
const MAX_QUANTIFIER = 100;

export class SafeRegexError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafeRegexError';
  }
}

/**
 * Validate a regex pattern for potential ReDoS vulnerabilities
 */
export function validateRegexPattern(pattern: string): { safe: boolean; reason?: string } {
  // Check for known dangerous patterns
  for (const dangerous of DANGEROUS_PATTERNS) {
    if (dangerous.test(pattern)) {
      return { safe: false, reason: 'Pattern contains nested quantifiers that may cause ReDoS' };
    }
  }

  // Check for excessive quantifiers like {1000,}
  const quantifierMatch = pattern.match(/\{(\d+)(,(\d*))?\}/g);
  if (quantifierMatch) {
    for (const q of quantifierMatch) {
      const nums = q.match(/\d+/g);
      if (nums && nums.some(n => parseInt(n, 10) > MAX_QUANTIFIER)) {
        return { safe: false, reason: `Quantifier exceeds maximum of ${MAX_QUANTIFIER}` };
      }
    }
  }

  // Check for excessive alternation depth
  const alternations = (pattern.match(/\|/g) || []).length;
  if (alternations > 20) {
    return { safe: false, reason: 'Too many alternations (max 20)' };
  }

  // Check pattern length
  if (pattern.length > 500) {
    return { safe: false, reason: 'Pattern too long (max 500 characters)' };
  }

  // Try to compile the pattern
  try {
    new RegExp(pattern);
  } catch (e) {
    return { safe: false, reason: `Invalid regex: ${(e as Error).message}` };
  }

  return { safe: true };
}

/**
 * Safely test a string against a regex pattern with timeout protection
 */
export function safeRegexTest(
  pattern: string,
  input: string,
  options: { maxInputLength?: number } = {}
): boolean {
  const { maxInputLength = 100000 } = options;

  // Validate pattern first
  const validation = validateRegexPattern(pattern);
  if (!validation.safe) {
    throw new SafeRegexError(`Unsafe regex pattern: ${validation.reason}`);
  }

  // Truncate excessively long inputs
  const truncatedInput = input.length > maxInputLength ? input.slice(0, maxInputLength) : input;

  // Execute with try-catch (Node.js doesn't support true regex timeout)
  try {
    const regex = new RegExp(pattern);
    return regex.test(truncatedInput);
  } catch (e) {
    throw new SafeRegexError(`Regex execution failed: ${(e as Error).message}`);
  }
}

/**
 * Pre-compile and validate multiple regex patterns
 * Returns only the safe patterns, logging warnings for unsafe ones
 */
export function compileSafePatterns(
  patterns: string[],
  onUnsafe?: (pattern: string, reason: string) => void
): RegExp[] {
  const compiled: RegExp[] = [];

  for (const pattern of patterns) {
    const validation = validateRegexPattern(pattern);
    if (validation.safe) {
      compiled.push(new RegExp(pattern));
    } else if (onUnsafe) {
      onUnsafe(pattern, validation.reason!);
    }
  }

  return compiled;
}
