/**
 * @blindkey/content-scanner
 *
 * Standalone content scanning library for detecting hardcoded secrets,
 * sensitive data patterns, and private keys in text content.
 *
 * Designed for use by Blindkey, Aquaman, OpenClaw-Secure, or any tool
 * that needs to prevent accidental credential leaks.
 */

// ── Types ──

export type ScanSeverity = 'block' | 'warn';

export interface ScanRule {
  /** Regex pattern to match against content */
  pattern: string;
  /** Human-readable message explaining the detection */
  message: string;
  /** Whether to block or just warn on match */
  severity: ScanSeverity;
  /** Optional category tag for grouping violations */
  category?: string;
}

export interface ScanViolation {
  rule: ScanRule;
  match: string;
}

export interface ScanResult {
  /** True if no blocking violations were found */
  allowed: boolean;
  /** All detected violations (both block and warn severity) */
  violations: ScanViolation[];
}

export interface ScanOptions {
  /** Maximum input length to scan (default: 100KB). Inputs exceeding this are truncated. */
  maxInputLength?: number;
}

// ── Default Rules ──

export const DEFAULT_RULES: ScanRule[] = [
  {
    pattern: '(api[_-]?key|secret[_-]?key|password|token|API[_-]?KEY|SECRET[_-]?KEY|PASSWORD|TOKEN|Api[_-]?Key|Secret[_-]?Key|Password|Token)\\s*[:=]\\s*["\']?[A-Za-z0-9_\\-]{16,}',
    message: 'Hardcoded API key or secret detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
    message: 'SSN-format data detected',
    severity: 'block',
    category: 'pii',
  },
  {
    pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    message: 'Private key detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'sk-[A-Za-z0-9]{20,}',
    message: 'OpenAI API key detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'AKIA[0-9A-Z]{16}',
    message: 'AWS Access Key ID detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'ghp_[A-Za-z0-9]{36,}',
    message: 'GitHub personal access token detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'xox[bpors]-[A-Za-z0-9\\-]{10,}',
    message: 'Slack token detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'AIzaSy[A-Za-z0-9_\\-]{33}',
    message: 'Google/Gemini API key detected',
    severity: 'block',
    category: 'credential',
  },
  {
    pattern: 'sk-or-v1-[A-Za-z0-9]{48,}',
    message: 'OpenRouter API key detected',
    severity: 'block',
    category: 'credential',
  },
];

// ── Pattern Validation (ReDoS protection) ──

const DANGEROUS_PATTERNS = [
  /\(\.\*\)\+/,
  /\(\[^\]]*\)\+/,
  /\(\.+\)\+/,
  /\(\w+\)\+/,
  /\(\s+\)\+/,
  /\(\.\*\)\*/,
  /\(\.\+\)\*/,
];

function isPatternSafe(pattern: string): boolean {
  for (const dangerous of DANGEROUS_PATTERNS) {
    if (dangerous.test(pattern)) return false;
  }
  if (pattern.length > 500) return false;
  const alternations = (pattern.match(/\|/g) || []).length;
  if (alternations > 20) return false;
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

// ── Core Scanner ──

/**
 * Scan content against a set of rules. Returns whether the content
 * passes (no blocking violations) and all detected violations.
 */
export function scanContent(
  content: string,
  rules: ScanRule[] = DEFAULT_RULES,
  options: ScanOptions = {},
): ScanResult {
  const { maxInputLength = 100_000 } = options;
  const input = content.length > maxInputLength ? content.slice(0, maxInputLength) : content;

  const violations: ScanViolation[] = [];

  for (const rule of rules) {
    if (!isPatternSafe(rule.pattern)) {
      // Skip unsafe patterns silently to prevent ReDoS
      continue;
    }

    try {
      const regex = new RegExp(rule.pattern, 'g');
      const matches = input.match(regex);
      if (matches) {
        violations.push({ rule, match: matches[0] });
      }
    } catch {
      // Skip patterns that fail to compile
      continue;
    }
  }

  return {
    allowed: !violations.some(v => v.rule.severity === 'block'),
    violations,
  };
}

/**
 * Convenience function to check if content is clean (no blocking violations).
 */
export function isClean(content: string, rules?: ScanRule[]): boolean {
  return scanContent(content, rules).allowed;
}

/**
 * Create a scanner with custom rules merged with defaults.
 */
export function createScanner(customRules: ScanRule[], includeDefaults = true) {
  const rules = includeDefaults ? [...DEFAULT_RULES, ...customRules] : customRules;
  return {
    scan: (content: string, options?: ScanOptions) => scanContent(content, rules, options),
    isClean: (content: string) => scanContent(content, rules).allowed,
    rules,
  };
}
