# @blindkey/content-scanner

Standalone content scanning library for detecting hardcoded secrets, sensitive data patterns, and private keys in text content.

## Installation

```bash
npm install @blindkey/content-scanner
```

## Usage

```typescript
import { scanContent, isClean, createScanner } from '@blindkey/content-scanner';

// Quick scan with default rules
const result = scanContent('api_key = "sk-abc123def456ghi789"');
console.log(result.allowed);    // false
console.log(result.violations); // [{ rule: ..., match: 'api_key = "sk-abc123def456ghi789"' }]

// Boolean check
if (!isClean(fileContents)) {
  console.error('Content contains sensitive data');
}

// Custom scanner with additional rules
const scanner = createScanner([
  {
    pattern: 'INTERNAL_SECRET_[A-Z0-9]{8,}',
    message: 'Internal secret token detected',
    severity: 'block',
    category: 'internal',
  },
]);

const result = scanner.scan(content);
```

## Default Rules

| Pattern | Description | Severity |
|---------|-------------|----------|
| API key / secret / password / token assignments | Hardcoded credential values | block |
| SSN format (`XXX-XX-XXXX`) | Social Security Number patterns | block |
| PEM private keys | RSA, EC, DSA, OpenSSH private keys | block |
| `sk-*` tokens | OpenAI API keys | block |
| `AKIA*` strings | AWS Access Key IDs | block |
| `ghp_*` tokens | GitHub personal access tokens | block |
| `xox[bpors]-*` tokens | Slack tokens | block |

## API

### `scanContent(content, rules?, options?)`

Scan content against rules. Returns `{ allowed: boolean, violations: ScanViolation[] }`.

### `isClean(content, rules?)`

Returns `true` if no blocking violations are found.

### `createScanner(customRules, includeDefaults?)`

Create a reusable scanner with custom rules optionally merged with defaults.

## Integration

This package is used by:
- `@blindkey/openclaw-secure-backend` - OpenClaw-Secure backend adapter
- `@blindkey/aquaman-backend` - Aquaman backend adapter
- `@blindkey/fs-proxy` - Filesystem proxy content scanning

It can also be used standalone by any tool that needs to prevent credential leaks in content.
