# @blindkey/fs-gate

Standalone filesystem gating library providing path-based permission checking, grant management, and filesystem policy evaluation.

## Installation

```bash
npm install @blindkey/fs-gate
```

## Usage

### Grant Management

```typescript
import { GrantManager } from '@blindkey/fs-gate';

const manager = new GrantManager();

// Grant read/write access to a directory
manager.grant({
  path: '/home/user/project',
  permissions: ['read', 'write', 'list'],
  recursive: true,
});

// Check access
const check = manager.checkAccess('read', '/home/user/project/src/index.ts');
console.log(check.granted); // true

const denied = manager.checkAccess('delete', '/home/user/project/src/index.ts');
console.log(denied.granted); // false
console.log(denied.reason);  // "No filesystem grant covers delete on ..."

// Revoke access
manager.revoke('/home/user/project');
```

### Standalone Access Checking

```typescript
import { checkAccess, type FsGrant } from '@blindkey/fs-gate';

const grants: FsGrant[] = [
  { id: '1', path: '/data', permissions: ['read', 'list'], recursive: true, requires_approval: false },
];

const result = checkAccess(grants, 'read', '/data/reports/2024.csv');
console.log(result.granted); // true
```

### Policy Evaluation

```typescript
import { evaluatePolicy, DEFAULT_BLOCK_PATTERNS } from '@blindkey/fs-gate';

const rules = [
  { type: 'fs_block_patterns' as const, patterns: DEFAULT_BLOCK_PATTERNS },
  { type: 'fs_size_limit' as const, max_read_bytes: 10_000_000, max_write_bytes: 5_000_000 },
];

const result = evaluatePolicy(rules, { operation: 'read', path: '/home/user/.env' });
console.log(result.allowed);       // false
console.log(result.blocking_rule); // 'fs_block_patterns'
```

## Default Blocked Patterns

Paths matching these patterns are blocked by default:
- `.env`, `.env.*` - Environment files
- `*.pem`, `*.key` - Certificate/key files
- `id_rsa*`, `id_ed25519*` - SSH keys
- `credentials*` - Credential files
- `.git/config`, `.aws/**`, `.ssh/**`, `.gnupg/**` - Config directories
- `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube/config` - Tool configs

## API

### `checkAccess(grants, operation, path)`

Check if an operation is permitted by any of the provided grants.

### `evaluatePolicy(rules, request, contentSize?)`

Evaluate filesystem policy rules against a request.

### `GrantManager`

In-memory grant manager with `grant()`, `revoke()`, `listGrants()`, `checkAccess()`, and `clear()`.

## Integration

This package is used by:
- `@blindkey/openclaw-secure-backend` - OpenClaw-Secure backend adapter
- `@blindkey/aquaman-backend` - Aquaman backend adapter
- `@blindkey/fs-proxy` - Filesystem proxy grant enforcement

It can also be used standalone by any tool that needs path-based filesystem access control.
