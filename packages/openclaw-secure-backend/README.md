# @blindkey/openclaw-secure-backend

Backend adapter that implements [OpenClaw-Secure](https://github.com/seomikewaltman/openclaw-secure)'s `SecretBackend` interface, backed by Blindkey's encrypted local vault.

## Installation

```bash
npm install @blindkey/openclaw-secure-backend
```

## Usage

### As an OpenClaw-Secure Backend

```typescript
import { BlindkeyBackend } from '@blindkey/openclaw-secure-backend';

const backend = new BlindkeyBackend();

// Check availability
if (await backend.available()) {
  // Standard SecretBackend operations
  await backend.set('my-api-key', 'sk-abc123...');
  const value = await backend.get('my-api-key');
  const keys = await backend.list();
  await backend.delete('my-api-key');
}
```

### Registering with OpenClaw-Secure

To add Blindkey as a backend option in OpenClaw-Secure's `createBackend()` factory:

```typescript
import { BlindkeyBackend } from '@blindkey/openclaw-secure-backend';

// In openclaw-secure/src/backends/index.ts:
case 'blindkey':
  return new BlindkeyBackend(options);
```

### Blindkey Extensions

Beyond the standard `SecretBackend` interface, this adapter exposes Blindkey's unique features:

```typescript
const backend = new BlindkeyBackend();
await backend.available();

// Filesystem gating (powered by @blindkey/fs-gate)
backend.grantFilesystemAccess('/home/user/project', ['read', 'write'], { recursive: true });
const access = backend.checkFilesystemAccess('read', '/home/user/project/src/app.ts');
console.log(access.granted); // true

backend.revokeFilesystemAccess('/home/user/project');

// Content scanning (powered by @blindkey/content-scanner)
const scan = backend.scanContent('api_key = "sk-live-abc123..."');
console.log(scan.allowed);    // false
console.log(scan.violations); // [{ rule: ..., match: ... }]
```

## SecretBackend Interface

| Method | Description |
|--------|-------------|
| `name` | Returns `'blindkey'` |
| `available()` | Returns `true` if vault can be initialized |
| `get(key)` | Retrieve and decrypt a secret by name |
| `set(key, value)` | Store or update a secret (AES-256-GCM encrypted) |
| `delete(key)` | Remove a secret |
| `list()` | List all secret names scoped to the configured service |

## Options

```typescript
new BlindkeyBackend({
  service: 'openclaw',  // Service scope for secrets (default: 'openclaw')
});
```

## Security

- All secrets are encrypted at rest using AES-256-GCM
- Master key derived from `VAULT_MASTER_KEY` environment variable
- SQLite WAL mode for concurrent access safety
- Content scanning prevents storing hardcoded secrets
- Filesystem gating controls what paths agents can access
