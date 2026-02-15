# @blindkey/aquaman-backend

Backend adapter that implements [Aquaman](https://github.com/tech4242/aquaman)'s `CredentialStore` interface, backed by Blindkey's encrypted local vault.

## Installation

```bash
npm install @blindkey/aquaman-backend
```

## Usage

### As an Aquaman CredentialStore

```typescript
import { createBlindkeyStore } from '@blindkey/aquaman-backend';

const store = createBlindkeyStore();

// Standard CredentialStore operations
await store.set('anthropic', 'api-key', 'sk-ant-abc123...');
const value = await store.get('anthropic', 'api-key');
const creds = await store.list('anthropic');
const exists = await store.exists('anthropic', 'api-key');
await store.delete('anthropic', 'api-key');
```

### Registering with Aquaman

To add Blindkey as a backend option in Aquaman's `createCredentialStore()` factory:

```typescript
import { BlindkeyStore } from '@blindkey/aquaman-backend';

// In aquaman/packages/proxy/src/core/credentials/index.ts:
case 'blindkey':
  return new BlindkeyStore(options);
```

### Static Availability Check

```typescript
import { BlindkeyStore } from '@blindkey/aquaman-backend';

if (await BlindkeyStore.isAvailable()) {
  const store = new BlindkeyStore();
  // ...
}
```

### Blindkey Extensions

Beyond the standard `CredentialStore` interface, this adapter exposes Blindkey's unique features:

```typescript
const store = createBlindkeyStore();

// Filesystem gating (powered by @blindkey/fs-gate)
store.grantFilesystemAccess('/home/user/project', ['read', 'write'], { recursive: true });
const access = store.checkFilesystemAccess('read', '/home/user/project/src/app.ts');
console.log(access.granted); // true

store.revokeFilesystemAccess('/home/user/project');

// Content scanning (powered by @blindkey/content-scanner)
const scan = store.scanContent('api_key = "sk-live-abc123..."');
console.log(scan.allowed);    // false
console.log(scan.violations); // [{ rule: ..., match: ... }]
```

## CredentialStore Interface

| Method | Description |
|--------|-------------|
| `get(service, key)` | Retrieve and decrypt a credential |
| `set(service, key, value, metadata?)` | Store or update a credential (AES-256-GCM encrypted) |
| `delete(service, key)` | Remove a credential, returns success status |
| `list(service?)` | List credentials, optionally filtered by service |
| `exists(service, key)` | Check if a credential exists |

## Security

- All credentials are encrypted at rest using AES-256-GCM
- Master key derived from `VAULT_MASTER_KEY` environment variable
- SQLite WAL mode for concurrent access safety
- Content scanning prevents storing hardcoded secrets
- Filesystem gating controls what paths agents can access
