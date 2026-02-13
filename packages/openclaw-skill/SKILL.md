---
name: BlindKey
description: Secure credential management and filesystem gating for AI agents. Store API keys in an encrypted vault, inject them at runtime, and control which files your agent can access.
version: 0.1.0
author: BlindKey
tags:
  - security
  - vault
  - credentials
  - filesystem
---

# BlindKey

BlindKey secures your AI agent's access to sensitive credentials and filesystem paths.

## What it does

- **Encrypted Secret Storage**: API keys and tokens are stored encrypted locally — never in `.env` files
- **Blind Credential Injection**: Your agent uses `bk://` references. Real credentials are injected server-side
- **Domain Allowlists**: Each secret specifies which API domains it can be used with
- **Filesystem Gating**: Default-deny filesystem access. Only explicitly unlocked paths are visible
- **Immutable Audit Log**: Every action is logged to a local append-only database

## Setup

```bash
# Install the CLI
npm install -g @blindkey/cli

# Add your first secret
bk add STRIPE_KEY sk_live_51Hx... --domain api.stripe.com
bk add GITHUB_TOKEN ghp_xK29... --domain api.github.com

# Unlock directories your agent needs
bk unlock ~/project/src --permission read
bk unlock ~/project/output --permission write

# View your vault
bk list
bk grants
```

## Available Tools

### `bk_proxy` — Make an authenticated API request
The agent calls this tool with a vault reference. The real credential is never exposed.

Example: `bk_proxy({ vault_ref: "bk://stripe-...", method: "POST", url: "https://api.stripe.com/v1/charges", body: { amount: 2000 } })`

### `bk_fs_read` — Read a file
Only works if the path has been unlocked with `bk unlock`.

### `bk_fs_write` — Write a file
Requires write permission on the path. Content is scanned for accidentally leaked secrets.

### `bk_fs_list` — List directory contents
Only works on unlocked directories.

### `bk_fs_info` — Get file metadata
Returns size, type, and timestamps for a file or directory.

### `bk_list_secrets` — List available secrets
Shows vault references (never the actual values) the agent can use.

### `bk_list_grants` — List filesystem grants
Shows which paths are unlocked and their permission levels.

## Security Model

1. **Default deny**: Nothing is accessible unless explicitly granted
2. **Sensitive paths always blocked**: `.ssh`, `.aws`, `.env`, `.pem`, `.key`, `.git/config` — even if a parent directory is unlocked
3. **Content scanning**: Writes are scanned for patterns that look like leaked credentials or PII
4. **Size limits**: 10MB read limit, 5MB write limit per operation
5. **Audit everything**: Every operation is logged immutably to `~/.blindkey/vault.db`
