# BlindKey

**Secure credential management for AI agents.** BlindKey keeps your API keys encrypted and injects them only when needed, ensuring AI agents never see your actual secrets.

## Why BlindKey?

When AI agents make API calls on your behalf, they typically need direct access to your credentials. This creates security risks:

- Credentials could be logged, cached, or leaked
- Agents could use credentials for unintended purposes
- No audit trail of credential usage

### How BlindKey Compares

Other tools focus on credential injection. BlindKey goes further:

| Feature | 1Password | Aquaman | OpenClaw-Secure | **BlindKey** |
|---------|-----------|---------|-----------------|--------------|
| Credential injection | Yes | Yes | Yes | **Yes** |
| **Filesystem gating** | No | No | No | **Yes** |
| **Content scanning** | No | No | No | **Yes** |
| **Visual dashboard** | No | No | No | **Yes** |
| **Policy engine** | No | No | No | **Yes** |

BlindKey answers: *"What can the AI agent access?"* not just *"How does it authenticate?"*

### How It Works

BlindKey solves this with **blind credential injection**:

```
Your Code                    BlindKey                     External API
    |                           |                              |
    |-- "Use bk://stripe" ----->|                              |
    |                           |-- [injects real key] ------->|
    |                           |<----- response --------------|
    |<----- response -----------|                              |
```

The AI agent only sees `bk://stripe` - never the actual API key.

## Features

- **AES-256-GCM Encryption** - Military-grade encryption for all stored secrets
- **Blind Injection** - Agents reference `bk://ref` tokens, never real credentials
- **Domain Allowlisting** - Each secret specifies which domains can receive it
- **Filesystem Gating** - Default-deny access to files and directories
- **Content Scanning** - Writes are scanned for accidentally leaked secrets and PII
- **Audit Logging** - Tamper-evident hash chain of all credential access
- **Policy Engine** - Regex blocklists, content scanning rules
- **MCP Integration** - Works with Claude and other MCP-compatible AI assistants
- **OpenClaw Plugin** - Native plugin for OpenClaw-powered agents

## Quick Start

### Requirements

- Node.js 18+
- npm 8+

> **Windows:** `better-sqlite3` requires Visual Studio Build Tools for native compilation.
> **macOS:** Xcode Command Line Tools (`xcode-select --install`).
> **Linux:** `build-essential` package.

### Installation

```bash
# Install globally
npm install -g @blindkey/cli

# Or use npx (no install required)
npx @blindkey/cli setup
```

### Interactive Setup

```bash
# Run the guided setup wizard (recommended)
bk setup

# Or use the quick init
bk init

# The wizard will:
# 1. Let you choose Local or Docker mode
# 2. Create your encrypted vault at ~/.blindkey
# 3. Generate a master key (BACK THIS UP!)
# 4. Help you add your first secret
```

### Add Secrets

```bash
# Add an API key
bk add OPENAI_API_KEY sk-proj-xxxxx --domain api.openai.com

# Add with service preset (auto-configures domain)
bk add STRIPE_KEY sk_live_xxxxx --service stripe

# List all secrets
bk list
```

### Use with AI Agents

Reference secrets using `bk://` URIs:

```javascript
// In your agent code
const response = await fetch('https://api.openai.com/v1/chat/completions', {
  headers: {
    'Authorization': 'Bearer bk://OPENAI_API_KEY'
  }
});

// BlindKey proxy intercepts and injects the real key
```

### Filesystem Access

```bash
# Grant read access to a directory
bk unlock ./src --mode read

# Grant read-write access
bk unlock ./data --mode write

# Check current grants
bk grants
```

## Architecture

```
packages/
├── cli/               # Command-line interface (bk command)
├── core/              # Cryptographic primitives & types
├── local-vault/       # SQLite-based encrypted storage
├── local-api/         # Local HTTP server bridging dashboard to vault.db
├── openclaw-plugin/   # OpenClaw agent plugin (tool registration)
├── openclaw-skill/    # MCP server for Claude integration
├── dashboard/         # React admin UI
├── fs-gate/           # Filesystem access control library
└── content-scanner/   # Secret & PII detection in content
```

## OpenClaw Plugin

BlindKey ships an OpenClaw plugin so your agents can use `bk://` credential references automatically.

### Install

```bash
npm install @blindkey/openclaw-plugin
```

Add to your OpenClaw config:

```json
{
  "plugins": ["@blindkey/openclaw-plugin"]
}
```

The plugin registers these tools:

| Tool | Description |
|------|-------------|
| `bk_proxy` | Make an authenticated API request (credential injected server-side) |
| `bk_list_secrets` | List available secret references (values never shown) |
| `bk_fs_read` | Read a file (requires explicit grant, sensitive paths blocked) |
| `bk_fs_write` | Write a file (content scanned for leaked secrets) |
| `bk_fs_list` | List directory contents (only unlocked directories) |
| `bk_fs_info` | Get file/directory metadata |
| `bk_list_grants` | Show unlocked paths and permissions |

### Usage with OpenClaw

```
You: "Call the Stripe API to list charges using bk://stripe-abc123"
Agent: (calls bk_proxy -> credential injected -> response returned)
```

## Dashboard

The dashboard provides a visual interface for managing secrets, filesystem grants, policies, and the audit log.

### Start the dashboard (local mode)

```bash
# Terminal 1: Start the local API server
bk serve                                    # runs on http://127.0.0.1:3200

# Terminal 2: Start the dashboard
npm run dev -w @blindkey/dashboard          # opens http://localhost:3400
```

The dashboard auto-detects local mode and skips the login screen.

### Dashboard features

- **Secrets management** - Add, rotate, delete API keys with domain restrictions
- **Filesystem gating** - Visual tree view, quick unlock for common paths, one-click revoke
- **Security policies** - Manage content scanning rules, add custom regex patterns, toggle on/off
- **Audit timeline** - Color-coded timeline of all agent actions, filter by type, export CSV/JSON

All data persists to `~/.blindkey/vault.db` (SQLite).

## MCP Configuration (Claude Desktop)

BlindKey integrates with Claude Desktop via the Model Context Protocol (MCP).

```bash
# Generate MCP config during init
bk init --mcp
```

Or manually add to your Claude Desktop settings:

```json
{
  "mcpServers": {
    "blindkey": {
      "command": "npx",
      "args": ["@blindkey/cli", "serve", "--mcp"]
    }
  }
}
```

If you've installed BlindKey globally (`npm install -g @blindkey/cli`):

```json
{
  "mcpServers": {
    "blindkey": {
      "command": "bk",
      "args": ["serve", "--mcp"]
    }
  }
}
```

## Commands

| Command | Description |
|---------|-------------|
| `bk setup` | Guided setup wizard (choose Local or Docker mode) |
| `bk init` | Quick vault initialization |
| `bk add <name> <value>` | Store a new secret |
| `bk list` | List all stored secrets |
| `bk rm <name>` | Delete a secret |
| `bk rotate <name>` | Rotate a secret's value |
| `bk unlock <path>` | Grant filesystem access |
| `bk lock <path>` | Revoke filesystem access |
| `bk grants` | List active filesystem grants |
| `bk policy` | Manage content policies |
| `bk audit` | View audit log |
| `bk serve` | Start local API server (port 3200) |
| `bk serve --mcp` | Start MCP server for Claude |
| `bk doctor` | Check installation health |
| `bk migrate` | Run database migrations |

## Security Model

### Encryption
- All secrets encrypted with AES-256-GCM
- Master key derived from secure random bytes
- Each secret has unique IV (initialization vector)

### Access Control
- **Domain allowlisting**: Secrets only sent to specified domains
- **Filesystem gating**: Default-deny with explicit grants
- **Content scanning**: Writes checked for leaked credentials and PII
- **Policy engine**: Regex blocklists, content scanning rules

### Audit Trail
- All access logged with cryptographic hash chain
- Tamper-evident: any modification breaks the chain
- Optional HMAC signatures for external verification

### Fail-Closed Design
- No policy = blocked (not allowed)
- Missing grants = denied
- Invalid signatures = rejected

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BLINDKEY_DIR` | Vault storage location | `~/.blindkey` |
| `VAULT_MASTER_KEY` | Master encryption key | Auto-generated |
| `LOCAL_API_PORT` | Local API server port | `3200` |
| `POLICY_FAIL_OPEN` | Allow no-policy sessions | `false` |

## Development

```bash
# Clone the repo
git clone https://github.com/michaelkenealy/blindkey.git
cd blindkey

# Install dependencies
npm install

# Build all packages
npm run build

# Run the CLI locally
node packages/cli/dist/index.js --help
```

## License

MIT - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.

## Security

Found a vulnerability? Please report it privately to security@blindkey.dev or via GitHub Security Advisories.
