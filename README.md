# BlindKey

**Secure credential management for AI agents.** BlindKey keeps your API keys encrypted and injects them only when needed, ensuring AI agents never see your actual secrets.

## Why BlindKey?

When AI agents make API calls on your behalf, they typically need direct access to your credentials. This creates security risks:

- Credentials could be logged, cached, or leaked
- Agents could use credentials for unintended purposes
- No audit trail of credential usage

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
- **Audit Logging** - Tamper-evident hash chain of all credential access
- **Policy Engine** - Rate limits, regex blocklists, time-based access
- **MCP Integration** - Works with Claude and other MCP-compatible AI assistants

## Quick Start

### Installation

```bash
# Install globally
npm install -g @blindkey/cli

# Or use npx (no install required)
npx @blindkey/cli init
```

### Interactive Setup

```bash
# Run the setup wizard
bk init

# The wizard will:
# 1. Create your encrypted vault at ~/.blindkey
# 2. Generate a master key (BACK THIS UP!)
# 3. Help you add your first secret
# 4. Optionally configure MCP for Claude
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
├── cli/              # Command-line interface (bk command)
├── core/             # Cryptographic primitives & types
├── local-vault/      # SQLite-based encrypted storage
├── local-api/        # Local HTTP server bridging dashboard → vault.db
├── proxy/            # HTTP proxy with credential injection
├── dashboard/        # React admin UI
├── openclaw-plugin/  # OpenClaw agent plugin
└── openclaw-skill/   # MCP server for Claude integration
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

The plugin registers two tools:

| Tool | Description |
|------|-------------|
| `bk_proxy` | Make an authenticated API request (credential injected server-side) |
| `bk_list_secrets` | List available secret references (values never shown) |

### Usage with OpenClaw

```
You: "Call the Stripe API to list charges using bk://stripe-abc123"
Agent: (calls bk_proxy → credential injected → response returned)
```

## Dashboard (Local Mode)

The dashboard can manage secrets and filesystem grants stored in `~/.blindkey/vault.db` without requiring PostgreSQL.

### Start the local API server + dashboard

```bash
# Terminal 1: Start the local API server (wraps ~/.blindkey/vault.db)
cd packages/local-api
npm run dev    # runs on http://localhost:3200

# Terminal 2: Start the dashboard
cd packages/dashboard
npm run dev    # opens http://localhost:3400
```

The dashboard proxies `/v1` requests to `localhost:3200`. Secrets and filesystem grants are persisted to SQLite and will survive page refreshes.

## MCP Configuration (Claude Desktop)

```bash
# Generate MCP config during setup
bk init --mcp

# Or manually configure in Claude Desktop settings:
```

```json
{
  "mcpServers": {
    "blindkey": {
      "command": "npx",
      "args": ["@blindkey/cli", "serve"]
    }
  }
}
```

## Commands

| Command | Description |
|---------|-------------|
| `bk init` | Interactive setup wizard |
| `bk add <name> <value>` | Store a new secret |
| `bk list` | List all stored secrets |
| `bk get <name>` | Retrieve a secret (for debugging) |
| `bk rm <name>` | Delete a secret |
| `bk unlock <path>` | Grant filesystem access |
| `bk grants` | List active filesystem grants |
| `bk audit` | View audit log |
| `bk doctor` | Check installation health |
| `bk serve` | Start MCP server |

## Security Model

### Encryption
- All secrets encrypted with AES-256-GCM
- Master key derived from secure random bytes
- Each secret has unique IV (initialization vector)

### Access Control
- **Domain allowlisting**: Secrets only sent to specified domains
- **Filesystem gating**: Default-deny with explicit grants
- **Policy engine**: Rate limits, time windows, regex blocklists

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

## Requirements

- Node.js 18+
- npm 8+

**Note:** The `better-sqlite3` dependency requires a C++ compiler for native builds. On most systems this works automatically, but you may need:

- **Windows**: Visual Studio Build Tools
- **macOS**: Xcode Command Line Tools (`xcode-select --install`)
- **Linux**: `build-essential` package

## License

MIT - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.

## Security

Found a vulnerability? Please report it privately to security@blindkey.dev or via GitHub Security Advisories.
