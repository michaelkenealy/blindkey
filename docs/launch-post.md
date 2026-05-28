# Your AI Agent Has Your Stripe Key in Plaintext

Every MCP server tutorial tells you the same thing: paste your API key into a JSON config file. That file sits on disk, in plaintext, readable by every process on your machine.

We'd never do this in production. So why are we doing it for AI agents?

## The Problem Is Worse Than You Think

When you give an AI agent access to an API, the agent typically holds your credential in memory for the entire session. It can log it. Cache it. Accidentally write it into a file. Include it in a response. There's no access control, no audit trail, and no way to know what happened after the fact.

GitGuardian's 2026 State of Secrets Sprawl report found 29 million secrets leaked on public GitHub last year — an 81% increase driven by AI-assisted development. MCP had 30 CVEs in its first 60 days. A critical LangChain vulnerability (CVE-2025-68664) allowed secret exfiltration through prompt injection.

This isn't a theoretical risk. It's happening now, and AI agents are accelerating it.

## What Blind Credential Injection Looks Like

I built BlindKey to fix this. The core idea is simple: the agent never sees the real key.

```
Your Agent                   BlindKey                     Stripe API
    |                           |                              |
    |-- "Use bk://stripe" ----->|                              |
    |                           |-- [injects real key] ------->|
    |                           |<----- response --------------|
    |<----- response -----------|                              |
```

The agent references `bk://stripe`. BlindKey intercepts the outbound request, swaps in the real credential, and forwards it. The response comes back clean. At no point does the agent touch, see, or store the actual API key.

Every secret is AES-256-GCM encrypted at rest. Every access is logged in a tamper-proof hash chain — if someone modifies a log entry, the chain breaks and you know immediately.

## Credentials Are Only Half the Problem

Blind injection handles the authentication layer. But what about everything else the agent can do?

**What files can it read?** By default, BlindKey blocks all filesystem access. You explicitly grant per-path permissions — read, write, or both. An agent with access to `./src` cannot touch `./credentials` or `~/.ssh`.

**What if it leaks a secret?** Every write operation passes through a content scanner that checks for accidentally exposed API keys, tokens, and PII patterns. If your agent tries to write your Stripe key into a README, BlindKey catches it before it hits disk.

**Who did what, and when?** The audit log records every credential access, every file operation, every policy decision. The hash chain means the log itself is tamper-evident — you can cryptographically verify that no entries have been modified or deleted.

## How It Compares

Most tools in this space solve one piece of the problem. Password managers (1Password, Bitwarden, Keeper) now have MCP servers, but the agent still receives the credential once resolved — it enters process memory. Infrastructure tools like HashiCorp Vault are designed for server-to-server auth, not local AI development.

A few projects have started doing blind injection specifically — OneCLI (Rust HTTP gateway), nono (kernel-level sandbox with phantom tokens), AgentKeys (proxy with reference tokens). These are solid, but they're proxy-only. None of them add filesystem gating, content scanning, or a policy engine.

| Feature | 1Password MCP | OneCLI | nono | HashiCorp Vault | BlindKey |
|---------|---------------|--------|------|-----------------|----------|
| Blind injection | No | Yes | Yes | No | Yes |
| MCP integration | Yes | No | No | Yes | Yes |
| Filesystem gating | No | No | Kernel | No | Yes |
| Content scanning | No | No | No | No | Yes |
| Audit trail | No | No | Sigstore | Yes | Yes |
| Local-first | No | Yes | Yes | No | Yes |

BlindKey is the only tool that combines blind injection, MCP integration, filesystem gating, content scanning, and audit logging in one local-first package.

## Get Started in 30 Seconds

```bash
npm install -g @blindkey/cli
bk setup
```

The setup wizard initializes your encrypted vault, generates a master key, and walks you through adding your first secret.

```bash
# Add a secret with domain restriction
bk add STRIPE_KEY sk_live_xxxxx --service stripe

# Grant filesystem access
bk unlock ./src --mode read

# Check what's configured
bk doctor
```

For Claude Desktop, add this to your MCP config:

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

The agent gets 7 security-aware tools: `bk_proxy` (authenticated requests), `bk_list_secrets` (references only, never values), `bk_fs_read`, `bk_fs_write`, `bk_fs_list`, `bk_fs_info`, and `bk_list_grants`.

## Open Source, Local-First

BlindKey is MIT licensed. Everything runs locally — SQLite vault at `~/.blindkey/vault.db`, no cloud, no account required. Your secrets never leave your machine.

The code is at github.com/michaelkenealy/blindkey. The npm packages are `@blindkey/cli`, `@blindkey/core`, `@blindkey/local-vault`, `@blindkey/openclaw-skill`, and `@blindkey/openclaw-plugin`.

If you're building AI agents that call APIs, this is the security layer that should sit between your agent and your credentials. The agent is blind to the key — and that's the point.
