# BlindKey V2 Scope

## Blunt Take

BlindKey should not try to become the Stripe of all key management in v2.

That market already has strong incumbents: Doppler, Infisical, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, 1Password, and platform-native secret stores. A broad "replace `.env` for everyone" product is too expensive to build, too hard to distribute, and too easy to dismiss as another secrets manager.

BlindKey's wedge is narrower and stronger:

> BlindKey is the blind API access layer for AI agents and agentic apps.

The v2 job is to make it trivial for a developer or small team to let agents use APIs without ever exposing raw provider credentials, while adding usage attribution, budgets, audit, and emergency containment.

## Positioning

### One-Line

BlindKey lets AI agents call APIs without seeing your API keys.

### Expanded

BlindKey replaces raw API keys in agent runtimes with scoped virtual keys, blind injection, policy checks, usage attribution, budgets, audit logs, and one-click containment.

### Audience

Primary:

- Developers building agentic apps
- Founders using Codex, Claude, OpenClaw, or MCP-heavy workflows
- Small teams with multiple API providers and growing AI spend

Secondary:

- Security-conscious engineering teams evaluating agent deployments
- AI platform teams that need agent-level API governance

Not primary in v2:

- Generic backend teams looking for a cloud secret store
- Enterprises that need SOC2, SAML, SCIM, procurement, and custom deployment
- Non-agent workloads that only need normal environment variables

## Core Promise

In under 10 minutes, a developer should be able to:

1. Add an OpenAI, Anthropic, Stripe, or GitHub token to BlindKey.
2. Give an agent a `bk://` reference or BlindKey virtual key.
3. Let the agent make an allowed API call.
4. Prove the raw secret was never visible to the agent.
5. See who or what used the credential, against which provider, with what result.
6. Revoke the agent's access without rotating the real provider key.

That is the v2 heartbeat.

## V2 Product Shape

### 1. Solo Agent Vault

The local product remains the trust engine and free adoption path.

Must have:

- Local encrypted vault
- `bk://` references
- CLI setup that works without reading docs
- MCP/OpenClaw/Codex-oriented integration examples
- Domain allowlists
- Local audit log
- Secret redaction tests
- `.env` import

Nice, but not required:

- Beautiful local dashboard
- Advanced filesystem policy UI
- Complex provider-specific rotation

### 2. Agent Proxy SDK

This is the developer adoption surface.

Must have:

- Tiny JavaScript/TypeScript integration
- `fetch`-compatible proxy helper
- Agent-friendly tool wrapper
- First-class examples for OpenAI, Anthropic, Stripe, GitHub
- Clear failure messages when policy blocks a call
- Safe defaults: no policy means denied for hosted/proxy paths

Target feel:

```ts
import { blindFetch } from "@blindkey/sdk";

const response = await blindFetch("bk://openai-prod", {
  url: "https://api.openai.com/v1/responses",
  method: "POST",
  body: {
    model: "gpt-4.1-mini",
    input: "Hello"
  }
});
```

The exact API can change. The point is that v2 needs a stupidly obvious integration, not a big platform tour.

### 3. Control Plane Primitives

The current `@blindkey/control-plane` direction is right.

V2 should harden:

- `ProviderCredential`
- `VirtualKey`
- `Subject`: user, app, agent, service account
- Domain allowlists
- Model allowlists
- Budget checks
- Usage events
- RBAC
- Rotation state machine
- Incident state

These primitives should be boring, typed, tested, and provider-agnostic.

### 4. Hosted Team Beta

The hosted beta should be small and opinionated.

Must have:

- Workspaces
- Members and roles
- Shared credential metadata
- Virtual key issuance and revocation
- Hosted proxy gateway for selected providers
- Usage log by virtual key, provider, model, app, and agent
- Monthly/daily budget limits
- Kill switch for virtual keys

Should defer:

- SAML/SCIM
- Enterprise audit exports
- Complex approval workflows
- Full provider marketplace
- Automatic rotation across every provider
- Compliance dashboards

## The V2 Wedge

Do not lead with "manage all your API keys."

Lead with:

> Your agent can use Stripe, OpenAI, GitHub, and Anthropic without ever seeing the real keys.

The sharper wedge is agent safety plus attribution:

- Which agent used which provider?
- Which model did it call?
- What did it cost?
- Was the call allowed by policy?
- Can I kill access instantly?
- Can I prove the agent never saw the raw secret?

That is more differentiated than "store and rotate secrets."

## Non-Goals

V2 should not promise:

- Universal automatic provider rotation
- Zero downtime rotation for every API
- Replacing Vault, Doppler, Infisical, or AWS Secrets Manager
- Free unlimited hosted proxying
- Enterprise-grade compliance
- Fraud-proof API usage
- Full secret lifecycle management for every stack

Especially avoid "zero downtime rotation across every product" as a headline claim. It creates a huge proof burden and many provider-specific edge cases.

## Rotation Scope

Rotation is valuable, but dangerous to oversell.

V2 rotation should be:

- Manual or guided
- State-machine driven
- Provider-playbook based
- Health-check aware
- Rollback-capable
- Audited

V2 rotation should not claim:

- Fully automatic universal rotation
- Daily rotation by default
- One-click rotation for unsupported providers

Better promise:

> BlindKey helps you rotate safely by staging the new key, testing it, switching traffic, monitoring, and only then revoking the old key.

## Pricing And Packaging

### Open Source / Free

Free:

- Local vault
- CLI
- Local dashboard
- MCP/OpenClaw/Codex integrations
- Local audit
- Local policies
- Limited local usage summaries

This builds trust and distribution.

### Hosted Hobby

Free or very low-cost:

- Small workspace
- Low request volume
- Limited hosted proxy quota
- Limited usage history
- No advanced team governance

Do not offer unlimited free proxying. Proxy traffic has real cost, abuse risk, and latency accountability.

### Pro / Team

Paid:

- More virtual keys
- More providers
- Team members
- Budgets
- Usage history
- Hosted proxy quota
- Incident mode
- Rotation playbooks

### Enterprise Later

Paid high-touch:

- SSO/SAML/SCIM
- Custom retention
- Advanced audit export
- Private deployment
- Provider-specific adapters
- Procurement/security review

Not v2.

## MVP Provider Set

Start with a narrow, high-signal set:

- OpenAI
- Anthropic
- Stripe
- GitHub

Reasoning:

- OpenAI and Anthropic prove the agent/LLM use case.
- Stripe proves non-LLM API use without becoming generic.
- GitHub proves developer workflow integration.

Do not add ten providers until these four feel excellent.

## Success Metrics

Developer activation:

- Time from install to first blind API call
- Percent of users who import `.env`
- Percent who create first `bk://` reference
- Percent who connect an agent integration

Trust:

- Secret redaction test pass rate
- Number of raw-secret exposure paths closed
- Audit log completeness
- Policy-denied calls recorded

Commercial:

- Hosted proxy calls per active workspace
- Virtual keys per workspace
- Number of team members invited
- Budget rules created
- Incidents or revocations executed

Avoid vanity metrics like total stored secrets. BlindKey wins when credentials are safely used by agents, not merely stored.

## V2 Exit Criteria

V2 is done when:

1. A solo developer can set up BlindKey locally and make an agent call OpenAI or Anthropic without exposing a raw key.
2. A small team can create a workspace, add one shared provider credential, issue virtual keys to an app or agent, and see usage attribution.
3. A virtual key can be revoked without touching the real provider credential.
4. A budget can block a proxy call before it reaches the provider.
5. An audit trail records allowed, denied, and errored calls.
6. The product can explain its security model in one screen without hand-waving.

## The Hard Truth

The broad vision is plausible only after BlindKey earns a narrow right to exist.

The winning v2 is not "Stripe for key management."

The winning v2 is:

> The default way developers give API access to AI agents without leaking secrets.

If BlindKey owns that, the broader control-plane story becomes credible. If it starts broad, it will look like an underfunded secrets manager with agent language sprinkled on top.
