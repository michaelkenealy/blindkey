# Public And Private Boundary

BlindKey should use public source to build trust, but never publish operational secrets, customer data, private deployment details, or commercial-only infrastructure that increases attack leverage.

## Safe For The Public GitHub Repo

These should be public by default:

- Local-first vault code
- Cryptographic primitives
- Policy evaluation logic
- Filesystem gating
- Content scanner
- CLI
- Local dashboard
- MCP/OpenClaw/Codex integration code
- Provider presets that contain no credentials
- Public package manifests
- Public architecture docs
- Threat model summaries
- Security design notes
- Sanitized examples
- Sanitized test fixtures
- `.env.example` with empty placeholders only
- Public default policies

The public repo should prove the security model is inspectable. Anything needed for a solo developer to run BlindKey locally belongs in public unless it exposes private operations.

## Must Remain Private

These must never be committed to the public repo:

- `.env` and real environment files
- `VAULT_MASTER_KEY`
- `TOKEN_HASH_PEPPER`
- `AUDIT_SIGNING_KEY`
- API keys, OAuth client secrets, refresh tokens, session tokens
- Real customer names, emails, prompts, payloads, logs, or audit records
- Production database URLs
- KMS key IDs if they reveal private infrastructure
- Cloud provider credentials
- Vercel, Supabase, GitHub, Stripe, Xero, Google, or OpenAI secrets
- Private Terraform state
- Production deployment manifests with real resource names
- SOC2 evidence, customer contracts, incident reports, private runbooks
- Unsanitized research scrapes or market data in `data/`
- Local vault databases
- Private pricing experiments and enterprise deal notes

## Private Or Commercial Repos

Use private repositories or private packages for:

- Hosted BlindKey Cloud API implementation
- Hosted proxy gateway deployment code
- Billing implementation
- Abuse detection rules that should not be easy to evade
- Internal incident response automation
- Private provider partnership integrations
- Enterprise SSO/SAML implementation details if customer-specific
- Production infrastructure modules
- Customer-specific rotation adapters

Public interfaces and sanitized examples can remain public. The operational deployment and customer-specific logic should remain private.

## Publishable Examples

Examples are safe when they:

- Use fake keys such as `bk_test_example`
- Use fake company and user data
- Use local fake provider servers
- Avoid real domains unless they are documentation-only
- Avoid real tenant IDs, project IDs, or account IDs
- Include comments saying values are placeholders

## Sanitization Checklist Before Publishing

Before pushing or publishing:

1. Run secret scanning.
2. Search for common key prefixes and private key blocks.
3. Confirm `git status` does not include `.env`, `data/`, vault databases, or private deployment files.
4. Check new docs for real customer names, emails, domains, and incident details.
5. Confirm screenshots do not show keys, tokens, customer data, or private URLs.
6. Confirm examples use fake IDs and fake provider responses.
7. Run tests and build.

## Current Repo Guidance

- `packages/` is public by default except future hosted/commercial packages.
- `docs/architecture/` is public if it stays generic and sanitized.
- `policies/` is public if it contains generic defaults.
- `data/` is private by default.
- `.env` is private.
- `.env.example` is public.
- `scripts/` is private by default until each script is reviewed and sanitized.

When unsure, keep it private first and publish a sanitized version later.
