# Control Plane Architecture

The control plane separates real provider credentials from the capabilities issued to people, apps, and agents.

## Core Objects

- `ProviderCredential`: a real API key, OAuth token, or service credential stored in a vault.
- `VirtualKey`: a BlindKey-issued capability mapped to one provider credential and a subject.
- `Subject`: a user, team, app, agent, or service account.
- `Budget`: a hard or soft spending limit attached to a workspace, team, user, app, agent, or virtual key.
- `UsageEvent`: a metered request outcome.
- `Policy`: a restriction on domains, endpoints, methods, payloads, models, time, IP, or approval.
- `RotationPlan`: a safe workflow for replacing a provider credential.
- `Incident`: a security event with containment and resolution state.

## Request Flow

```text
Client or agent
  -> BlindKey virtual key
  -> proxy gateway
  -> resolve virtual key
  -> validate subject and provider binding
  -> enforce domain/model/policy/budget
  -> inject provider credential
  -> call provider
  -> redact response
  -> record usage and audit
  -> return response
```

## Security Rules

- Raw provider credentials are never returned to browsers, agents, or client SDKs.
- Virtual keys are revocable and scoped.
- Missing policy fails closed for hosted proxy use.
- Budget checks happen before provider calls.
- Usage and audit writes are part of the critical path, with an explicit degraded mode for provider outages only.
- Rotation must support staged cutover and rollback.

## Package Boundaries

- `@blindkey/core`: cryptography, local policy evaluation, vault contracts.
- `@blindkey/control-plane`: workspace, virtual-key, budget, usage, and governance primitives.
- `@blindkey/local-vault`: SQLite implementation for solo use.
- `@blindkey/proxy` or `services/proxy-gateway`: runtime enforcement and provider calls.
- `services/api`: hosted workspace, team, RBAC, audit, and rotation API.
- `services/worker`: background rotation, alert, usage-rollup, and incident jobs.

## UX Disclosure

The same objects should be presented differently by tier:

- Solo: secrets, grants, local usage, rotate.
- Teams: apps, environments, shared vaults, rotation plans, incidents.
- Control Centre: virtual keys, budgets, agents, policies, audit, kill switch.
