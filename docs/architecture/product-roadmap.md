# BlindKey Product Roadmap

BlindKey is the control plane for API keys, AI agents, and API usage. The local product earns developer trust by keeping agents away from raw secrets. The commercial product extends the same primitives to teams, budgets, rotations, hosted proxying, audit, and incident response.

## Product Layers

### Solo

For individual developers and OpenClaw/Codex/Claude users.

- Local encrypted vault
- `bk://` references
- Blind injection into approved domains
- Filesystem gating
- Content scanning for accidental leaks
- Local audit timeline
- CLI and local dashboard

### Teams

For small businesses managing 20-50 keys across production workflows.

- Shared workspaces
- RBAC
- Environments: development, staging, production
- Provider presets
- Guided rotation plans
- Deployment health checks
- Incident mode
- Audit export

### Control Centre

For mid-size teams governing AI agents, APIs, and spend.

- Virtual API keys
- Team, user, app, and agent budgets
- Usage metering by model/provider/agent
- Policy inheritance
- Human approvals
- Hosted proxy gateway
- Agent registry
- Security centre and kill switch

## Shared Primitives

The same security primitives power every layer:

- Vaulted provider credentials
- Blind injection
- Domain and endpoint allowlists
- Model allowlists
- Spend and request budgets
- Tamper-evident audit logs
- Rotation plans
- Incident records

## Defensibility

BlindKey should not compete as another generic password manager. The durable business is the control-plane data layer:

- Which agents use which tools
- Which keys back which apps and workflows
- Which teams spend money on which providers
- Which policies block risky calls
- Which rotations succeeded or failed
- Which incidents touched which secrets

This creates operational memory that becomes difficult to replace.

## Build Sequence

1. Harden the solo local product.
2. Add hosted workspaces and RBAC.
3. Add safe rotation workflows.
4. Add virtual keys and hosted proxying.
5. Add usage metering and budgets.
6. Add the AI Control Centre.

Each phase must preserve the local-first trust story: developers can inspect and run the critical local path without sending secrets to BlindKey Cloud.
