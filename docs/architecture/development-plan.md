# Development And Testing Plan

This plan grows BlindKey from a trusted local developer tool into a recurring-revenue control centre for teams and AI resource governance. Each phase should ship behind stable package boundaries and tests.

## Phase 1: Solo Trust Layer

Goal: make the free local product excellent for developers and agentic tools.

Build:

- Local vault hardening
- CLI polish
- OpenClaw, MCP, Codex, and Claude setup guides
- Provider presets
- `.env` import
- Content scanning on writes
- Filesystem grants
- Local audit timeline

Test:

- Crypto round trips
- Tamper detection
- Wrong master key failure
- Domain allowlist enforcement
- Secret redaction in responses
- `.env` import never logs values
- CLI integration tests with a temp vault
- Filesystem deny-by-default tests

Exit criteria:

- A solo developer can store keys, let an agent use them, and verify raw values never appear in agent output.

## Phase 2: Control Plane Primitives

Goal: establish shared primitives for virtual keys, budgets, usage, rotation, and incidents.

Build:

- `@blindkey/control-plane`
- Workspace, team, app, agent, provider credential, virtual key types
- Budget windows and hard-limit checks
- Proxy access evaluation
- Rotation state machine
- Incident model

Test:

- Budget window calculations use UTC
- Hard budget blocks before provider call
- Domain/model mismatch blocks
- Revoked virtual key blocks
- Invalid rotation transitions fail closed
- Old key cannot be revoked before monitoring passes

Exit criteria:

- Hosted proxy and team APIs can depend on typed, tested governance primitives.

## Phase 3: Hosted Team Vault

Goal: support small businesses with shared keys and safe operations.

Build:

- Hosted API service
- Workspace auth
- RBAC
- Shared secrets metadata
- Environment model
- Cloud vault backend
- Audit API
- Invite and offboarding flows

Test:

- Workspace isolation
- RBAC matrix
- Admin can rotate, viewer cannot
- User from workspace A cannot access workspace B metadata
- Cloud vault encryption and decryption
- Migration tests
- API contract tests

Exit criteria:

- A small team can store and share 20-50 keys without revealing raw values to normal users.

## Phase 4: Safe Rotation

Goal: rotate production keys without breaking live workflows.

Build:

- Rotation plan UI
- Provider-specific rotation playbooks
- Vercel env integration
- GitHub Actions secrets integration
- Health checks
- Staged cutover
- Rollback
- Incident mode

Test:

- Rotation state-machine tests
- Failed health check blocks revocation
- Rollback restores prior key version
- Provider adapter mocks
- Deployment integration mocks
- Incident report export

Exit criteria:

- A business can rotate a production key with guided checks and a rollback path.

## Phase 5: Hosted Proxy And Virtual Keys

Goal: make BlindKey an API access router with blind injection.

Build:

- Proxy gateway
- Virtual key issuance and revocation
- Provider adapters
- Credential injection
- Policy enforcement
- Usage event writing
- Response redaction
- Low-latency cache for virtual-key metadata

Test:

- Raw provider credential never leaves proxy
- Revoked virtual key fails
- Wrong domain/model/endpoint fails
- Budget exceeded fails
- Provider errors are attributed and audited
- Usage is written once per request
- Load tests for p95 latency
- SSRF and redirect tests

Exit criteria:

- Apps and agents can use BlindKey virtual keys instead of real provider keys.

## Phase 6: Usage Metering And Budgets

Goal: make API spend allocatable by team, person, app, and agent.

Build:

- Usage ledger
- Cost estimation per provider/model
- Daily/monthly budget windows
- Team, user, app, agent attribution
- Alerts
- Usage dashboards
- Anomaly detection

Test:

- Provider cost calculations
- Concurrent budget race tests
- Alert deduping
- Rollup accuracy
- Time-window boundaries

Exit criteria:

- An owner can assign a monthly AI budget and see exactly where spend went.

## Phase 7: AI Control Centre

Goal: serve the AI architects who govern agents, APIs, tools, and budgets.

Build:

- Agent registry
- Tool grants
- Policy inheritance
- Approval workflows
- Kill switch
- Security centre
- Compliance exports

Test:

- Most restrictive policy wins
- Approval timeout denies by default
- Kill switch revokes active virtual keys
- Agent cannot exceed grants
- Audit export integrity
- End-to-end dashboard tests

Exit criteria:

- A mid-size company can manage agents, secrets, budgets, and security from one control centre.

## Always-On Security Work

- Threat model updates before major releases
- Dependency review
- Secret scanning in CI
- Red-team tests for prompt and tool misuse
- Audit log integrity checks
- Incident drills
- Secure defaults for every new feature

## Performance Targets

- Local secret lookup: under 10 ms p95
- Hosted virtual-key resolution from hot cache: under 5 ms p95
- Proxy policy evaluation: under 2 ms p95
- Provider proxy overhead excluding upstream latency: under 25 ms p95
- Audit/usage write path: durable with explicit degraded mode, never silent loss
