# Hosted Cloud API Scaffold

This document defines the hosted/private service shape without committing production infrastructure or secrets to the public repo.

## Public Contract

The public repo can include:

- Route contracts
- Request and response types
- Local fake-provider test fixtures
- OpenAPI examples with fake IDs
- Security model documentation
- SDK interfaces

The public repo should not include production deployment wiring, real resource names, billing provider secrets, or abuse detection internals.

## Private Implementation

The private/commercial implementation should include:

- Authentication provider configuration
- Workspace database migrations
- KMS/envelope encryption wiring
- Billing integration
- Hosted proxy gateway
- Rate-limit storage
- Abuse detection rules
- Production deployment manifests
- Internal alerting and incident automation

## Initial Service Modules

```text
services/api/
  src/
    auth/
    workspaces/
    members/
    secrets/
    virtual-keys/
    budgets/
    usage/
    rotations/
    incidents/
    audit/

services/proxy-gateway/
  src/
    resolve-virtual-key/
    enforce-policy/
    inject-credential/
    providers/
    meter-usage/
    redact-response/

services/worker/
  src/
    rotation-jobs/
    usage-rollups/
    budget-alerts/
    incident-digests/
```

## Route Families

```text
POST   /v1/workspaces
GET    /v1/workspaces/:id
POST   /v1/workspaces/:id/invites

GET    /v1/secrets
POST   /v1/secrets
POST   /v1/secrets/:id/rotate
DELETE /v1/secrets/:id

POST   /v1/virtual-keys
POST   /v1/virtual-keys/:id/revoke

POST   /v1/budgets
GET    /v1/usage

POST   /v1/rotations
POST   /v1/rotations/:id/events

POST   /v1/incidents
POST   /v1/incidents/:id/contain
POST   /v1/incidents/:id/resolve
```

## Security Invariants

- Raw provider credentials never return from hosted APIs.
- Virtual keys are scoped and revocable.
- Workspace isolation is enforced before every database read.
- Service-role or KMS credentials are not reachable from request handlers except through narrow vault interfaces.
- Budget checks happen before provider calls.
- Audit and usage events are written for both allowed and denied proxy calls.
- Production deploys fail closed when policy or credential lookup fails.

## Latency Strategy

- Keep virtual-key metadata in a short-lived hot cache.
- Cache provider credential metadata, never plaintext secret values.
- Decrypt only at the final injection step.
- Use asynchronous rollups for analytics, but synchronous event writes for request accountability.
- Keep policy evaluation in-process and deterministic.
