import { describe, expect, it } from 'vitest';
import { assertRotationCanRevokeOld, canTransitionRotation, transitionRotationPlan } from './rotation.js';
import type { RotationPlan } from './types.js';

function plan(status: RotationPlan['status'] = 'draft'): RotationPlan {
  return {
    id: 'rotation_1',
    workspaceId: 'workspace_1',
    providerCredentialId: 'credential_1',
    environment: 'production',
    status,
    createdByUserId: 'user_1',
    createdAt: new Date('2026-05-01T00:00:00Z'),
    completedAt: null,
  };
}

describe('rotation state machine', () => {
  it('supports the safe production rotation path', () => {
    const created = transitionRotationPlan(plan(), 'create_new_key');
    const testing = transitionRotationPlan(created.plan, 'start_test');
    const deploying = transitionRotationPlan(testing.plan, 'test_passed');
    const monitoring = transitionRotationPlan(deploying.plan, 'healthcheck_passed');
    const revoking = transitionRotationPlan(monitoring.plan, 'revoke_old');
    const completed = transitionRotationPlan(revoking.plan, 'complete', new Date('2026-05-03T00:00:00Z'));

    expect(completed.allowed).toBe(true);
    expect(completed.plan.status).toBe('completed');
    expect(completed.plan.completedAt?.toISOString()).toBe('2026-05-03T00:00:00.000Z');
  });

  it('blocks revocation before monitoring has passed', () => {
    expect(canTransitionRotation('deploying', 'revoke_old')).toBe(false);
    const result = transitionRotationPlan(plan('deploying'), 'revoke_old');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('invalid_transition:deploying:revoke_old');
    expect(() => assertRotationCanRevokeOld(plan('deploying'))).toThrow(/monitoring passes/);
  });

  it('allows rollback before the old key is revoked', () => {
    const result = transitionRotationPlan(plan('monitoring'), 'rollback', new Date('2026-05-03T00:00:00Z'));
    expect(result.allowed).toBe(true);
    expect(result.plan.status).toBe('rolled_back');
    expect(result.plan.completedAt?.toISOString()).toBe('2026-05-03T00:00:00.000Z');
  });
});
