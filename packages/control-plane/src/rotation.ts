import type { RotationEvent, RotationPlan, RotationStatus, RotationTransitionResult } from './types.js';

const TRANSITIONS: Record<RotationStatus, Partial<Record<RotationEvent, RotationStatus>>> = {
  draft: {
    create_new_key: 'new_key_created',
    fail: 'failed',
  },
  new_key_created: {
    start_test: 'testing',
    rollback: 'rolled_back',
    fail: 'failed',
  },
  testing: {
    test_passed: 'deploying',
    rollback: 'rolled_back',
    fail: 'failed',
  },
  deploying: {
    healthcheck_passed: 'monitoring',
    rollback: 'rolled_back',
    fail: 'failed',
  },
  monitoring: {
    revoke_old: 'revoking_old',
    rollback: 'rolled_back',
    fail: 'failed',
  },
  revoking_old: {
    complete: 'completed',
    fail: 'failed',
  },
  completed: {},
  failed: {
    rollback: 'rolled_back',
  },
  rolled_back: {},
};

export function canTransitionRotation(status: RotationStatus, event: RotationEvent): boolean {
  return TRANSITIONS[status][event] !== undefined;
}

export function transitionRotationPlan(
  plan: RotationPlan,
  event: RotationEvent,
  now: Date = new Date(),
): RotationTransitionResult {
  const nextStatus = TRANSITIONS[plan.status][event];
  if (!nextStatus) {
    return {
      plan,
      allowed: false,
      reason: `invalid_transition:${plan.status}:${event}`,
    };
  }

  return {
    plan: {
      ...plan,
      status: nextStatus,
      completedAt: nextStatus === 'completed' || nextStatus === 'rolled_back' ? now : plan.completedAt,
    },
    allowed: true,
    reason: null,
  };
}

export function assertRotationCanRevokeOld(plan: RotationPlan): void {
  if (plan.status !== 'monitoring') {
    throw new Error(`Old credential can only be revoked after monitoring passes. Current status: ${plan.status}`);
  }
}
