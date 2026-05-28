import { describe, expect, it } from 'vitest';
import { calculateBudgetUsage, getWindowStart, wouldExceedHardBudget } from './budget.js';
import type { Budget, UsageEvent } from './types.js';

const budget: Budget = {
  id: 'budget_1',
  workspaceId: 'workspace_1',
  subjectType: 'virtual_key',
  subjectId: 'vk_1',
  window: 'month',
  amountCents: 1000,
  currency: 'USD',
  hardLimit: true,
  createdAt: new Date('2026-01-01T00:00:00Z'),
};

function usage(costCents: number, occurredAt: string, virtualKeyId = 'vk_1'): UsageEvent {
  return {
    id: `usage_${costCents}_${occurredAt}`,
    workspaceId: 'workspace_1',
    virtualKeyId,
    provider: 'openai',
    model: 'gpt-5.4-mini',
    costCents,
    status: 'allowed',
    occurredAt: new Date(occurredAt),
  };
}

describe('budget controls', () => {
  it('calculates calendar month usage for a virtual key', () => {
    const now = new Date('2026-05-20T12:00:00Z');
    const result = calculateBudgetUsage(budget, [
      usage(250, '2026-05-01T00:00:00Z'),
      usage(300, '2026-05-19T00:00:00Z'),
      usage(999, '2026-04-30T23:59:59Z'),
      usage(999, '2026-05-02T00:00:00Z', 'vk_other'),
    ], now);

    expect(result.spentCents).toBe(550);
    expect(result.remainingCents).toBe(450);
    expect(result.percentUsed).toBe(55);
  });

  it('detects hard-budget overrun before proxy execution', () => {
    const now = new Date('2026-05-20T12:00:00Z');
    const exceeded = wouldExceedHardBudget([budget], [
      usage(800, '2026-05-19T00:00:00Z'),
    ], 250, now);

    expect(exceeded?.budget.id).toBe('budget_1');
  });

  it('uses Monday as the start of a week window', () => {
    expect(getWindowStart(new Date('2026-05-03T15:00:00Z'), 'week').toISOString()).toBe('2026-04-27T00:00:00.000Z');
  });
});
