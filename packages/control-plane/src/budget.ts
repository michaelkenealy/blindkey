import type { Budget, BudgetUsageSnapshot, UsageEvent } from './types.js';

export function getWindowStart(now: Date, window: Budget['window']): Date {
  const start = new Date(now);
  start.setUTCMilliseconds(0);
  start.setUTCSeconds(0);
  start.setUTCMinutes(0);

  switch (window) {
    case 'day':
      start.setUTCHours(0);
      return start;
    case 'week': {
      start.setUTCHours(0);
      const day = start.getUTCDay();
      const diff = day === 0 ? 6 : day - 1;
      start.setUTCDate(start.getUTCDate() - diff);
      return start;
    }
    case 'month':
      start.setUTCHours(0);
      start.setUTCDate(1);
      return start;
    case 'quarter': {
      start.setUTCHours(0);
      start.setUTCDate(1);
      const quarterStartMonth = Math.floor(start.getUTCMonth() / 3) * 3;
      start.setUTCMonth(quarterStartMonth);
      return start;
    }
    case 'year':
      start.setUTCHours(0);
      start.setUTCMonth(0, 1);
      return start;
  }
}

export function calculateBudgetUsage(
  budget: Budget,
  usageEvents: UsageEvent[],
  now: Date = new Date(),
): BudgetUsageSnapshot {
  const windowStart = getWindowStart(now, budget.window);
  const spentCents = usageEvents
    .filter((event) => event.workspaceId === budget.workspaceId)
    .filter((event) => event.status === 'allowed')
    .filter((event) => event.occurredAt >= windowStart && event.occurredAt <= now)
    .filter((event) => {
      switch (budget.subjectType) {
        case 'workspace':
          return true;
        case 'virtual_key':
          return event.virtualKeyId === budget.subjectId;
        default:
          return event.metadata?.[`${budget.subjectType}Id`] === budget.subjectId;
      }
    })
    .reduce((sum, event) => sum + event.costCents, 0);

  const remainingCents = Math.max(0, budget.amountCents - spentCents);
  const percentUsed = budget.amountCents === 0
    ? 100
    : Math.min(100, Math.round((spentCents / budget.amountCents) * 10000) / 100);

  return { budget, spentCents, remainingCents, percentUsed };
}

export function wouldExceedHardBudget(
  budgets: Budget[],
  usageEvents: UsageEvent[],
  projectedCostCents: number,
  now: Date = new Date(),
): BudgetUsageSnapshot | null {
  for (const budget of budgets) {
    if (!budget.hardLimit) continue;
    const snapshot = calculateBudgetUsage(budget, usageEvents, now);
    if (snapshot.spentCents + projectedCostCents > budget.amountCents) {
      return snapshot;
    }
  }
  return null;
}
