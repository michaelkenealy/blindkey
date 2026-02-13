import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { AgentSession, ProxyRequest, PolicySet, RateLimitRule } from '@blindkey/core';
import { evaluatePolicy, RateLimitError, PolicyDeniedError } from '@blindkey/core';

export class PolicyMiddleware {
  constructor(
    private db: Pool,
    private redis: Redis
  ) {}

  async enforce(session: AgentSession, proxyRequest: ProxyRequest): Promise<{
    checked: string[];
    blocking_policy: string | null;
  }> {
    if (!session.policy_set_id) {
      return { checked: [], blocking_policy: null };
    }

    const result = await this.db.query(
      `SELECT id, user_id, name, rules, created_at FROM policy_sets WHERE id = $1`,
      [session.policy_set_id]
    );

    if (result.rows.length === 0) {
      return { checked: [], blocking_policy: null };
    }

    const policySet = result.rows[0] as PolicySet;
    // rules is stored as JSONB, parse if needed
    const rules = typeof policySet.rules === 'string'
      ? JSON.parse(policySet.rules)
      : policySet.rules;
    policySet.rules = rules;

    // Evaluate static policies
    const evalResult = evaluatePolicy(policySet, proxyRequest);
    if (!evalResult.allowed) {
      throw new PolicyDeniedError(evalResult.blocking_policy!, evalResult.message ?? undefined);
    }

    // Enforce rate limits via Redis
    for (const rule of rules) {
      if (rule.type === 'rate_limit') {
        await this.enforceRateLimit(session.id, proxyRequest.vault_ref, rule as RateLimitRule);
      }
    }

    return {
      checked: evalResult.checked,
      blocking_policy: null,
    };
  }

  private async enforceRateLimit(
    sessionId: string,
    vaultRef: string,
    rule: RateLimitRule
  ): Promise<void> {
    const key = `ratelimit:${sessionId}:${vaultRef}`;
    const now = Date.now();
    const windowMs = rule.window_seconds * 1000;

    const pipeline = this.redis.pipeline();
    // Remove expired entries
    pipeline.zremrangebyscore(key, 0, now - windowMs);
    // Count current entries
    pipeline.zcard(key);
    // Add current request
    pipeline.zadd(key, now.toString(), `${now}:${Math.random()}`);
    // Set expiry on the key
    pipeline.expire(key, rule.window_seconds);

    const results = await pipeline.exec();
    const count = results?.[1]?.[1] as number;

    if (count >= rule.max_requests) {
      throw new RateLimitError(rule.window_seconds);
    }
  }
}
