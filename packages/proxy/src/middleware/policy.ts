import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { AgentSession, ProxyRequest, PolicySet, RateLimitRule, HumanApprovalRule } from '@blindkey/core';
import { evaluatePolicy, RateLimitError, PolicyDeniedError, ApprovalRequiredError } from '@blindkey/core';

// Environment variable to control fail-closed behavior
// Set POLICY_FAIL_OPEN=true to allow sessions without policies (NOT RECOMMENDED)
const FAIL_OPEN = process.env.POLICY_FAIL_OPEN === 'true';

export class PolicyMiddleware {
  constructor(
    private db: Pool,
    private redis: Redis
  ) {}

  async enforce(session: AgentSession, proxyRequest: ProxyRequest, approvalId?: string): Promise<{
    checked: string[];
    blocking_policy: string | null;
  }> {
    if (!session.policy_set_id) {
      // SECURITY: Fail-closed by default
      // Sessions without an assigned policy are blocked unless explicitly configured otherwise
      if (!FAIL_OPEN) {
        console.warn(
          `[SECURITY] Session ${session.id} has no policy assigned. ` +
          `Blocking request (fail-closed). Set POLICY_FAIL_OPEN=true to allow.`
        );
        throw new PolicyDeniedError(
          'no_policy',
          'Session has no policy assigned. All sessions require an explicit policy for security.'
        );
      }
      // Fail-open mode (not recommended)
      console.warn(
        `[SECURITY WARNING] Session ${session.id} has no policy but POLICY_FAIL_OPEN=true. ` +
        `Request allowed without policy enforcement.`
      );
      return { checked: ['no_policy_warn'], blocking_policy: null };
    }

    const result = await this.db.query(
      `SELECT id, user_id, name, rules, created_at FROM policy_sets WHERE id = $1`,
      [session.policy_set_id]
    );

    if (result.rows.length === 0) {
      // Policy was deleted but session still references it
      // SECURITY: Fail-closed - treat as invalid configuration
      console.error(
        `[SECURITY] Session ${session.id} references non-existent policy ${session.policy_set_id}. ` +
        `Blocking request.`
      );
      throw new PolicyDeniedError(
        'policy_not_found',
        'Referenced policy no longer exists. Session must be updated or recreated.'
      );
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

    const humanApprovalRule = rules.find((rule): rule is HumanApprovalRule => rule.type === 'human_approval');
    if (!humanApprovalRule) {
      return {
        checked: evalResult.checked,
        blocking_policy: null,
      };
    }

    if (approvalId) {
      const approval = await this.db.query(
        `SELECT id
         FROM approval_queue
         WHERE id = $1
           AND user_id = $2
           AND session_id = $3
           AND vault_ref = $4
           AND status = 'approved'
           AND expires_at > now()`,
        [approvalId, session.user_id, session.id, proxyRequest.vault_ref]
      );

      if (approval.rows.length === 0) {
        throw new PolicyDeniedError('human_approval', 'Missing, invalid, or expired approval token');
      }

      return {
        checked: [...evalResult.checked, 'human_approval'],
        blocking_policy: null,
      };
    }

    const expiresAt = new Date(Date.now() + humanApprovalRule.timeout_seconds * 1000);
    const approvalInsert = await this.db.query(
      `INSERT INTO approval_queue (user_id, session_id, vault_ref, request_payload, policy_trigger, status, expires_at)
       VALUES ($1, $2, $3, $4, 'human_approval', 'pending', $5)
       RETURNING id`,
      [
        session.user_id,
        session.id,
        proxyRequest.vault_ref,
        JSON.stringify({
          method: proxyRequest.method,
          url: proxyRequest.url,
          headers: proxyRequest.headers ?? {},
          body: proxyRequest.body ?? null,
        }),
        expiresAt,
      ]
    );

    throw new ApprovalRequiredError(approvalInsert.rows[0].id as string);
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
