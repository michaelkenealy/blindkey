import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';

interface AuditQuerystring {
  vault_ref?: string;
  session_id?: string;
  action?: string;
  from?: string;
  to?: string;
  limit?: string;
  offset?: string;
}

export function registerAuditRoutes(app: FastifyInstance, db: Pool) {
  app.get<{ Querystring: AuditQuerystring }>('/v1/audit', async (request, reply) => {
    const userId = request.userId!;
    const { vault_ref, session_id, action, from, to, limit, offset } = request.query;

    const conditions: string[] = ['user_id = $1'];
    const params: unknown[] = [userId];
    let paramIdx = 2;

    if (vault_ref) {
      conditions.push(`vault_ref = $${paramIdx++}`);
      params.push(vault_ref);
    }
    if (session_id) {
      conditions.push(`session_id = $${paramIdx++}`);
      params.push(session_id);
    }
    if (action) {
      conditions.push(`action = $${paramIdx++}`);
      params.push(action);
    }
    if (from) {
      conditions.push(`created_at >= $${paramIdx++}`);
      params.push(new Date(from));
    }
    if (to) {
      conditions.push(`created_at <= $${paramIdx++}`);
      params.push(new Date(to));
    }

    const queryLimit = Math.min(parseInt(limit ?? '50', 10), 200);
    const queryOffset = parseInt(offset ?? '0', 10);

    const where = conditions.join(' AND ');
    const result = await db.query(
      `SELECT id, session_id, vault_ref, action, request_summary, policy_result,
              response_status, latency_ms, created_at
       FROM audit_log
       WHERE ${where}
       ORDER BY created_at DESC
       LIMIT ${queryLimit} OFFSET ${queryOffset}`,
      params
    );

    const countResult = await db.query(
      `SELECT COUNT(*) as total FROM audit_log WHERE ${where}`,
      params
    );

    return reply.send({
      entries: result.rows,
      total: parseInt(countResult.rows[0].total, 10),
      limit: queryLimit,
      offset: queryOffset,
    });
  });
}
