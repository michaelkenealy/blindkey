import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { ValidationError } from '@blindkey/core';

interface AuditQuerystring {
  vault_ref?: string;
  session_id?: string;
  action?: string;
  from?: string;
  to?: string;
  limit?: string;
  offset?: string;
}

function parseNonNegativeInt(value: string | undefined, fallback: number, field: string): number {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value)) {
    throw new ValidationError(`${field} must be a non-negative integer`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new ValidationError(`${field} must be a non-negative integer`);
  }
  return parsed;
}

function parseIsoDate(value: string | undefined, field: string): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new ValidationError(`${field} must be a valid date`);
  }
  return date;
}

export function registerAuditRoutes(app: FastifyInstance, db: Pool) {
  app.get<{ Querystring: AuditQuerystring }>('/v1/audit', async (request, reply) => {
    const userId = request.userId!;
    const { vault_ref, session_id, action, from, to, limit, offset } = request.query;

    const fromDate = parseIsoDate(from, 'from');
    const toDate = parseIsoDate(to, 'to');
    if (fromDate && toDate && fromDate > toDate) {
      throw new ValidationError('from must be earlier than or equal to to');
    }

    const queryLimit = Math.min(parseNonNegativeInt(limit, 50, 'limit'), 200);
    const queryOffset = parseNonNegativeInt(offset, 0, 'offset');

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
    if (fromDate) {
      conditions.push(`created_at >= $${paramIdx++}`);
      params.push(fromDate);
    }
    if (toDate) {
      conditions.push(`created_at <= $${paramIdx++}`);
      params.push(toDate);
    }

    const where = conditions.join(' AND ');

    const limitParam = paramIdx++;
    const offsetParam = paramIdx++;
    const result = await db.query(
      `SELECT id, session_id, vault_ref, action, request_summary, policy_result,
              response_status, latency_ms, created_at
       FROM audit_log
       WHERE ${where}
       ORDER BY created_at DESC
       LIMIT $${limitParam} OFFSET $${offsetParam}`,
      [...params, queryLimit, queryOffset]
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
