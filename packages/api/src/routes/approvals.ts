import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { NotFoundError } from '@blindkey/core';

export function registerApprovalsRoutes(app: FastifyInstance, db: Pool) {
  // List pending approvals
  app.get('/v1/approvals/pending', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query(
      `SELECT id, session_id, vault_ref, request_payload, policy_trigger,
              status, expires_at, created_at
       FROM approval_queue
       WHERE user_id = $1 AND status = 'pending' AND expires_at > now()
       ORDER BY created_at DESC`,
      [userId]
    );

    return reply.send({ approvals: result.rows });
  });

  // Approve a request
  app.post<{ Params: { id: string } }>('/v1/approvals/:id/approve', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      `UPDATE approval_queue
       SET status = 'approved', resolved_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'pending'
       RETURNING id, session_id, vault_ref, status`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Approval request');
    }

    await db.query(
      `INSERT INTO audit_log (user_id, session_id, vault_ref, action)
       VALUES ($1, $2, $3, 'approval_granted')`,
      [userId, result.rows[0].session_id, result.rows[0].vault_ref]
    );

    return reply.send(result.rows[0]);
  });

  // Deny a request
  app.post<{ Params: { id: string } }>('/v1/approvals/:id/deny', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      `UPDATE approval_queue
       SET status = 'denied', resolved_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'pending'
       RETURNING id, session_id, vault_ref, status`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Approval request');
    }

    await db.query(
      `INSERT INTO audit_log (user_id, session_id, vault_ref, action)
       VALUES ($1, $2, $3, 'approval_denied')`,
      [userId, result.rows[0].session_id, result.rows[0].vault_ref]
    );

    return reply.send(result.rows[0]);
  });
}
