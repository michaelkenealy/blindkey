import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { ValidationError, NotFoundError, type PolicySetCreateInput } from '@blindkey/core';

interface CreatePolicyBody {
  name: string;
  rules: unknown[];
}

export function registerPoliciesRoutes(app: FastifyInstance, db: Pool) {
  // Create a policy set
  app.post<{ Body: CreatePolicyBody }>('/v1/policies', async (request, reply) => {
    const userId = request.userId!;
    const { name, rules } = request.body;

    if (!name || !rules || !Array.isArray(rules)) {
      throw new ValidationError('name and rules (array) are required');
    }

    const result = await db.query(
      `INSERT INTO policy_sets (user_id, name, rules) VALUES ($1, $2, $3)
       RETURNING id, name, rules, created_at`,
      [userId, name, JSON.stringify(rules)]
    );

    return reply.code(201).send(result.rows[0]);
  });

  // List policy sets
  app.get('/v1/policies', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query(
      'SELECT id, name, rules, created_at FROM policy_sets WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    return reply.send({ policies: result.rows });
  });

  // Get a policy set
  app.get<{ Params: { id: string } }>('/v1/policies/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      'SELECT id, name, rules, created_at FROM policy_sets WHERE id = $1 AND user_id = $2',
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Policy set');
    }

    return reply.send(result.rows[0]);
  });

  // Delete a policy set
  app.delete<{ Params: { id: string } }>('/v1/policies/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      'DELETE FROM policy_sets WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Policy set');
    }

    return reply.code(204).send();
  });
}
