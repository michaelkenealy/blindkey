import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import {
  generateSessionToken,
  hashToken,
  ValidationError,
  NotFoundError,
  type FilesystemGrantInput,
} from '@blindkey/core';

interface CreateSessionBody {
  allowed_secrets: string[];
  policy_set_id?: string;
  ttl_seconds?: number;
  filesystem_grants?: FilesystemGrantInput[];
  metadata?: {
    agent_name?: string;
    purpose?: string;
    [key: string]: unknown;
  };
}

const DEFAULT_TTL = 3600; // 1 hour
const MIN_TTL = 60; // 1 minute
const MAX_TTL = 86400; // 24 hours

export function registerSessionsRoutes(app: FastifyInstance, db: Pool) {
  // Create an agent session
  app.post<{ Body: CreateSessionBody }>('/v1/sessions', async (request, reply) => {
    const userId = request.userId!;
    const { allowed_secrets, policy_set_id, ttl_seconds, filesystem_grants, metadata } = request.body;

    if (!allowed_secrets || allowed_secrets.length === 0) {
      throw new ValidationError(`ttl_seconds must be an integer between ${MIN_TTL} and ${MAX_TTL}`);
    }

    // Verify all vault refs belong to this user
    if (allowed_secrets.length > 0) {
      const placeholders = allowed_secrets.map((_, i) => `$${i + 2}`).join(', ');
      const result = await db.query(
        `SELECT vault_ref FROM secrets WHERE user_id = $1 AND vault_ref IN (${placeholders})`,
        [userId, ...allowed_secrets]
      );
      const found = new Set(result.rows.map((r: { vault_ref: string }) => r.vault_ref));
      const missing = allowed_secrets.filter((ref) => !found.has(ref));
      if (missing.length > 0) {
        throw new ValidationError(`Secret(s) not found: ${missing.join(', ')}`);
      }
    }

    // Validate policy set if provided
    if (policy_set_id) {
      const pResult = await db.query(
        'SELECT id FROM policy_sets WHERE id = $1 AND user_id = $2',
        [policy_set_id, userId]
      );
      if (pResult.rows.length === 0) {
        throw new NotFoundError('Policy set');
      }
    }

    const requestedTtl = ttl_seconds ?? DEFAULT_TTL;
    if (!Number.isInteger(requestedTtl) || requestedTtl < MIN_TTL || requestedTtl > MAX_TTL) {
      throw new ValidationError(`ttl_seconds must be an integer between ${MIN_TTL} and ${MAX_TTL}`);
    }

    const ttl = requestedTtl;
    const sessionToken = generateSessionToken();
    const tokenHash = hashToken(sessionToken);
    const expiresAt = new Date(Date.now() + ttl * 1000);

    const result = await db.query(
      `INSERT INTO agent_sessions (user_id, token_hash, allowed_secrets, policy_set_id, expires_at, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, user_id, allowed_secrets, policy_set_id, expires_at, metadata, created_at`,
      [userId, tokenHash, allowed_secrets, policy_set_id ?? null, expiresAt, JSON.stringify(metadata ?? {})]
    );

    const session = result.rows[0];

    // Persist filesystem grants if provided
    const createdGrants = [];
    if (filesystem_grants && filesystem_grants.length > 0) {
      for (const grant of filesystem_grants) {
        if (!grant.path || !grant.permissions || grant.permissions.length === 0) {
          throw new ValidationError(`ttl_seconds must be an integer between ${MIN_TTL} and ${MAX_TTL}`);
        }
        const grantResult = await db.query(
          `INSERT INTO filesystem_grants (session_id, path, permissions, recursive, requires_approval)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, session_id, path, permissions, recursive, requires_approval, created_at`,
          [session.id, grant.path, grant.permissions, grant.recursive ?? true, grant.requires_approval ?? false]
        );
        createdGrants.push(grantResult.rows[0]);
      }
    }

    await db.query(
      `INSERT INTO audit_log (user_id, session_id, action, request_summary)
       VALUES ($1, $2, 'session_created', $3)`,
      [userId, session.id, JSON.stringify({ allowed_secrets, ttl, filesystem_grants: createdGrants.length, agent_name: metadata?.agent_name })]
    );

    return reply.code(201).send({
      session: {
        id: session.id,
        allowed_secrets: session.allowed_secrets,
        policy_set_id: session.policy_set_id,
        expires_at: session.expires_at,
        metadata: session.metadata,
        created_at: session.created_at,
        filesystem_grants: createdGrants,
      },
      session_token: sessionToken,
    });
  });

  // List active sessions
  app.get('/v1/sessions', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query(
      `SELECT id, allowed_secrets, policy_set_id, expires_at, revoked_at, metadata, created_at
       FROM agent_sessions
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    return reply.send({ sessions: result.rows });
  });

  // Revoke a session
  app.delete<{ Params: { id: string } }>('/v1/sessions/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      `UPDATE agent_sessions SET revoked_at = now()
       WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
       RETURNING id`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Session');
    }

    await db.query(
      `INSERT INTO audit_log (user_id, session_id, action)
       VALUES ($1, $2, 'session_revoked')`,
      [userId, id]
    );

    return reply.code(204).send();
  });
}


