import type { FastifyRequest, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { hashToken, AuthenticationError } from '@blindkey/core';
import type { AgentSession } from '@blindkey/core';

declare module 'fastify' {
  interface FastifyRequest {
    session?: AgentSession;
  }
}

export function createAuthMiddleware(db: Pool) {
  return async function authMiddleware(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const err = new AuthenticationError('Missing or invalid Authorization header');
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }

    const token = authHeader.slice(7);
    const tokenHash = hashToken(token);

    const result = await db.query(
      `SELECT id, user_id, token_hash, allowed_secrets, policy_set_id,
              expires_at, revoked_at, metadata, created_at
       FROM agent_sessions
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      const err = new AuthenticationError();
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }

    const session = result.rows[0] as AgentSession;

    if (session.revoked_at) {
      const err = new AuthenticationError('Session has been revoked');
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }

    if (new Date(session.expires_at) < new Date()) {
      const err = new AuthenticationError('Session has expired');
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }

    request.session = session;
  };
}
