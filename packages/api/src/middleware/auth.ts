import type { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { AuthenticationError } from '@blindkey/core';

export interface JwtPayload {
  sub: string;
  email: string;
  purpose?: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    userId?: string;
    userEmail?: string;
  }
}

export function createJwtMiddleware(secret: string, issuer: string, audience: string) {
  return async function jwtMiddleware(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const err = new AuthenticationError('Missing or invalid Authorization header');
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }

    const token = authHeader.slice(7);
    try {
      const payload = jwt.verify(token, secret, {
        algorithms: ['HS256'],
        issuer,
        audience,
      }) as JwtPayload;
      request.userId = payload.sub;
      request.userEmail = payload.email;
    } catch {
      const err = new AuthenticationError('Invalid or expired JWT token');
      reply.code(err.statusCode).send(err.toJSON());
      return;
    }
  };
}
