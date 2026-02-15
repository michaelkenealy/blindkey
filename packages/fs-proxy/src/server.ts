import Fastify from 'fastify';
import cors from '@fastify/cors';
import pg from 'pg';
import type { FastifyRequest, FastifyReply } from 'fastify';
import {
  hashToken,
  AuthenticationError,
  FsAccessDeniedError,
  type AgentSession,
  type FsOperation,
  type FsRequest,
} from '@blindkey/core';
import { GrantService } from './grants.js';
import { FsAuditService } from './audit.js';
import { scanRequest, hashContent } from './scanner.js';
import { executeRead, executeWrite, executeList, executeDelete, executeInfo } from './operations.js';
import { realpath, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const { Pool } = pg;

const CORS_ALLOW_ALL = process.env.CORS_ALLOW_ALL === 'true';
const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS ?? '')
  .split(',')
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);

function isCorsOriginAllowed(origin?: string): boolean {
  if (!origin) return true;
  if (CORS_ALLOW_ALL) return true;
  return CORS_ALLOWED_ORIGINS.includes(origin);
}

declare module 'fastify' {
  interface FastifyRequest {
    session?: AgentSession;
  }
}

export interface FsProxyServerConfig {
  port: number;
  databaseUrl: string;
}

export async function createFsProxyServer(config: FsProxyServerConfig) {
  const app = Fastify({
    logger: {
      level: 'info',
      transport: {
        target: 'pino-pretty',
        options: { colorize: true },
      },
    },
  });

  const db = new Pool({ connectionString: config.databaseUrl });
  const grantService = new GrantService(db);
  const auditService = new FsAuditService(db);

  await app.register(cors, {
    origin: (origin, callback) => {
      callback(null, isCorsOriginAllowed(origin));
    },
    credentials: false,
  });

  // Health check
  app.get('/health', async () => ({ status: 'ok', service: 'agentvault-fs-proxy' }));

  // Session auth middleware for /v1/ routes
  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.url.startsWith('/v1/')) return;

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
  });

  // -- Filesystem operation endpoint --

  interface FsRequestBody {
    operation: FsOperation;
    path: string;
    content?: string;
    mode?: 'overwrite' | 'append';
    encoding?: string;
    recursive?: boolean;
  }

  app.post<{ Body: FsRequestBody }>('/v1/fs', async (request, reply) => {
    const session = request.session!;
    const { operation, path, content, mode, encoding, recursive } = request.body;

    const fsRequest: FsRequest = { operation, path, content, mode, encoding, recursive };

    // 1. Check grants
    const grantResult = await grantService.checkAccess(session.id, operation, path);

    if (!grantResult.granted) {
      await auditService.log({
        session_id: session.id,
        operation,
        path,
        granted: false,
        blocking_rule: 'no_grant',
      });
      throw new FsAccessDeniedError(path, operation);
    }

    // 2. Check if grant requires approval (stub - future: queue for approval)
    if (grantResult.grant?.requires_approval) {
      await auditService.log({
        session_id: session.id,
        operation,
        path,
        granted: false,
        blocking_rule: 'requires_approval',
      });
      return reply.code(202).send({
        error: 'approval_required',
        message: `Operation "${operation}" on "${path}" requires human approval`,
      });
    }

    // 3. Run policy checks (block patterns, size limits, content scan)
    let contentSize: number | undefined;

    if (operation === 'read') {
      const canonicalPath = await realpath(resolve(path));
      const fileInfo = await stat(canonicalPath);
      contentSize = fileInfo.size;
    } else if (content !== undefined) {
      contentSize = Buffer.byteLength(content, 'utf-8');
    }

    const policyResult = scanRequest(fsRequest, [], contentSize);

    if (!policyResult.allowed) {
      await auditService.log({
        session_id: session.id,
        operation,
        path,
        granted: false,
        blocking_rule: policyResult.blocking_rule ?? undefined,
      });
      throw new FsAccessDeniedError(path, operation, policyResult.blocking_rule ?? undefined);
    }

    // 4. Execute the operation
    try {
      let result: unknown;
      let bytesTransferred: number | undefined;
      let fileHash: string | undefined;

      switch (operation) {
        case 'read': {
          const readResult = await executeRead(fsRequest);
          result = readResult;
          bytesTransferred = readResult.size;
          fileHash = hashContent(readResult.content);
          break;
        }
        case 'write':
        case 'create': {
          const writeResult = await executeWrite(fsRequest);
          result = writeResult;
          bytesTransferred = writeResult.bytes_written;
          if (content) {
            fileHash = hashContent(content);
          }
          break;
        }
        case 'list': {
          const listResult = await executeList(fsRequest);
          result = { entries: listResult };
          break;
        }
        case 'delete': {
          await executeDelete(fsRequest);
          result = { deleted: true };
          break;
        }
        case 'info': {
          const infoResult = await executeInfo(fsRequest);
          result = infoResult;
          break;
        }
      }

      // 5. Audit success
      await auditService.log({
        session_id: session.id,
        operation,
        path,
        granted: true,
        bytes_transferred: bytesTransferred,
        file_hash: fileHash,
      });

      return reply.send(result);
    } catch (err) {
      // If it's already one of our errors, rethrow
      if (err instanceof FsAccessDeniedError) throw err;

      // Log the filesystem error and return 500
      const message = (err as Error).message;
      await auditService.log({
        session_id: session.id,
        operation,
        path,
        granted: true,
        blocking_rule: `fs_error: ${message}`,
      });

      return reply.code(500).send({
        error: 'fs_operation_failed',
        message,
      });
    }
  });

  // -- List grants for current session --

  app.get('/v1/fs/grants', async (request, reply) => {
    const session = request.session!;
    const grants = await grantService.getGrantsForSession(session.id);
    return reply.send({ grants });
  });

  // Error handler
  app.setErrorHandler(async (error, request, reply) => {
    request.log.error(error);

    const err = error as Record<string, unknown>;
    if (typeof err.statusCode === 'number' && typeof err.code === 'string') {
      return reply.code(err.statusCode).send({
        error: err.code,
        message: err.message ?? 'Unknown error',
      });
    }

    return reply.code(500).send({
      error: 'internal_error',
      message: 'An unexpected error occurred',
    });
  });

  // Graceful shutdown
  const shutdown = async () => {
    app.log.info('Shutting down fs-proxy server...');
    await app.close();
    await db.end();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  return { app, db };
}

