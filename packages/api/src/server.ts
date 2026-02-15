import Fastify from 'fastify';
import cors from '@fastify/cors';
import pg from 'pg';
import { createJwtMiddleware } from './middleware/auth.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerSecretsRoutes } from './routes/secrets.js';
import { registerSessionsRoutes } from './routes/sessions.js';
import { registerPoliciesRoutes } from './routes/policies.js';
import { registerAuditRoutes } from './routes/audit.js';
import { registerApprovalsRoutes } from './routes/approvals.js';

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

export interface ApiServerConfig {
  port: number;
  databaseUrl: string;
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
}

export async function createApiServer(config: ApiServerConfig) {
  const app = Fastify({
    logger: {
      level: 'info',
      transport: {
        target: 'pino-pretty',
        options: { colorize: true },
      },
    },
  });

  // Database
  const db = new Pool({ connectionString: config.databaseUrl });

  // CORS
  await app.register(cors, {
    origin: (origin, callback) => {
      callback(null, isCorsOriginAllowed(origin));
    },
    credentials: false,
  });

  // Health check (no auth)
  app.get('/health', async () => ({ status: 'ok', service: 'agentvault-api' }));

  // Public auth routes (no JWT required)
  registerAuthRoutes(app, db, {
    secret: config.jwtSecret,
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
  });

  // JWT middleware for protected routes
  const jwtMiddleware = createJwtMiddleware(config.jwtSecret, config.jwtIssuer, config.jwtAudience);
  app.addHook('onRequest', async (request, reply) => {
    const publicPaths = ['/health', '/v1/auth/register', '/v1/auth/login', '/v1/auth/verify-totp'];
    if (publicPaths.some((p) => request.url.startsWith(p))) {
      return;
    }
    if (request.url.startsWith('/v1/')) {
      await jwtMiddleware(request, reply);
    }
  });

  // Protected routes
  registerSecretsRoutes(app, db);
  registerSessionsRoutes(app, db);
  registerPoliciesRoutes(app, db);
  registerAuditRoutes(app, db);
  registerApprovalsRoutes(app, db);

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
    app.log.info('Shutting down API server...');
    await app.close();
    await db.end();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  return { app, db };
}


