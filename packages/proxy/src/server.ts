import Fastify from 'fastify';
import cors from '@fastify/cors';
import pg from 'pg';
import { Redis as IORedis } from 'ioredis';
import { createAuthMiddleware } from './middleware/auth.js';
import { registerProxyRoutes } from './routes/proxy.js';
import { registerSecretsRoutes } from './routes/secrets.js';
import { PostgresVaultBackend } from './services/postgres-vault-backend.js';
import { CachingVaultService } from './services/caching-vault-service.js';

const { Pool } = pg;

export interface ProxyServerConfig {
  port: number;
  databaseUrl: string;
  redisUrl: string;
}

export async function createProxyServer(config: ProxyServerConfig) {
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

  // Redis
  const redis = new IORedis(config.redisUrl);

  // CORS
  await app.register(cors, { origin: true });

  // Health check (no auth required)
  app.get('/health', async () => ({ status: 'ok', service: 'agentvault-proxy' }));

  // Auth middleware for all /v1/ routes
  const authMiddleware = createAuthMiddleware(db);
  app.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/v1/')) {
      await authMiddleware(request, reply);
    }
  });

  // Vault backend: PostgreSQL → in-memory TTL cache
  const postgresBackend = new PostgresVaultBackend(db);
  const vaultBackend = new CachingVaultService(postgresBackend);

  // Register routes
  registerProxyRoutes(app, db, redis, vaultBackend);
  registerSecretsRoutes(app, vaultBackend);

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
    app.log.info('Shutting down proxy server...');
    await app.close();
    await db.end();
    redis.disconnect();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  return { app, db, redis };
}
