import { createProxyServer } from './server.js';

const port = parseInt(process.env.PROXY_PORT ?? '3100', 10);
const databaseUrl = process.env.DATABASE_URL ?? 'postgresql://agentvault:agentvault_dev@localhost:5432/agentvault';
const redisUrl = process.env.REDIS_URL ?? 'redis://localhost:6379';

async function main() {
  const { app } = await createProxyServer({ port, databaseUrl, redisUrl });

  try {
    await app.listen({ port, host: '0.0.0.0' });
    app.log.info(`AgentVault Proxy running on port ${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
