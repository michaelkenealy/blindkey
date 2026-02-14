import { createProxyServer } from './server.js';
import { parsePort, requireEnv } from '@blindkey/core';

const port = parsePort('PROXY_PORT', 3100);
const databaseUrl = requireEnv('DATABASE_URL');
const redisUrl = requireEnv('REDIS_URL');

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
