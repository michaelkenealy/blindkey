import { createFsProxyServer } from './server.js';
import { parsePort, requireEnv } from '@blindkey/core';

const port = parsePort('FS_PROXY_PORT', 3300);
const databaseUrl = requireEnv('DATABASE_URL');

async function main() {
  const { app } = await createFsProxyServer({
    port,
    databaseUrl,
  });

  await app.listen({ port, host: '0.0.0.0' });
  app.log.info(`AgentVault FS Proxy listening on port ${port}`);
}

main().catch((err) => {
  console.error('Fatal error starting fs-proxy:', err);
  process.exit(1);
});
