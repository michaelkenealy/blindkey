import { createFsProxyServer } from './server.js';

const PORT = parseInt(process.env.FS_PROXY_PORT ?? '3300', 10);
const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://agentvault:agentvault_dev@localhost:5432/agentvault';

async function main() {
  const { app } = await createFsProxyServer({
    port: PORT,
    databaseUrl: DATABASE_URL,
  });

  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info(`AgentVault FS Proxy listening on port ${PORT}`);
}

main().catch((err) => {
  console.error('Fatal error starting fs-proxy:', err);
  process.exit(1);
});
