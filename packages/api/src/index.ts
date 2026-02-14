import { createApiServer } from './server.js';
import { parsePort, requireEnv, requireStrongSecret } from '@blindkey/core';

const port = parsePort('API_PORT', 3200);
const databaseUrl = requireEnv('DATABASE_URL');
const jwtSecret = requireStrongSecret('JWT_SECRET');

async function main() {
  const { app } = await createApiServer({ port, databaseUrl, jwtSecret });

  try {
    await app.listen({ port, host: '0.0.0.0' });
    app.log.info(`AgentVault API running on port ${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
