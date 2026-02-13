import { createApiServer } from './server.js';

const port = parseInt(process.env.API_PORT ?? '3200', 10);
const databaseUrl = process.env.DATABASE_URL ?? 'postgresql://agentvault:agentvault_dev@localhost:5432/agentvault';
const jwtSecret = process.env.JWT_SECRET ?? 'dev-secret-change-in-production';

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
