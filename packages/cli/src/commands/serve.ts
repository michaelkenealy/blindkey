import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

/**
 * Start the MCP stdio server by spawning @blindkey/openclaw-skill.
 * Used when `bk serve --mcp` is invoked (or from .mcp.json).
 */
function startMcpServer(): void {
  const require = createRequire(import.meta.url);
  let skillEntry: string;

  try {
    skillEntry = require.resolve('@blindkey/openclaw-skill');
  } catch {
    console.error('\x1b[31m✕\x1b[0m Could not find @blindkey/openclaw-skill package.');
    console.error('  Make sure it is installed: npm install @blindkey/openclaw-skill');
    process.exit(1);
  }

  console.error('Starting BlindKey MCP server on stdio...');
  console.error(`Entry: ${skillEntry}`);

  const child = spawn('node', [skillEntry], {
    stdio: 'inherit',
    env: { ...process.env },
  });

  child.on('error', (err) => {
    console.error(`\x1b[31m✕\x1b[0m Failed to start MCP server: ${err.message}`);
    console.error('Run \x1b[1mnpx turbo build\x1b[0m first to compile the skill package.');
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

/**
 * Start the local HTTP API server backed by @blindkey/local-vault.
 * The dashboard connects to this in local mode.
 */
async function startHttpServer(vault: LocalVault, port: number): Promise<void> {
  // Dynamic imports — fastify is an optional dep that only loads for HTTP mode
  const { default: Fastify } = await import('fastify');
  const { default: cors } = await import('@fastify/cors');

  const app = Fastify({ logger: false });

  await app.register(cors, {
    origin: [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:3400',
      'http://127.0.0.1:3400',
    ],
    credentials: false,
  });

  // ── Health / Config ──

  app.get('/health', async () => ({ status: 'ok', mode: 'local' }));
  app.get('/api/config', async () => ({ mode: 'local', version: '0.1.0' }));

  // ── Secrets ──

  app.get('/secrets', async () => {
    const secrets = await vault.store.listSecrets([]);
    return { secrets };
  });

  app.post<{
    Body: {
      name: string;
      service: string;
      secret_type: string;
      plaintext_value: string;
      allowed_domains?: string[];
      injection_ttl_seconds?: number;
      metadata?: Record<string, unknown>;
    };
  }>('/secrets', async (request, reply) => {
    const { name, service, secret_type, plaintext_value, allowed_domains, injection_ttl_seconds, metadata } =
      request.body;

    if (!name || !secret_type || !plaintext_value) {
      return reply.code(400).send({ message: 'name, secret_type, and plaintext_value are required' });
    }

    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name,
      service: service ?? 'Custom',
      secret_type: secret_type as 'api_key' | 'oauth_token' | 'basic_auth' | 'custom_header' | 'query_param',
      plaintext_value,
      allowed_domains,
      injection_ttl_seconds,
      metadata,
    });

    vault.audit.log({ action: 'secret_created', vault_ref: vaultRef, granted: true });

    const secrets = await vault.store.listSecrets([vaultRef]);
    return reply.code(201).send(secrets[0]);
  });

  app.delete<{ Params: { id: string } }>('/secrets/:id', async (request, reply) => {
    const { id } = request.params;
    await vault.store.deleteSecret(id);
    vault.audit.log({ action: 'secret_deleted', vault_ref: id, granted: true });
    return reply.code(204).send();
  });

  app.post<{ Params: { id: string }; Body: { plaintext_value: string } }>(
    '/secrets/:id/rotate',
    async (request, reply) => {
      const { id } = request.params;
      const { plaintext_value } = request.body;

      if (!plaintext_value) {
        return reply.code(400).send({ message: 'plaintext_value is required' });
      }

      await vault.store.rotateSecret(id, plaintext_value);
      vault.audit.log({ action: 'secret_rotated', vault_ref: id, granted: true });

      const secrets = await vault.store.listSecrets([id]);
      if (secrets.length === 0) {
        return reply.code(404).send({ message: 'Secret not found' });
      }
      return reply.send(secrets[0]);
    },
  );

  // ── Filesystem Grants ──

  app.get('/grants', async () => {
    const grants = vault.grants.getAll();
    return {
      grants: grants.map((g) => ({
        id: g.id,
        path: g.path,
        permissions: g.permissions,
        recursive: g.recursive,
        requires_approval: g.requires_approval,
        created_at: g.created_at,
      })),
    };
  });

  app.post<{
    Body: {
      path: string;
      permissions: string[];
      recursive?: boolean;
      requires_approval?: boolean;
    };
  }>('/grants', async (request, reply) => {
    const { path, permissions, recursive, requires_approval } = request.body;

    if (!path || !permissions) {
      return reply.code(400).send({ message: 'path and permissions are required' });
    }

    const grant = vault.grants.add({
      path,
      permissions: permissions as ('read' | 'write' | 'create' | 'delete' | 'list')[],
      recursive: recursive !== false,
      requires_approval: requires_approval ?? false,
    });

    vault.audit.log({ action: 'grant_created', path, granted: true });

    return reply.code(201).send({
      id: grant.id,
      path: grant.path,
      permissions: grant.permissions,
      recursive: grant.recursive,
      requires_approval: grant.requires_approval,
      created_at: grant.created_at,
    });
  });

  app.delete<{ Params: { id: string } }>('/grants/:id', async (request, reply) => {
    const { id } = request.params;

    const grants = vault.grants.getAll();
    const grant = grants.find((g) => g.id === id);
    if (!grant) {
      return reply.code(404).send({ message: 'Grant not found' });
    }

    vault.grants.remove(grant.path);
    vault.audit.log({ action: 'grant_revoked', path: grant.path, granted: true });

    return reply.code(204).send();
  });

  // ── Start ──

  await app.listen({ port, host: '127.0.0.1' });

  const secretCount = (await vault.store.listSecrets([])).length;
  const grantCount = vault.grants.getAll().length;

  console.log(`\n\x1b[32m✓\x1b[0m BlindKey local server running at \x1b[1mhttp://127.0.0.1:${port}\x1b[0m`);
  console.log(`  Vault: ~/.blindkey/vault.db`);
  console.log(`  Loaded: ${secretCount} secret(s), ${grantCount} grant(s)`);
  console.log(`\n  Dashboard can now connect in local mode.`);
  console.log(`  Press Ctrl+C to stop.\n`);
}

export function registerServeCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('serve')
    .description('Start the BlindKey local HTTP API server (or MCP server with --mcp)')
    .option('-p, --port <port>', 'Port for the HTTP API server', '3002')
    .option('--mcp', 'Start the MCP stdio server instead of the HTTP API')
    .action(async (options: { port: string; mcp?: boolean }) => {
      if (options.mcp) {
        startMcpServer();
        return;
      }

      const port = parseInt(options.port, 10);
      const vault = await getVault();
      await startHttpServer(vault, port);
    });
}
