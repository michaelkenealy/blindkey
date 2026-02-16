#!/usr/bin/env node

/**
 * BlindKey Local API Server
 *
 * Lightweight Fastify server that wraps @blindkey/local-vault in HTTP
 * endpoints so the dashboard (localhost:3400) can persist secrets and
 * filesystem grants to ~/.blindkey/vault.db without PostgreSQL.
 *
 * Auth is simplified: register/login always succeed and return a
 * static token. This is safe because the server only binds to
 * localhost.
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { createLocalVault, type LocalVault } from '@blindkey/local-vault';

const LOCAL_TOKEN = 'blindkey-local-dev';
const PORT = Number(process.env.LOCAL_API_PORT ?? 3200);

let vault: LocalVault;

async function main() {
  vault = await createLocalVault();

  const app = Fastify({ logger: false });

  await app.register(cors, { origin: true });

  // ── Auth (simplified — local single-user) ──

  app.post<{ Body: { email: string; password: string } }>(
    '/v1/auth/register',
    async (request, reply) => {
      const { email } = request.body ?? {};
      return reply.code(201).send({
        user: { id: 'local', email: email ?? 'local@blindkey', created_at: new Date().toISOString() },
        token: LOCAL_TOKEN,
      });
    },
  );

  app.post<{ Body: { email: string; password: string } }>(
    '/v1/auth/login',
    async (request, reply) => {
      const { email } = request.body ?? {};
      return reply.send({
        user: { id: 'local', email: email ?? 'local@blindkey', created_at: new Date().toISOString() },
        token: LOCAL_TOKEN,
      });
    },
  );

  app.get('/v1/auth/totp-status', async (_request, reply) => {
    return reply.send({ totp_enabled: false });
  });

  // ── Secrets ──

  app.get('/v1/secrets', async (_request, reply) => {
    const secrets = await vault.store.listSecrets([]);
    // Map to the shape the dashboard expects
    return reply.send({
      secrets: secrets.map((s) => ({
        id: s.vault_ref,
        vault_ref: s.vault_ref,
        name: s.name,
        service: s.service,
        secret_type: s.secret_type,
        created_at: s.created_at,
        rotated_at: s.rotated_at,
        expires_at: s.expires_at,
        metadata: s.metadata,
        allowed_domains: s.allowed_domains,
        injection_ttl_seconds: s.injection_ttl_seconds,
      })),
    });
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
  }>('/v1/secrets', async (request, reply) => {
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

    // Return the newly created secret metadata
    const secrets = await vault.store.listSecrets([vaultRef]);
    const created = secrets[0];
    return reply.code(201).send({
      id: created.vault_ref,
      vault_ref: created.vault_ref,
      name: created.name,
      service: created.service,
      secret_type: created.secret_type,
      created_at: created.created_at,
      rotated_at: created.rotated_at,
      expires_at: created.expires_at,
      metadata: created.metadata,
      allowed_domains: created.allowed_domains,
      injection_ttl_seconds: created.injection_ttl_seconds,
    });
  });

  app.delete<{ Params: { '*': string } }>('/v1/secrets/*', async (request, reply) => {
    const id = decodeURIComponent(request.params['*']);
    await vault.store.deleteSecret(id);
    vault.audit.log({ action: 'secret_deleted', vault_ref: id, granted: true });
    return reply.code(204).send();
  });

  app.post<{ Params: { '*': string }; Body: { plaintext_value: string } }>(
    '/v1/secrets/*/rotate',
    async (request, reply) => {
      const id = decodeURIComponent(request.params['*']);
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

      const s = secrets[0];
      return reply.send({
        id: s.vault_ref,
        vault_ref: s.vault_ref,
        name: s.name,
        service: s.service,
        secret_type: s.secret_type,
        created_at: s.created_at,
        rotated_at: s.rotated_at,
        expires_at: s.expires_at,
        metadata: s.metadata,
        allowed_domains: s.allowed_domains,
        injection_ttl_seconds: s.injection_ttl_seconds,
      });
    },
  );

  // ── Filesystem Grants ──

  app.get('/v1/grants', async (_request, reply) => {
    const grants = vault.grants.getAll();
    return reply.send({
      grants: grants.map((g) => ({
        id: g.id,
        path: g.path,
        permissions: g.permissions,
        recursive: g.recursive,
        requires_approval: g.requires_approval,
        created_at: g.created_at,
      })),
    });
  });

  app.post<{
    Body: {
      path: string;
      permissions: string[];
      recursive?: boolean;
      requires_approval?: boolean;
    };
  }>('/v1/grants', async (request, reply) => {
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

  app.delete<{ Params: { id: string } }>('/v1/grants/:id', async (request, reply) => {
    const { id } = request.params;

    // Find the grant by ID to get its path, then remove by path
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

  await app.listen({ port: PORT, host: '127.0.0.1' });

  const secretCount = (await vault.store.listSecrets([])).length;
  const grantCount = vault.grants.getAll().length;
  console.log(`BlindKey local API running at http://127.0.0.1:${PORT}`);
  console.log(`Vault: ~/.blindkey/vault.db`);
  console.log(`Loaded: ${secretCount} secret(s), ${grantCount} grant(s)`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
