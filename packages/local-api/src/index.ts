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

import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { createLocalVault, type LocalVault } from '@blindkey/local-vault';
import type { FsPolicyRule } from '@blindkey/core';
import { getProvider } from '@blindkey/providers';

export const LOCAL_TOKEN = process.env.BLINDKEY_LOCAL_TOKEN ?? randomBytes(32).toString('base64url');
const PORT = Number(process.env.LOCAL_API_PORT ?? 3200);
const ALLOWED_PROXY_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']);
const MAX_AUDIT_LIMIT = 1000;

let vault: LocalVault;

function hostnameAllowed(hostname: string, allowedDomains: string[]): boolean {
  const actual = hostname.toLowerCase();
  return allowedDomains.some((domain) => {
    const normalized = domain.toLowerCase();
    if (normalized.startsWith('*.')) {
      return actual.endsWith(normalized.slice(1)) || actual === normalized.slice(2);
    }
    return actual === normalized;
  });
}

export async function buildApp(v: LocalVault) {
  vault = v;

  const app = Fastify({ logger: false });

  // Only allow requests from localhost origins to prevent cross-site credential theft
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) { cb(null, true); return; } // non-browser / same-origin requests
      try {
        const { hostname } = new URL(origin);
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
          cb(null, true);
        } else {
          cb(new Error('CORS: origin not allowed'), false);
        }
      } catch {
        cb(new Error('CORS: invalid origin'), false);
      }
    },
  });

  // Require Bearer token on all non-auth routes
  app.addHook('preHandler', async (request, reply) => {
    const path = request.url.split('?')[0];
    if (path === '/v1/auth/register' || path === '/v1/auth/login' || path === '/v1/auth/totp-status') return;
    const auth = request.headers.authorization;
    if (auth !== `Bearer ${LOCAL_TOKEN}`) {
      return reply.code(401).send({ message: 'Unauthorized' });
    }
  });

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

  // Rotate a secret — vault_ref in body because wildcards can't appear mid-path in find-my-way (Fastify 5)
  app.post<{ Body: { vault_ref: string; plaintext_value: string } }>(
    '/v1/secrets/rotate',
    async (request, reply) => {
      const { vault_ref: id, plaintext_value } = request.body;

      if (!id) {
        return reply.code(400).send({ message: 'vault_ref is required' });
      }

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

  // ── Audit Log ──

  app.get<{ Querystring: { limit?: string } }>('/v1/audit', async (request, reply) => {
    const limit = Math.min(Math.max(1, parseInt(request.query.limit ?? '100', 10) || 100), MAX_AUDIT_LIMIT);
    const entries = vault.audit.recent(limit);
    return reply.send({ entries });
  });

  app.get('/v1/audit/count', async (_request, reply) => {
    const count = vault.audit.count();
    return reply.send({ count });
  });

  // ── Content Policies ──

  app.get('/v1/policies', async (_request, reply) => {
    const policies = vault.policies.getAll();
    return reply.send({ policies });
  });

  app.post('/v1/policies', async (request, reply) => {
    const rule = request.body as FsPolicyRule;
    const policy = vault.policies.add(rule);
    return reply.code(201).send({ policy });
  });

  app.delete<{ Params: { id: string } }>('/v1/policies/:id', async (request, reply) => {
    const removed = vault.policies.remove(request.params.id);
    return reply.send({ success: removed });
  });

  app.patch<{ Params: { id: string }; Body: { enabled: boolean } }>(
    '/v1/policies/:id',
    async (request, reply) => {
      vault.policies.toggle(request.params.id, request.body.enabled);
      return reply.send({ success: true });
    },
  );

  // ── Proxy ──

  app.post<{
    Body: {
      vault_ref: string;
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
    };
  }>('/v1/proxy', async (request, reply) => {
    const { vault_ref: refInput, method, url, headers: extraHeaders, body: reqBody } = request.body;

    if (!refInput || !method || !url) {
      return reply.code(400).send({ message: 'vault_ref, method, and url are required' });
    }

    const upperMethod = method.toUpperCase();
    if (!ALLOWED_PROXY_METHODS.has(upperMethod)) {
      return reply.code(400).send({ message: `Method "${method}" is not allowed` });
    }

    // Validate URL protocol to prevent SSRF via file://, ftp://, etc.
    let parsedTarget: URL;
    try {
      parsedTarget = new URL(url);
    } catch {
      return reply.code(400).send({ message: 'Invalid URL' });
    }
    if (parsedTarget.protocol !== 'https:' && parsedTarget.protocol !== 'http:') {
      return reply.code(400).send({ message: 'Only http:// and https:// URLs are allowed' });
    }

    // Resolve named ref if input is not a raw vault_ref
    let vaultRef = refInput;
    let providerName: string | null = null;
    if (!refInput.startsWith('bk://')) {
      const named = await vault.store.getRef(refInput);
      if (!named) {
        return reply.code(404).send({ message: `Named ref "${refInput}" not found` });
      }
      vaultRef = named.vault_ref;
      providerName = named.provider;
    }

    const result = await vault.store.getSecret(vaultRef);
    if (!result) {
      vault.audit.log({ action: 'proxy_request', vault_ref: vaultRef, granted: false, blocking_rule: 'not_found' });
      return reply.code(404).send({ message: `Secret not found: ${vaultRef}` });
    }

    const { secret, plaintext } = result;

    // Domain check — reuse already-validated parsedTarget
    const hostname = parsedTarget.hostname;
    const provider = providerName ? getProvider(providerName) : getProvider(secret.service);

    if (provider && provider.allowedDomains.length > 0 && !hostnameAllowed(hostname, provider.allowedDomains)) {
      vault.audit.log({ action: 'proxy_request', vault_ref: vaultRef, granted: false, blocking_rule: 'provider_domain_not_allowed', detail: JSON.stringify({ hostname }) });
      return reply.code(403).send({ message: `Domain "${hostname}" is not an allowed domain for provider "${secret.service}"` });
    }

    if (secret.allowed_domains && secret.allowed_domains.length > 0 && !hostnameAllowed(hostname, secret.allowed_domains)) {
      vault.audit.log({ action: 'proxy_request', vault_ref: vaultRef, granted: false, blocking_rule: 'domain_not_allowed', detail: JSON.stringify({ hostname }) });
      return reply.code(403).send({ message: `Domain "${hostname}" not in allowed list for this secret` });
    }

    if (!provider && (!secret.allowed_domains || secret.allowed_domains.length === 0)) {
      vault.audit.log({ action: 'proxy_request', vault_ref: vaultRef, granted: false, blocking_rule: 'domain_allowlist_required', detail: JSON.stringify({ hostname }) });
      return reply.code(403).send({ message: 'Custom secrets require at least one allowed domain before proxy use' });
    }

    // Inject auth via provider adapter (if known) or fall back to secret_type heuristic
    const reqHeaders: Record<string, string> = { ...extraHeaders };
    if (provider) {
      provider.injectAuth(reqHeaders, plaintext, secret.secret_type);
    } else {
      switch (secret.secret_type) {
        case 'api_key':
        case 'oauth_token':
          reqHeaders['Authorization'] = `Bearer ${plaintext}`;
          break;
        case 'basic_auth':
          reqHeaders['Authorization'] = `Basic ${Buffer.from(plaintext).toString('base64')}`;
          break;
        case 'custom_header': {
          const headerName = (secret.metadata?.header_name as string) ?? 'X-API-Key';
          reqHeaders[headerName] = plaintext;
          break;
        }
        // query_param: auth goes into the URL (see forwardUrl below), not a header
      }
    }

    if (!reqHeaders['Content-Type'] && reqBody) {
      reqHeaders['Content-Type'] = 'application/json';
    }

    const forwardUrl = secret.secret_type === 'query_param' && !provider
      ? (() => { const u = new URL(url); u.searchParams.set((secret.metadata?.query_param_name as string) ?? 'api_key', plaintext); return u.toString(); })()
      : url;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    let response: Response;
    try {
      response = await fetch(forwardUrl, {
        method: upperMethod,
        headers: reqHeaders,
        body: reqBody !== undefined ? JSON.stringify(reqBody) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timeout);
      const isTimeout = (err as Error).name === 'AbortError';
      vault.audit.log({
        action: 'proxy_request',
        vault_ref: vaultRef,
        granted: false,
        blocking_rule: isTimeout ? 'timeout' : 'fetch_error',
      });
      if (isTimeout) {
        return reply.code(504).send({ message: 'Upstream request timed out' });
      }
      return reply.code(502).send({ message: 'Upstream request failed' });
    } finally {
      clearTimeout(timeout);
    }

    const contentType = response.headers.get('content-type') ?? '';
    let responseBody: unknown;
    if (contentType.includes('application/json')) {
      responseBody = await response.json();
    } else {
      responseBody = await response.text();
    }

    // Redact plaintext and base64-encoded forms from response
    let sanitized = false;
    let responseStr = JSON.stringify(responseBody);
    if (responseStr.includes(plaintext)) {
      responseStr = responseStr.replaceAll(plaintext, '[REDACTED]');
      sanitized = true;
    }
    const base64Plaintext = Buffer.from(plaintext).toString('base64');
    if (responseStr.includes(base64Plaintext)) {
      responseStr = responseStr.replaceAll(base64Plaintext, '[REDACTED]');
      sanitized = true;
    }
    if (sanitized) {
      responseBody = JSON.parse(responseStr);
    }

    // Estimate cost if provider supports it
    const costCents = provider ? provider.estimateCostCents(responseBody) : 0;
    const model = provider ? provider.extractModel(reqBody) : null;

    vault.audit.log({
      action: 'proxy_request',
      vault_ref: vaultRef,
      granted: true,
      detail: JSON.stringify({
        method,
        url: new URL(forwardUrl).pathname,
        status: response.status,
        ...(model ? { model } : {}),
        ...(costCents ? { cost_cents: costCents } : {}),
        ...(sanitized ? { sanitized: true } : {}),
      }),
    });

    return reply.code(response.status).send({ status: response.status, body: responseBody });
  });

  // ── Named Refs ──

  app.get('/v1/refs', async (_request, reply) => {
    const refs = await vault.store.listRefs();
    return reply.send({ refs });
  });

  app.post<{ Body: { name: string; vault_ref: string; provider: string } }>(
    '/v1/refs',
    async (request, reply) => {
      const { name, vault_ref, provider } = request.body;
      if (!name || !vault_ref || !provider) {
        return reply.code(400).send({ message: 'name, vault_ref, and provider are required' });
      }
      await vault.store.setRef(name, vault_ref, provider);
      const ref = await vault.store.getRef(name);
      return reply.code(201).send({ ref });
    },
  );

  app.delete<{ Params: { name: string } }>('/v1/refs/:name', async (request, reply) => {
    const removed = await vault.store.deleteRef(request.params.name);
    if (!removed) {
      return reply.code(404).send({ message: 'Ref not found' });
    }
    return reply.code(204).send();
  });

  // ── Config (mode detection) ──

  app.get('/v1/config', async (_request, reply) => {
    return reply.send({ mode: 'local', version: '0.1.0' });
  });

  return app;
}

async function main() {
  const v = await createLocalVault();
  const app = await buildApp(v);

  await app.listen({ port: PORT, host: '127.0.0.1' });

  const secretCount = (await v.store.listSecrets([])).length;
  const grantCount = v.grants.getAll().length;
  console.log(`BlindKey local API running at http://127.0.0.1:${PORT}`);
  console.log(`Vault: ~/.blindkey/vault.db`);
  console.log(`Loaded: ${secretCount} secret(s), ${grantCount} grant(s)`);
}

// Only start the server when this file is the entry point (not when imported by tests)
const __filename = fileURLToPath(import.meta.url);
const normArgv = (process.argv[1] ?? '').replace(/\\/g, '/');
const normSelf = __filename.replace(/\\/g, '/');
if (normArgv === normSelf || normArgv.endsWith('blindkey-local-api')) {
  main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
}
