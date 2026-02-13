import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import {
  AuthorizationError,
  NotFoundError,
  hashBody,
  type ProxyRequest,
  type BlindKeyError,
  type VaultBackend,
} from '@blindkey/core';
import { AuditService } from '../services/audit.js';
import { PolicyMiddleware } from '../middleware/policy.js';
import { injectCredential } from '../services/injector.js';
import { sanitizeResponse, sanitizeHeaders } from '../middleware/sanitize.js';
import { validateTargetDomain } from '../services/domain-validator.js';

interface ProxyRequestBody {
  vault_ref: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export function registerProxyRoutes(app: FastifyInstance, db: Pool, redis: Redis, vaultBackend: VaultBackend) {
  const audit = new AuditService(db);
  const policy = new PolicyMiddleware(db, redis);

  app.post<{ Body: ProxyRequestBody }>('/v1/proxy/request', async (request, reply) => {
    const startTime = Date.now();
    const session = request.session!;
    const { vault_ref, method, url, headers: agentHeaders, body: agentBody } = request.body;

    // Validate the agent can access this secret
    if (!session.allowed_secrets.includes(vault_ref)) {
      const err = new AuthorizationError(`Session does not have access to ${vault_ref}`);
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_denied',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { reason: 'secret_not_allowed' },
      });
      return reply.code(err.statusCode).send(err.toJSON());
    }

    // Retrieve and decrypt the secret (served from TTL cache when available)
    const secretResult = await vaultBackend.getSecret(vault_ref);
    if (!secretResult) {
      const err = new NotFoundError(`Secret ${vault_ref}`);
      return reply.code(err.statusCode).send(err.toJSON());
    }

    const { secret, plaintext } = secretResult;

    // Validate target domain against secret's allowed_domains
    try {
      validateTargetDomain(secret, url);
    } catch (domainErr) {
      const avErr = domainErr as BlindKeyError;
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_denied',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { reason: 'domain_not_allowed' },
      });
      return reply.code(avErr.statusCode).send(avErr.toJSON());
    }

    const proxyRequest: ProxyRequest = { vault_ref, method, url, headers: agentHeaders, body: agentBody };

    // Enforce policies
    let policyChecked: string[] = [];
    try {
      const policyResult = await policy.enforce(session, proxyRequest);
      policyChecked = policyResult.checked;
    } catch (err) {
      const avErr = err as BlindKeyError;
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_denied',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { blocking_policy: (err as { policy?: string }).policy ?? avErr.code, checked: policyChecked },
      });
      return reply.code(avErr.statusCode).send(avErr.toJSON());
    }

    // Inject credentials
    const injection = injectCredential(secret, plaintext, agentHeaders ?? {}, url);

    // Forward the request to the target API
    let targetResponse: Response;
    try {
      targetResponse = await fetch(injection.url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...injection.headers,
        },
        body: agentBody && method !== 'GET' ? JSON.stringify(agentBody) : undefined,
      });
    } catch (fetchErr) {
      const latency = Date.now() - startTime;
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_allowed',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { checked: policyChecked, blocking_policy: null },
        response_status: 502,
        latency_ms: latency,
      });
      return reply.code(502).send({
        error: 'upstream_error',
        message: `Failed to reach target API: ${(fetchErr as Error).message}`,
      });
    }

    const latency = Date.now() - startTime;

    // Parse response
    let responseBody: unknown;
    const contentType = targetResponse.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      responseBody = await targetResponse.json();
    } else {
      responseBody = await targetResponse.text();
    }

    // Sanitize response — strip any leaked secrets
    responseBody = sanitizeResponse(responseBody, plaintext);

    // Build response headers (exclude hop-by-hop headers)
    const responseHeaders: Record<string, string> = {};
    const skipHeaders = new Set(['transfer-encoding', 'connection', 'keep-alive', 'content-encoding']);
    targetResponse.headers.forEach((value, key) => {
      if (!skipHeaders.has(key.toLowerCase())) {
        responseHeaders[key] = value;
      }
    });
    const cleanHeaders = sanitizeHeaders(responseHeaders, plaintext);

    // Audit log
    await audit.log({
      user_id: session.user_id,
      session_id: session.id,
      vault_ref,
      action: 'request_allowed',
      request_summary: { method, url, body_hash: hashBody(agentBody) },
      policy_result: { checked: policyChecked, blocking_policy: null },
      response_status: targetResponse.status,
      latency_ms: latency,
    });

    return reply
      .code(targetResponse.status)
      .headers(cleanHeaders)
      .send(responseBody);
  });
}
