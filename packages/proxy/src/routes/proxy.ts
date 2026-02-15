import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import {
  AuthorizationError,
  NotFoundError,
  ValidationError,
  hashBody,
  type ProxyRequest,
  type BlindKeyError,
  type VaultBackend,
} from '@blindkey/core';
import { AuditService } from '../services/audit.js';
import { PolicyMiddleware } from '../middleware/policy.js';
import { injectCredential, InjectionSecurityError } from '../services/injector.js';
import { sanitizeResponse, sanitizeHeaders } from '../middleware/sanitize.js';
import { validateTargetDomain } from '../services/domain-validator.js';

interface ProxyRequestBody {
  vault_ref: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  approval_id?: string;
}

const BLOCKED_FORWARD_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'http2-settings',
  'te',
  'trailer',
  'proxy-authorization',
  'proxy-authenticate',
  'proxy-connection',
]);

function sanitizeForwardHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  if (!headers) return {};

  const cleaned: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    if (typeof rawName !== 'string' || typeof rawValue !== 'string') {
      continue;
    }

    const name = rawName.trim();
    const value = rawValue.trim();
    const lowerName = name.toLowerCase();

    if (!name || BLOCKED_FORWARD_HEADERS.has(lowerName)) {
      continue;
    }
    if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) {
      continue;
    }

    cleaned[name] = value;
  }

  return cleaned;
}

export function registerProxyRoutes(app: FastifyInstance, db: Pool, redis: Redis, vaultBackend: VaultBackend) {
  const audit = new AuditService(db);
  const policy = new PolicyMiddleware(db, redis);

  app.post<{ Body: ProxyRequestBody }>('/v1/proxy/request', async (request, reply) => {
    const startTime = Date.now();
    const session = request.session!;
    const { vault_ref, method, url, headers: agentHeaders, body: agentBody, approval_id } = request.body;

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
      await validateTargetDomain(secret, url);
    } catch (domainErr) {
      const avErr = domainErr as BlindKeyError;
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_denied',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { reason: avErr.code },
      });
      return reply.code(avErr.statusCode).send(avErr.toJSON());
    }

    const safeAgentHeaders = sanitizeForwardHeaders(agentHeaders);
    const proxyRequest: ProxyRequest = { vault_ref, method, url, headers: safeAgentHeaders, body: agentBody };

    // Enforce policies
    let policyChecked: string[] = [];
    try {
      const policyResult = await policy.enforce(session, proxyRequest, approval_id);
      policyChecked = policyResult.checked;
    } catch (err) {
      const avErr = err as BlindKeyError;
      const action = avErr.code === 'approval_required' ? 'approval_requested' : 'request_denied';
      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action,
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { blocking_policy: (err as { policy?: string }).policy ?? avErr.code, checked: policyChecked },
      });
      return reply.code(avErr.statusCode).send(avErr.toJSON());
    }

    // Inject credentials
    let injection: { headers: Record<string, string>; url: string };
    try {
      injection = injectCredential(secret, plaintext, safeAgentHeaders, url);
    } catch (err) {
      const avErr = err instanceof InjectionSecurityError
        ? new ValidationError(`Credential injection rejected: ${err.message}`)
        : err as BlindKeyError;

      await audit.log({
        user_id: session.user_id,
        session_id: session.id,
        vault_ref,
        action: 'request_denied',
        request_summary: { method, url, body_hash: hashBody(agentBody) },
        policy_result: { blocking_policy: 'injection_validation', checked: policyChecked },
      });

      if ('statusCode' in (avErr as Record<string, unknown>)) {
        return reply.code((avErr as BlindKeyError).statusCode).send((avErr as BlindKeyError).toJSON());
      }

      return reply.code(400).send({
        error: 'validation_error',
        message: 'Credential injection rejected',
      });
    }

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

    // Sanitize response - strip any leaked secrets
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
