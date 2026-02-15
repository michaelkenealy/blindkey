import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import {
  encrypt,
  generateVaultRef,
  ValidationError,
  NotFoundError,
} from '@blindkey/core';

const SECRET_COLUMNS = `id, vault_ref, name, service, secret_type, created_at, rotated_at, expires_at, metadata, allowed_domains, injection_ttl_seconds`;

interface CreateSecretBody {
  name: string;
  service: string;
  secret_type: string;
  plaintext_value: string;
  metadata?: Record<string, unknown>;
  allowed_domains?: string[];
  injection_ttl_seconds?: number;
}

interface RotateSecretBody {
  plaintext_value: string;
}

interface UpdateSecretBody {
  allowed_domains?: string[] | null;
  injection_ttl_seconds?: number;
}

const DOMAIN_PATTERN = /^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const HEADER_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9\-_]*$/;
const QUERY_PARAM_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_\-]*$/;

const BLOCKED_CUSTOM_HEADERS = new Set([
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
  'cookie',
  'set-cookie',
  'authorization',
]);

function validateAllowedDomains(allowed_domains: unknown): void {
  if (allowed_domains === null || allowed_domains === undefined) return;
  if (!Array.isArray(allowed_domains) || !allowed_domains.every((d: unknown) => typeof d === 'string')) {
    throw new ValidationError('allowed_domains must be an array of strings');
  }

  for (const domainRaw of allowed_domains) {
    const domain = domainRaw.trim().toLowerCase();
    if (!domain || domain.length > 253) {
      throw new ValidationError('allowed_domains entries must be valid hostnames');
    }
    if (domain.includes('/') || domain.includes(':') || domain.includes('?') || domain.includes('#')) {
      throw new ValidationError('allowed_domains must contain hostnames only (no scheme, path, or port)');
    }
    if (!DOMAIN_PATTERN.test(domain)) {
      throw new ValidationError(`Invalid allowed_domains entry: ${domainRaw}`);
    }
  }
}

function validateInjectionTtl(ttl: unknown): void {
  if (ttl === undefined) return;
  if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 60 || ttl > 86400) {
    throw new ValidationError('injection_ttl_seconds must be an integer between 60 and 86400');
  }
}

function validateSecretMetadata(secretType: string, metadata: unknown): void {
  if (metadata === undefined || metadata === null) return;
  if (typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new ValidationError('metadata must be an object');
  }

  const meta = metadata as Record<string, unknown>;

  if (secretType === 'custom_header') {
    const headerNameRaw = meta.header_name;
    if (headerNameRaw !== undefined) {
      if (typeof headerNameRaw !== 'string') {
        throw new ValidationError('metadata.header_name must be a string');
      }
      const headerName = headerNameRaw.trim();
      if (!HEADER_NAME_PATTERN.test(headerName)) {
        throw new ValidationError('metadata.header_name contains invalid characters');
      }
      if (BLOCKED_CUSTOM_HEADERS.has(headerName.toLowerCase())) {
        throw new ValidationError(`metadata.header_name "${headerName}" is blocked for security`);
      }
    }
  }

  if (secretType === 'query_param') {
    const queryParamRaw = meta.query_param_name;
    if (queryParamRaw !== undefined) {
      if (typeof queryParamRaw !== 'string') {
        throw new ValidationError('metadata.query_param_name must be a string');
      }
      const queryParam = queryParamRaw.trim();
      if (!QUERY_PARAM_PATTERN.test(queryParam)) {
        throw new ValidationError('metadata.query_param_name contains invalid characters');
      }
      if (queryParam.length > 64) {
        throw new ValidationError('metadata.query_param_name must be <= 64 characters');
      }
    }
  }
}

export function registerSecretsRoutes(app: FastifyInstance, db: Pool) {
  // Create a new secret
  app.post<{ Body: CreateSecretBody }>('/v1/secrets', async (request, reply) => {
    const userId = request.userId!;
    const { name, service, secret_type, plaintext_value, metadata, allowed_domains, injection_ttl_seconds } = request.body;

    if (!name || !service || !secret_type || !plaintext_value) {
      throw new ValidationError('name, service, secret_type, and plaintext_value are required');
    }

    const validTypes = ['api_key', 'oauth_token', 'basic_auth', 'custom_header', 'query_param'];
    if (!validTypes.includes(secret_type)) {
      throw new ValidationError(`secret_type must be one of: ${validTypes.join(', ')}`);
    }

    validateAllowedDomains(allowed_domains);
    validateInjectionTtl(injection_ttl_seconds);
    validateSecretMetadata(secret_type, metadata);

    const vaultRef = generateVaultRef(service);
    const { encrypted, iv, authTag } = encrypt(plaintext_value);

    const result = await db.query(
      `INSERT INTO secrets (user_id, vault_ref, name, service, secret_type, encrypted_value, iv, auth_tag, metadata, allowed_domains, injection_ttl_seconds)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING ${SECRET_COLUMNS}`,
      [userId, vaultRef, name, service, secret_type, encrypted, iv, authTag, JSON.stringify(metadata ?? {}), allowed_domains ?? null, injection_ttl_seconds ?? 1800]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_log (user_id, vault_ref, action, request_summary)
       VALUES ($1, $2, 'secret_created', $3)`,
      [userId, vaultRef, JSON.stringify({ name, service, secret_type })]
    );

    return reply.code(201).send(result.rows[0]);
  });

  // List secrets (metadata only, never values)
  app.get('/v1/secrets', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query(
      `SELECT ${SECRET_COLUMNS}
       FROM secrets WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );

    return reply.send({ secrets: result.rows });
  });

  // Get secret metadata
  app.get<{ Params: { id: string } }>('/v1/secrets/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      `SELECT ${SECRET_COLUMNS}
       FROM secrets WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Secret');
    }

    return reply.send(result.rows[0]);
  });

  // Update secret settings (allowed_domains, injection_ttl_seconds)
  app.patch<{ Params: { id: string }; Body: UpdateSecretBody }>('/v1/secrets/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;
    const { allowed_domains, injection_ttl_seconds } = request.body;

    validateAllowedDomains(allowed_domains);
    validateInjectionTtl(injection_ttl_seconds);

    const setClauses: string[] = [];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (allowed_domains !== undefined) {
      setClauses.push(`allowed_domains = $${paramIdx++}`);
      params.push(allowed_domains);
    }
    if (injection_ttl_seconds !== undefined) {
      setClauses.push(`injection_ttl_seconds = $${paramIdx++}`);
      params.push(injection_ttl_seconds);
    }

    if (setClauses.length === 0) {
      throw new ValidationError('At least one field to update is required');
    }

    params.push(id, userId);
    const result = await db.query(
      `UPDATE secrets SET ${setClauses.join(', ')}
       WHERE id = $${paramIdx++} AND user_id = $${paramIdx}
       RETURNING ${SECRET_COLUMNS}`,
      params
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Secret');
    }

    return reply.send(result.rows[0]);
  });

  // Delete a secret
  app.delete<{ Params: { id: string } }>('/v1/secrets/:id', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;

    const result = await db.query(
      'DELETE FROM secrets WHERE id = $1 AND user_id = $2 RETURNING vault_ref',
      [id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Secret');
    }

    await db.query(
      `INSERT INTO audit_log (user_id, vault_ref, action)
       VALUES ($1, $2, 'secret_deleted')`,
      [userId, result.rows[0].vault_ref]
    );

    return reply.code(204).send();
  });

  // Rotate a secret
  app.post<{ Params: { id: string }; Body: RotateSecretBody }>('/v1/secrets/:id/rotate', async (request, reply) => {
    const userId = request.userId!;
    const { id } = request.params;
    const { plaintext_value } = request.body;

    if (!plaintext_value) {
      throw new ValidationError('plaintext_value is required');
    }

    const { encrypted, iv, authTag } = encrypt(plaintext_value);

    const result = await db.query(
      `UPDATE secrets SET encrypted_value = $1, iv = $2, auth_tag = $3, rotated_at = now()
       WHERE id = $4 AND user_id = $5
       RETURNING ${SECRET_COLUMNS}`,
      [encrypted, iv, authTag, id, userId]
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('Secret');
    }

    await db.query(
      `INSERT INTO audit_log (user_id, vault_ref, action)
       VALUES ($1, $2, 'secret_rotated')`,
      [userId, result.rows[0].vault_ref]
    );

    return reply.send(result.rows[0]);
  });
}
