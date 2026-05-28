import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { buildApp, LOCAL_TOKEN } from './index.js';
import {
  SQLiteVaultBackend,
  LocalGrantService,
  LocalAuditService,
  LocalPolicyService,
  initializeSchema,
  type LocalVault,
} from '@blindkey/local-vault';

// Minimal mock vault — tests only exercise the HTTP layer
function makeMockVault(): LocalVault {
  const audit = {
    log: () => {},
    recent: () => [],
    allAsc: () => [],
    verify: () => ({ valid: true, errors: [], lastValidIndex: -1 }),
    count: () => 0,
  };

  const grants = {
    getAll: () => [],
    add: (g: unknown) => ({ id: 'g1', created_at: new Date(), recursive: true, requires_approval: false, ...(g as object) }),
    remove: () => {},
    checkAccess: () => ({ granted: true, grant: null, reason: null }),
  };

  const store = {
    listSecrets: async () => [],
    getSecret: async () => null,
    storeSecret: async () => ({ vaultRef: 'bk://test-abc123456789' }),
    rotateSecret: async () => {},
    deleteSecret: async () => {},
    getRef: async () => null,
    setRef: async () => {},
    deleteRef: async () => false,
    listRefs: async () => [],
    getSecretByName: () => null,
    deleteSecretByName: () => false,
  };

  const policies = {
    getAll: () => [],
    getEffective: () => [],
    add: (r: unknown) => ({ id: 'p1', enabled: true, created_at: '', ...(r as object) }),
    remove: () => false,
    toggle: () => {},
  };

  return { db: {} as never, store: store as never, grants: grants as never, audit: audit as never, policies: policies as never };
}

describe('local-api security', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    app = await buildApp(makeMockVault());
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  // ── Authentication enforcement ──

  describe('authentication', () => {
    it('should return 401 for unauthenticated GET /v1/secrets', async () => {
      const res = await app.inject({ method: 'GET', url: '/v1/secrets' });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for unauthenticated GET /v1/grants', async () => {
      const res = await app.inject({ method: 'GET', url: '/v1/grants' });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for unauthenticated GET /v1/audit', async () => {
      const res = await app.inject({ method: 'GET', url: '/v1/audit' });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for unauthenticated POST /v1/proxy', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        payload: { vault_ref: 'bk://test', method: 'GET', url: 'https://api.example.com' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for wrong token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/secrets',
        headers: { authorization: 'Bearer wrong-token' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should allow access with correct Bearer token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/secrets',
        headers: { authorization: `Bearer ${LOCAL_TOKEN}` },
      });
      expect(res.statusCode).toBe(200);
    });

    it('should allow /v1/auth/login without token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'test@example.com', password: 'test' },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.token).toBe(LOCAL_TOKEN);
    });

    it('should allow /v1/auth/register without token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: { email: 'test@example.com', password: 'test' },
      });
      expect(res.statusCode).toBe(201);
    });
  });

  // ── Proxy SSRF protection ──

  describe('proxy SSRF protection', () => {
    const auth = { authorization: `Bearer ${LOCAL_TOKEN}` };

    it('should reject file:// URLs', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'GET', url: 'file:///etc/passwd' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().message).toContain('Only http');
    });

    it('should reject ftp:// URLs', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'GET', url: 'ftp://internal.host/file' },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should reject javascript: URLs', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'GET', url: 'javascript:alert(1)' },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should reject invalid URLs', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'GET', url: 'not-a-url' },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should reject disallowed HTTP methods', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'TRACE', url: 'https://api.example.com' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().message).toContain('TRACE');
    });

    it('should reject CONNECT method', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test', method: 'CONNECT', url: 'https://api.example.com' },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // ── Audit limit bounding ──

  describe('audit limit', () => {
    const auth = { authorization: `Bearer ${LOCAL_TOKEN}` };

    it('should cap limit to MAX_AUDIT_LIMIT', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/audit?limit=999999',
        headers: auth,
      });
      // Should succeed (not crash) with bounded limit
      expect(res.statusCode).toBe(200);
    });

    it('should handle non-numeric limit gracefully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/audit?limit=abc',
        headers: auth,
      });
      expect(res.statusCode).toBe(200);
    });
  });

  // ── Missing required fields ──

  describe('input validation', () => {
    const auth = { authorization: `Bearer ${LOCAL_TOKEN}` };

    it('should return 400 for POST /v1/secrets with missing fields', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/secrets',
        headers: auth,
        payload: { name: 'test' }, // missing secret_type and plaintext_value
      });
      expect(res.statusCode).toBe(400);
    });

    it('should return 400 for POST /v1/proxy with missing fields', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/proxy',
        headers: auth,
        payload: { vault_ref: 'bk://test' }, // missing method and url
      });
      expect(res.statusCode).toBe(400);
    });
  });
});

// ── Proxy critical-path tests (use real in-memory vault) ──────────────────────

const VALID_KEY = randomBytes(32).toString('hex');
const AUTH = { authorization: `Bearer ${LOCAL_TOKEN}` };

function makeRealVault(): { vault: LocalVault; db: Database.Database } {
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  initializeSchema(db);
  const vault: LocalVault = {
    db,
    store: new SQLiteVaultBackend(db),
    grants: new LocalGrantService(db),
    audit: new LocalAuditService(db),
    policies: new LocalPolicyService(db),
  };
  return { vault, db };
}

function makeFetchResponse(body: unknown, status = 200, contentType = 'application/json'): Response {
  return {
    status,
    headers: { get: (h: string) => (h.toLowerCase() === 'content-type' ? contentType : null) },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(String(body)),
  } as unknown as Response;
}

describe('/v1/proxy core flow', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let vault: LocalVault;
  let db: Database.Database;

  beforeEach(async () => {
    process.env.VAULT_MASTER_KEY = VALID_KEY;
    ({ vault, db } = makeRealVault());
    app = await buildApp(vault);
    await app.ready();
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    await app.close();
    db.close();
    delete process.env.VAULT_MASTER_KEY;
  });

  // ── Named ref resolution ──────────────────────────────────────────────────

  it('returns 404 for unknown named ref', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: 'does-not-exist', method: 'GET', url: 'https://api.openai.com/v1/models' },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().message).toContain('"does-not-exist" not found');
  });

  it('returns 404 for unknown raw vault_ref', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: 'bk://ghost-abc123', method: 'GET', url: 'https://api.openai.com/v1/models' },
    });
    expect(res.statusCode).toBe(404);
  });

  it('resolves named ref, injects Bearer auth, and proxies request', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'openai-prod',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-real-key',
      allowed_domains: ['api.openai.com'],
    });
    await vault.store.setRef('openai-prod', vaultRef, 'openai');

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ id: 'chatcmpl-1' })));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: {
        vault_ref: 'openai-prod',
        method: 'POST',
        url: 'https://api.openai.com/v1/chat/completions',
        body: { model: 'gpt-4o-mini', messages: [] },
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().body.id).toBe('chatcmpl-1');

    const [fetchUrl, fetchInit] = vi.mocked(fetch).mock.calls[0];
    expect(fetchUrl).toBe('https://api.openai.com/v1/chat/completions');
    expect((fetchInit?.headers as Record<string, string>)['Authorization']).toBe('Bearer sk-real-key');
  });

  // ── Domain check ─────────────────────────────────────────────────────────

  it('denies request when hostname is not in allowed_domains', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'restricted',
      service: 'custom',
      secret_type: 'api_key',
      plaintext_value: 'secret',
      allowed_domains: ['api.example.com'],
    });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://evil.example.com/steal' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().message).toContain('not in allowed list');
  });

  it('allows requests matching a wildcard domain', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'wildcard',
      service: 'custom',
      secret_type: 'api_key',
      plaintext_value: 'secret',
      allowed_domains: ['*.stripe.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.stripe.com/v1/charges' },
    });

    expect(res.statusCode).toBe(200);
  });

  it('uses provider allowedDomains as fallback when secret has no allowed_domains', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'no-domains',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-test',
      // no allowed_domains — provider adapter fallback applies
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    // openai.allowedDomains = ['api.openai.com'] — this should pass
    const okRes = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.openai.com/v1/models' },
    });
    expect(okRes.statusCode).toBe(200);

    // Off-adapter domain — should be blocked
    const denyRes = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://evil.com/steal' },
    });
    expect(denyRes.statusCode).toBe(403);
    expect(denyRes.json().message).toContain('allowed domain for provider');
  });

  // ── Auth injection ────────────────────────────────────────────────────────

  it('denies custom secrets with no allowed_domains', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'custom-no-domains',
      service: 'custom',
      secret_type: 'api_key',
      plaintext_value: 'custom-secret',
    });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://anything.example/resource' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().message).toContain('require at least one allowed domain');
  });

  it('enforces provider domains even when secret allowed_domains is wrong', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'openai-wrong-domain',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-test',
      allowed_domains: ['evil.com'],
    });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://evil.com/steal' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().message).toContain('allowed domain for provider');
  });

  it('injects Basic auth for basic_auth type (no provider adapter)', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'basic-key',
      service: 'unknown-service',
      secret_type: 'basic_auth',
      plaintext_value: 'user:pass',
      allowed_domains: ['custom.api.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://custom.api.com/resource' },
    });

    const [, init] = vi.mocked(fetch).mock.calls[0];
    const expected = `Basic ${Buffer.from('user:pass').toString('base64')}`;
    expect((init?.headers as Record<string, string>)['Authorization']).toBe(expected);
  });

  it('injects custom header for custom_header type', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'custom-header-key',
      service: 'unknown-service',
      secret_type: 'custom_header',
      plaintext_value: 'tok-123',
      allowed_domains: ['custom.api.com'],
      metadata: { header_name: 'X-My-Token' },
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://custom.api.com/resource' },
    });

    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)['X-My-Token']).toBe('tok-123');
  });

  it('injects query param for query_param type', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'qp-key',
      service: 'unknown-service',
      secret_type: 'query_param',
      plaintext_value: 'qp-secret',
      allowed_domains: ['custom.api.com'],
      metadata: { query_param_name: 'token' },
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://custom.api.com/resource' },
    });

    const [fetchUrl] = vi.mocked(fetch).mock.calls[0];
    const u = new URL(String(fetchUrl));
    expect(u.searchParams.get('token')).toBe('qp-secret');
  });

  it('uses Anthropic provider adapter (x-api-key, not Authorization)', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'anthropic-key',
      service: 'anthropic',
      secret_type: 'api_key',
      plaintext_value: 'sk-ant-real',
      allowed_domains: ['api.anthropic.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ id: 'msg-1' })));

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'POST', url: 'https://api.anthropic.com/v1/messages', body: {} },
    });

    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)['x-api-key']).toBe('sk-ant-real');
    expect((init?.headers as Record<string, string>)['Authorization']).toBeUndefined();
  });

  // ── Response redaction ────────────────────────────────────────────────────

  it('redacts plaintext from provider error response', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'redact-key',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-should-not-appear',
      allowed_domains: ['api.openai.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      makeFetchResponse({ error: { message: 'Invalid key: sk-should-not-appear' } }, 401),
    ));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.openai.com/v1/models' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.payload).not.toContain('sk-should-not-appear');
    expect(res.payload).toContain('[REDACTED]');
  });

  it('redacts base64-encoded plaintext from response', async () => {
    const secret = 'raw-secret-value';
    const b64 = Buffer.from(secret).toString('base64');
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'b64-redact-key',
      service: 'custom',
      secret_type: 'basic_auth',
      plaintext_value: secret,
      allowed_domains: ['custom.api.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ token: b64 })));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://custom.api.com/resource' },
    });

    expect(res.payload).not.toContain(b64);
    expect(res.payload).toContain('[REDACTED]');
  });

  // ── Error handling ────────────────────────────────────────────────────────

  it('returns 504 on AbortError without leaking plaintext', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'timeout-key',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-timeout',
      allowed_domains: ['api.openai.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('aborted', 'AbortError')));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.openai.com/v1/models' },
    });

    expect(res.statusCode).toBe(504);
    expect(res.json().message).toBe('Upstream request timed out');
    expect(res.payload).not.toContain('sk-timeout');
  });

  it('returns 502 on network error without leaking plaintext', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'net-error-key',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-do-not-leak',
      allowed_domains: ['api.openai.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('sk-do-not-leak: connection refused')));

    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.openai.com/v1/models' },
    });

    expect(res.statusCode).toBe(502);
    expect(res.json().message).toBe('Upstream request failed');
    expect(res.payload).not.toContain('sk-do-not-leak');
  });

  // ── Audit trail ───────────────────────────────────────────────────────────

  it('writes a successful audit entry and never logs plaintext', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'audit-key',
      service: 'openai',
      secret_type: 'api_key',
      plaintext_value: 'sk-audit-secret',
      allowed_domains: ['api.openai.com'],
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(makeFetchResponse({ ok: true })));

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://api.openai.com/v1/models' },
    });

    const entries = vault.audit.recent(10);
    const proxyEntry = entries.find((e) => e.action === 'proxy_request');
    expect(proxyEntry).toBeDefined();
    expect(proxyEntry!.vault_ref).toBe(vaultRef);
    expect(proxyEntry!.granted).toBe(1);
    expect(JSON.stringify(proxyEntry)).not.toContain('sk-audit-secret');
  });

  it('writes a denied audit entry on domain check failure', async () => {
    const { vaultRef } = await vault.store.storeSecret({
      user_id: 'local',
      name: 'deny-audit',
      service: 'custom',
      secret_type: 'api_key',
      plaintext_value: 'secret',
      allowed_domains: ['allowed.com'],
    });

    await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: AUTH,
      payload: { vault_ref: vaultRef, method: 'GET', url: 'https://denied.com/resource' },
    });

    const entries = vault.audit.recent(10);
    const denied = entries.find((e) => e.action === 'proxy_request' && e.granted === 0);
    expect(denied).toBeDefined();
    expect(denied!.blocking_rule).toBe('domain_not_allowed');
  });
});
