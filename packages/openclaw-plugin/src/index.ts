/**
 * BlindKey OpenClaw Plugin — registers credential injection and secret
 * listing tools so OpenClaw agents can make authenticated API requests
 * without ever seeing plaintext secrets.
 */

import { Type } from '@sinclair/typebox';
import { createLocalVault, type LocalVault, checkFsAccess, DEFAULT_FS_POLICIES } from '@blindkey/local-vault';
import { evaluateFsPolicy, type FsRequest } from '@blindkey/core';
import { readFile, writeFile, appendFile, stat, readdir, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';

let vault: LocalVault;

async function ensureVault(): Promise<LocalVault> {
  if (!vault) {
    vault = await createLocalVault();
  }
  return vault;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default async (api: any) => {
  const v = await ensureVault();

  // ── Credential Proxy Tool ──

  api.registerTool({
    name: 'bk_proxy',
    description:
      'Make an authenticated API request. The real credential is injected server-side — never visible to the agent.',
    parameters: Type.Object({
      vault_ref: Type.String({ description: 'Secret reference (e.g., bk://stripe-abc123)' }),
      method: Type.String({ description: 'HTTP method: GET, POST, PUT, PATCH, DELETE' }),
      url: Type.String({ description: 'Full target API URL' }),
      headers: Type.Optional(Type.String({ description: 'JSON-encoded request headers object' })),
      body: Type.Optional(Type.String({ description: 'JSON-encoded request body' })),
    }),
    async execute(
      _id: string,
      params: { vault_ref: string; method: string; url: string; headers?: string; body?: string },
    ) {
      const { vault_ref, method, headers: rawHeaders, body: rawBody } = params;
      let { url } = params;

      const reqHeaders: Record<string, string> = rawHeaders
        ? (JSON.parse(rawHeaders) as Record<string, string>)
        : {};
      const body = rawBody ? (JSON.parse(rawBody) as unknown) : undefined;

      const result = await v.store.getSecret(vault_ref);
      if (!result) {
        v.audit.log({ action: 'proxy_request', vault_ref, granted: false, blocking_rule: 'not_found' });
        return { error: `Secret not found: ${vault_ref}` };
      }

      const { secret, plaintext } = result;

      // Domain check
      if (secret.allowed_domains && secret.allowed_domains.length > 0) {
        const hostname = new URL(url).hostname;
        const allowed = secret.allowed_domains.some((d) => {
          if (d.startsWith('*.')) {
            return hostname.endsWith(d.slice(1)) || hostname === d.slice(2);
          }
          return hostname === d;
        });
        if (!allowed) {
          v.audit.log({
            action: 'proxy_request',
            vault_ref,
            granted: false,
            blocking_rule: 'domain_not_allowed',
            detail: JSON.stringify({ url, hostname }),
          });
          return { error: `Domain "${hostname}" not in allowed list for this secret` };
        }
      }

      // Inject credential based on type
      switch (secret.secret_type) {
        case 'api_key':
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
        case 'oauth_token':
          reqHeaders['Authorization'] = `Bearer ${plaintext}`;
          break;
        case 'query_param': {
          const paramName = (secret.metadata?.query_param_name as string) ?? 'api_key';
          const u = new URL(url);
          u.searchParams.set(paramName, plaintext);
          url = u.toString();
          break;
        }
      }

      if (!reqHeaders['Content-Type'] && body) {
        reqHeaders['Content-Type'] = 'application/json';
      }

      const response = await fetch(url, {
        method,
        headers: reqHeaders,
        body: body ? JSON.stringify(body) : undefined,
      });

      const contentType = response.headers.get('content-type') ?? '';
      let responseBody: unknown;
      if (contentType.includes('application/json')) {
        responseBody = await response.json();
      } else {
        responseBody = await response.text();
      }

      // Sanitize response — strip any echoed secrets
      let sanitized = false;
      const responseStr = JSON.stringify(responseBody);
      if (responseStr.includes(plaintext)) {
        responseBody = JSON.parse(responseStr.replaceAll(plaintext, '[REDACTED]'));
        sanitized = true;
      }

      v.audit.log({
        action: 'proxy_request',
        vault_ref,
        granted: true,
        detail: JSON.stringify({
          method,
          url: new URL(url).pathname,
          status: response.status,
          ...(sanitized ? { sanitized: true } : {}),
        }),
      });

      return { status: response.status, body: responseBody };
    },
  });

  // ── List Secrets Tool ──

  api.registerTool({
    name: 'bk_list_secrets',
    description: 'List available secret references for this session. Values are never shown.',
    parameters: Type.Object({}),
    async execute() {
      const secrets = await v.store.listSecrets([]);
      return secrets.map((s) => ({
        vault_ref: s.vault_ref,
        name: s.name,
        service: s.service,
        type: s.secret_type,
        domains: s.allowed_domains,
      }));
    },
  });

  // ── Filesystem Tools ──

  api.registerTool({
    name: 'bk_fs_read',
    description:
      'Read a file. Requires explicit grant via Blindkey dashboard. Blocked paths: .env, .ssh, credentials.',
    parameters: Type.Object({
      path: Type.String({ description: 'Absolute path to the file' }),
      encoding: Type.Optional(Type.String({ description: 'File encoding (default: utf-8)' })),
    }),
    async execute(
      _id: string,
      { path, encoding }: { path: string; encoding?: string },
    ) {
      const fullPath = resolve(path);
      const access = await checkFsAccess(v, 'read', fullPath);
      if (!access.allowed) {
        return { error: `Access denied: ${access.reason}` };
      }

      try {
        const content = await readFile(fullPath, { encoding: (encoding ?? 'utf-8') as BufferEncoding });
        const info = await stat(fullPath);
        v.audit.log({ action: 'fs_read', path: fullPath, granted: true, detail: JSON.stringify({ size: info.size }) });
        return { content };
      } catch (err) {
        return { error: (err as Error).message };
      }
    },
  });

  api.registerTool({
    name: 'bk_fs_write',
    description:
      'Write a file. Content is scanned for secrets/API keys — writes containing credentials are BLOCKED.',
    parameters: Type.Object({
      path: Type.String({ description: 'Absolute path to the file' }),
      content: Type.String({ description: 'Content to write' }),
      mode: Type.Optional(Type.String({ description: 'Write mode: overwrite or append (default: overwrite)' })),
    }),
    async execute(
      _id: string,
      { path, content, mode }: { path: string; content: string; mode?: string },
    ) {
      const fullPath = resolve(path);
      const access = await checkFsAccess(v, 'write', fullPath);
      if (!access.allowed) {
        return { error: `Access denied: ${access.reason}` };
      }

      // Content scan
      const contentSize = Buffer.byteLength(content, 'utf-8');
      const scanReq: FsRequest = { operation: 'write', path: fullPath, content };
      const effectivePolicies = v.policies
        ? v.policies.getEffective()
        : DEFAULT_FS_POLICIES;
      const scanResult = evaluateFsPolicy(effectivePolicies, scanReq, contentSize);
      if (!scanResult.allowed) {
        v.audit.log({ action: 'fs_write', path: fullPath, granted: false, blocking_rule: scanResult.blocking_rule ?? undefined });
        return { error: `Blocked: ${scanResult.message}` };
      }

      try {
        await mkdir(dirname(fullPath), { recursive: true });

        if (mode === 'append') {
          await appendFile(fullPath, content, 'utf-8');
        } else {
          await writeFile(fullPath, content, 'utf-8');
        }

        const hash = createHash('sha256').update(content).digest('hex').slice(0, 12);
        v.audit.log({ action: 'fs_write', path: fullPath, granted: true, detail: JSON.stringify({ bytes: contentSize, hash }) });
        return { bytes_written: contentSize };
      } catch (err) {
        return { error: (err as Error).message };
      }
    },
  });

  api.registerTool({
    name: 'bk_fs_list',
    description: 'List directory contents. Only works on unlocked directories.',
    parameters: Type.Object({
      path: Type.String({ description: 'Absolute path to the directory' }),
    }),
    async execute(_id: string, { path }: { path: string }) {
      const fullPath = resolve(path);
      const access = await checkFsAccess(v, 'list', fullPath);
      if (!access.allowed) {
        return { error: `Access denied: ${access.reason}` };
      }

      try {
        const entries = await readdir(fullPath, { withFileTypes: true });
        const results = [];
        for (const entry of entries) {
          try {
            const info = await stat(resolve(fullPath, entry.name));
            results.push({
              name: entry.name,
              type: entry.isDirectory() ? 'directory' : 'file',
              size: info.size,
              modified: info.mtime.toISOString(),
            });
          } catch {
            results.push({ name: entry.name, type: entry.isDirectory() ? 'directory' : 'file', size: 0, modified: '' });
          }
        }
        v.audit.log({ action: 'fs_list', path: fullPath, granted: true });
        return results;
      } catch (err) {
        return { error: (err as Error).message };
      }
    },
  });

  api.registerTool({
    name: 'bk_fs_info',
    description: 'Get metadata about a file or directory.',
    parameters: Type.Object({
      path: Type.String({ description: 'Absolute path' }),
    }),
    async execute(_id: string, { path }: { path: string }) {
      const fullPath = resolve(path);
      const access = await checkFsAccess(v, 'info', fullPath);
      if (!access.allowed) {
        return { error: `Access denied: ${access.reason}` };
      }

      try {
        const info = await stat(fullPath);
        v.audit.log({ action: 'fs_info', path: fullPath, granted: true });
        return {
          name: fullPath.split(/[/\\]/).pop(),
          type: info.isDirectory() ? 'directory' : 'file',
          size: info.size,
          created: info.birthtime.toISOString(),
          modified: info.mtime.toISOString(),
        };
      } catch (err) {
        return { error: (err as Error).message };
      }
    },
  });

  api.registerTool({
    name: 'bk_list_grants',
    description: 'List filesystem grants — which paths are unlocked and their permissions.',
    parameters: Type.Object({}),
    async execute() {
      const grants = v.grants.getAll();
      return grants.map((g) => ({
        path: g.path,
        permissions: g.permissions,
        recursive: g.recursive,
        requires_approval: g.requires_approval,
      }));
    },
  });
};
