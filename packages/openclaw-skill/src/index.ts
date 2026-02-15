#!/usr/bin/env node

/**
 * BlindKey OpenClaw Skill — MCP server that provides secure credential
 * injection and filesystem gating for AI agents.
 *
 * Works as a standalone MCP server or as an OpenClaw skill.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  createLocalVault, type LocalVault,
  DEFAULT_FS_POLICIES, checkFsAccess as sharedCheckFsAccess,
} from '@blindkey/local-vault';
import { evaluateFsPolicy, type FsRequest } from '@blindkey/core';

let vault: LocalVault;

const server = new McpServer({
  name: 'blindkey',
  version: '0.1.0',
});

// Workaround: MCP SDK's tool() overloads trigger TS2589 when combined
// with project references. Bind to an untyped wrapper to avoid deep inference.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tool: (...args: any[]) => any = server.tool.bind(server);

// ── Credential Proxy Tool ──

tool(
  'bk_proxy',
  'Make an authenticated API request. The real credential is injected server-side — never visible to the agent.',
  {
    vault_ref: z.string().describe('Secret reference (e.g., bk://stripe-abc123)'),
    method: z.string().describe('HTTP method: GET, POST, PUT, PATCH, DELETE'),
    url: z.string().describe('Full target API URL'),
    headers: z.string().optional().describe('JSON-encoded request headers object'),
    body: z.string().optional().describe('JSON-encoded request body'),
  },
  async ({ vault_ref, method, url, headers: rawHeaders, body: rawBody }: { vault_ref: string; method: string; url: string; headers?: string; body?: string }) => {
    const headers = rawHeaders ? JSON.parse(rawHeaders) as Record<string, string> : undefined;
    const body = rawBody ? JSON.parse(rawBody) as unknown : undefined;
    try {
      const result = await vault.store.getSecret(vault_ref);
      if (!result) {
        vault.audit.log({ action: 'proxy_request', vault_ref, granted: false, blocking_rule: 'not_found' });
        return { content: [{ type: 'text' as const, text: `Error: Secret not found: ${vault_ref}` }], isError: true };
      }

      const { secret, plaintext } = result;

      // Domain check
      if (secret.allowed_domains && secret.allowed_domains.length > 0) {
        const hostname = new URL(url).hostname;
        const allowed = secret.allowed_domains.some(d => {
          if (d.startsWith('*.')) {
            return hostname.endsWith(d.slice(1)) || hostname === d.slice(2);
          }
          return hostname === d;
        });
        if (!allowed) {
          vault.audit.log({ action: 'proxy_request', vault_ref, granted: false, blocking_rule: 'domain_not_allowed', detail: JSON.stringify({ url, hostname }) });
          return { content: [{ type: 'text' as const, text: `Error: Domain "${hostname}" not in allowed list for this secret` }], isError: true };
        }
      }

      // Inject credential based on type
      const reqHeaders: Record<string, string> = { ...headers };
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

      // Sanitize response — strip any echoed secrets from the response body
      const responseStr = JSON.stringify(responseBody);
      if (responseStr.includes(plaintext)) {
        responseBody = JSON.parse(responseStr.replaceAll(plaintext, '[REDACTED]'));
        vault.audit.log({
          action: 'proxy_request',
          vault_ref,
          granted: true,
          detail: JSON.stringify({ method, url: new URL(url).pathname, status: response.status, sanitized: true }),
        });
      } else {
        vault.audit.log({
          action: 'proxy_request',
          vault_ref,
          granted: true,
          detail: JSON.stringify({ method, url: new URL(url).pathname, status: response.status }),
        });
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ status: response.status, body: responseBody }, null, 2),
        }],
      };
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  }
);

// ── List Secrets Tool ──

tool(
  'bk_list_secrets',
  'List available secret references for this session. Values are never shown.',
  async () => {
    const secrets = await vault.store.listSecrets([]);
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify(secrets.map(s => ({
          vault_ref: s.vault_ref,
          name: s.name,
          service: s.service,
          type: s.secret_type,
          domains: s.allowed_domains,
        })), null, 2),
      }],
    };
  }
);

// ── Filesystem Tools ──

import { readFile, writeFile, appendFile, stat, readdir, unlink, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';

async function checkFsAccess(operation: string, path: string): Promise<{ allowed: boolean; reason?: string }> {
  return sharedCheckFsAccess(vault, operation, path);
}

tool(
  'bk_fs_read',
  'Read a file. Only works on paths unlocked via the bk CLI.',
  {
    path: z.string().describe('Absolute path to the file'),
    encoding: z.string().optional().describe('File encoding (default: utf-8)'),
  },
  async ({ path, encoding }: { path: string; encoding?: string }) => {
    const fullPath = resolve(path);
    const access = await checkFsAccess('read', fullPath);
    if (!access.allowed) {
      return { content: [{ type: 'text' as const, text: `Access denied: ${access.reason}` }], isError: true };
    }

    try {
      const content = await readFile(fullPath, { encoding: (encoding ?? 'utf-8') as BufferEncoding });
      const info = await stat(fullPath);

      vault.audit.log({ action: 'fs_read', path: fullPath, granted: true, detail: JSON.stringify({ size: info.size }) });

      return { content: [{ type: 'text' as const, text: content }] };
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  }
);

tool(
  'bk_fs_write',
  'Write content to a file. Requires write permission. Content is scanned for leaked secrets.',
  {
    path: z.string().describe('Absolute path to the file'),
    content: z.string().describe('Content to write'),
    mode: z.string().optional().describe('Write mode: overwrite or append (default: overwrite)'),
  },
  async ({ path, content, mode }: { path: string; content: string; mode?: string }) => {
    const fullPath = resolve(path);
    const operation = mode === 'append' ? 'write' : 'write';
    const access = await checkFsAccess(operation, fullPath);
    if (!access.allowed) {
      return { content: [{ type: 'text' as const, text: `Access denied: ${access.reason}` }], isError: true };
    }

    // Content scan
    const contentSize = Buffer.byteLength(content, 'utf-8');
    const scanReq: FsRequest = { operation: 'write', path: fullPath, content };
    const effectivePolicies = vault.policies
      ? vault.policies.getEffective()
      : DEFAULT_FS_POLICIES;
    const scanResult = evaluateFsPolicy(effectivePolicies, scanReq, contentSize);
    if (!scanResult.allowed) {
      vault.audit.log({ action: 'fs_write', path: fullPath, granted: false, blocking_rule: scanResult.blocking_rule ?? undefined });
      return { content: [{ type: 'text' as const, text: `Blocked: ${scanResult.message}` }], isError: true };
    }

    try {
      await mkdir(dirname(fullPath), { recursive: true });

      if (mode === 'append') {
        await appendFile(fullPath, content, 'utf-8');
      } else {
        await writeFile(fullPath, content, 'utf-8');
      }

      const hash = createHash('sha256').update(content).digest('hex').slice(0, 12);
      vault.audit.log({ action: 'fs_write', path: fullPath, granted: true, detail: JSON.stringify({ bytes: contentSize, hash }) });

      return { content: [{ type: 'text' as const, text: JSON.stringify({ bytes_written: contentSize }) }] };
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  }
);

tool(
  'bk_fs_list',
  'List directory contents. Only works on unlocked directories.',
  {
    path: z.string().describe('Absolute path to the directory'),
  },
  async ({ path }: { path: string }) => {
    const fullPath = resolve(path);
    const access = await checkFsAccess('list', fullPath);
    if (!access.allowed) {
      return { content: [{ type: 'text' as const, text: `Access denied: ${access.reason}` }], isError: true };
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

      vault.audit.log({ action: 'fs_list', path: fullPath, granted: true });

      return { content: [{ type: 'text' as const, text: JSON.stringify(results, null, 2) }] };
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  }
);

tool(
  'bk_fs_info',
  'Get metadata about a file or directory.',
  {
    path: z.string().describe('Absolute path'),
  },
  async ({ path }: { path: string }) => {
    const fullPath = resolve(path);
    const access = await checkFsAccess('info', fullPath);
    if (!access.allowed) {
      return { content: [{ type: 'text' as const, text: `Access denied: ${access.reason}` }], isError: true };
    }

    try {
      const info = await stat(fullPath);
      const result = {
        name: fullPath.split(/[/\\]/).pop(),
        type: info.isDirectory() ? 'directory' : 'file',
        size: info.size,
        created: info.birthtime.toISOString(),
        modified: info.mtime.toISOString(),
      };

      vault.audit.log({ action: 'fs_info', path: fullPath, granted: true });

      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  }
);

tool(
  'bk_list_grants',
  'List filesystem grants — which paths are unlocked and their permissions.',
  async () => {
    const grants = vault.grants.getAll();
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify(grants.map(g => ({
          path: g.path,
          permissions: g.permissions,
          recursive: g.recursive,
          requires_approval: g.requires_approval,
        })), null, 2),
      }],
    };
  }
);

// ── Start ──

async function main() {
  vault = await createLocalVault();

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('BlindKey MCP server running on stdio');
  console.error(`Vault: ~/.blindkey/vault.db`);

  const secretCount = (await vault.store.listSecrets([])).length;
  const grantCount = vault.grants.getAll().length;
  console.error(`Loaded: ${secretCount} secret(s), ${grantCount} filesystem grant(s)`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
