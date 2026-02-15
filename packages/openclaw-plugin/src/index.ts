/**
 * BlindKey OpenClaw Plugin — registers credential injection and secret
 * listing tools so OpenClaw agents can make authenticated API requests
 * without ever seeing plaintext secrets.
 */

import { Type } from '@sinclair/typebox';
import { createLocalVault, type LocalVault } from '@blindkey/local-vault';

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
};
