const PROXY_BASE_URL = process.env.AGENTVAULT_PROXY_URL ?? 'http://localhost:3100';
const FS_PROXY_BASE_URL = process.env.AGENTVAULT_FS_PROXY_URL ?? 'http://localhost:3300';
const SESSION_TOKEN = process.env.AGENTVAULT_SESSION_TOKEN ?? '';

async function proxyFetch(path: string, options: RequestInit = {}): Promise<Response> {
  return fetch(`${PROXY_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${SESSION_TOKEN}`,
      ...(options.headers as Record<string, string> ?? {}),
    },
  });
}

export interface ProxyRequestArgs {
  vault_ref: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export async function handleProxyRequest(args: ProxyRequestArgs): Promise<{
  status: number;
  body: unknown;
}> {
  const response = await proxyFetch('/v1/proxy/request', {
    method: 'POST',
    body: JSON.stringify({
      vault_ref: args.vault_ref,
      method: args.method,
      url: args.url,
      headers: args.headers,
      body: args.body,
    }),
  });

  const contentType = response.headers.get('content-type') ?? '';
  let body: unknown;
  if (contentType.includes('application/json')) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  return { status: response.status, body };
}

export async function handleListSecrets(): Promise<{
  secrets: Array<{
    vault_ref: string;
    name: string;
    service: string;
    secret_type: string;
  }>;
}> {
  const response = await proxyFetch('/v1/proxy/secrets');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to list secrets: ${JSON.stringify(error)}`);
  }
  return await response.json() as {
    secrets: Array<{
      vault_ref: string;
      name: string;
      service: string;
      secret_type: string;
    }>;
  };
}

// ── Filesystem Proxy Handlers ──

async function fsFetch(path: string, options: RequestInit = {}): Promise<Response> {
  return fetch(`${FS_PROXY_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${SESSION_TOKEN}`,
      ...(options.headers as Record<string, string> ?? {}),
    },
  });
}

export interface FsOperationArgs {
  operation: string;
  path: string;
  content?: string;
  mode?: string;
  encoding?: string;
}

export async function handleFsOperation(args: FsOperationArgs): Promise<unknown> {
  const response = await fsFetch('/v1/fs', {
    method: 'POST',
    body: JSON.stringify({
      operation: args.operation,
      path: args.path,
      content: args.content,
      mode: args.mode,
      encoding: args.encoding,
    }),
  });

  const contentType = response.headers.get('content-type') ?? '';
  let body: unknown;
  if (contentType.includes('application/json')) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  if (!response.ok) {
    throw new Error(`FS operation failed (${response.status}): ${JSON.stringify(body)}`);
  }

  return body;
}

export async function handleFsListGrants(): Promise<unknown> {
  const response = await fsFetch('/v1/fs/grants');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to list fs grants: ${JSON.stringify(error)}`);
  }
  return await response.json();
}
