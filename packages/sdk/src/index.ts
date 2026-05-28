const DEFAULT_LOCAL_API = 'http://127.0.0.1:3200';

export interface BlindFetchOptions {
  /** Full target URL to forward to the provider. */
  url: string;
  /** HTTP method. Defaults to GET. */
  method?: string;
  /** Extra request headers forwarded to the provider (no auth — BlindKey injects that). */
  headers?: Record<string, string>;
  /** Request body, serialized as JSON. */
  body?: unknown;
  /** BlindKey local-api base URL. Defaults to http://127.0.0.1:3200. */
  apiBase?: string;
}

export interface BlindFetchResponse {
  status: number;
  body: unknown;
}

/**
 * Make an authenticated API call through BlindKey without exposing the raw credential.
 *
 * @param ref  A named ref ("openai-prod") or raw vault_ref ("bk://openai-abc123").
 * @param opts  Request options.
 *
 * @example
 * const res = await blindFetch("openai-prod", {
 *   url: "https://api.openai.com/v1/chat/completions",
 *   method: "POST",
 *   body: { model: "gpt-4o-mini", messages: [{ role: "user", content: "Hello" }] },
 * });
 */
export async function blindFetch(
  ref: string,
  opts: BlindFetchOptions,
): Promise<BlindFetchResponse> {
  const apiBase = opts.apiBase ?? process.env['BLINDKEY_API'] ?? DEFAULT_LOCAL_API;

  const response = await fetch(`${apiBase}/v1/proxy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vault_ref: ref,
      method: opts.method ?? 'GET',
      url: opts.url,
      headers: opts.headers,
      body: opts.body,
    }),
  });

  const json = await response.json() as { status: number; body: unknown; message?: string };

  if (!response.ok) {
    throw new BlindKeyError(
      json.message ?? `BlindKey proxy error: ${response.status}`,
      response.status,
    );
  }

  return { status: json.status, body: json.body };
}

export class BlindKeyError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'BlindKeyError';
  }
}

export interface BlindClientOptions {
  /** Named ref or vault_ref pointing to the credential for this provider. */
  ref: string;
  /** BlindKey local-api base URL. Defaults to http://127.0.0.1:3200. */
  apiBase?: string;
}

/**
 * Create a pre-bound fetch-compatible client for a specific credential.
 * Useful when an SDK or library expects a `fetch`-like function.
 *
 * @example
 * const client = createBlindClient({ ref: "openai-prod" });
 * const res = await client.fetch("https://api.openai.com/v1/models", { method: "GET" });
 */
export function createBlindClient(opts: BlindClientOptions) {
  return {
    fetch(url: string, init?: { method?: string; headers?: Record<string, string>; body?: unknown }) {
      return blindFetch(opts.ref, {
        url,
        method: init?.method,
        headers: init?.headers,
        body: init?.body,
        apiBase: opts.apiBase,
      });
    },
  };
}
