import type { Secret } from '@blindkey/core';

export interface InjectionResult {
  headers: Record<string, string>;
  url: string;
}

export class InjectionSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InjectionSecurityError';
  }
}

// Allowlisted custom header names (case-insensitive)
// These are safe headers that won't cause request smuggling or other attacks
const ALLOWED_CUSTOM_HEADERS = new Set([
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-secret-key',
  'x-client-id',
  'x-client-secret',
  'x-app-key',
  'x-app-id',
  'x-application-key',
  'x-service-key',
  'x-request-id',
  'x-correlation-id',
  'x-trace-id',
  'api-key',
  'apikey',
  'access-token',
  'auth-token',
  'secret-key',
  'client-id',
  'client-secret',
]);

// Headers that must NEVER be set via custom injection
const BLOCKED_HEADERS = new Set([
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
  'authorization', // Use api_key/oauth_token/basic_auth types instead
]);

// Valid header name: token characters only (RFC 7230)
const HEADER_NAME_REGEX = /^[a-zA-Z][a-zA-Z0-9\-_]*$/;

// Valid query parameter name
const PARAM_NAME_REGEX = /^[a-zA-Z_][a-zA-Z0-9_\-]*$/;

function validateHeaderName(name: string): void {
  const lowerName = name.toLowerCase();

  // Check against blocked headers
  if (BLOCKED_HEADERS.has(lowerName)) {
    throw new InjectionSecurityError(
      `Header "${name}" is blocked for security reasons. Use appropriate secret_type instead.`
    );
  }

  // Validate format
  if (!HEADER_NAME_REGEX.test(name)) {
    throw new InjectionSecurityError(
      `Invalid header name "${name}". Must match pattern: ${HEADER_NAME_REGEX.source}`
    );
  }

  // Check allowlist (warn but allow X- prefixed custom headers)
  if (!ALLOWED_CUSTOM_HEADERS.has(lowerName) && !lowerName.startsWith('x-')) {
    console.warn(
      `[SECURITY] Custom header "${name}" is not in allowlist. Consider using X- prefix.`
    );
  }
}

function validateParamName(name: string): void {
  if (!PARAM_NAME_REGEX.test(name)) {
    throw new InjectionSecurityError(
      `Invalid query parameter name "${name}". Must match pattern: ${PARAM_NAME_REGEX.source}`
    );
  }

  // Max length check
  if (name.length > 64) {
    throw new InjectionSecurityError(
      `Query parameter name "${name}" exceeds maximum length of 64 characters.`
    );
  }
}

export function injectCredential(
  secret: Secret,
  plaintext: string,
  originalHeaders: Record<string, string>,
  originalUrl: string
): InjectionResult {
  const headers = { ...originalHeaders };
  let url = originalUrl;

  switch (secret.secret_type) {
    case 'api_key':
      headers['Authorization'] = `Bearer ${plaintext}`;
      break;

    case 'oauth_token':
      headers['Authorization'] = `Bearer ${plaintext}`;
      break;

    case 'basic_auth':
      headers['Authorization'] = `Basic ${Buffer.from(plaintext).toString('base64')}`;
      break;

    case 'custom_header': {
      const headerName = (secret.metadata as Record<string, unknown>)?.header_name;
      if (typeof headerName === 'string') {
        validateHeaderName(headerName);
        headers[headerName] = plaintext;
      } else {
        headers['X-API-Key'] = plaintext;
      }
      break;
    }

    case 'query_param': {
      const paramName =
        (typeof (secret.metadata as Record<string, unknown>)?.query_param_name === 'string'
          ? (secret.metadata as Record<string, unknown>).query_param_name
          : 'api_key') as string;
      validateParamName(paramName);
      const separator = url.includes('?') ? '&' : '?';
      url = `${url}${separator}${encodeURIComponent(paramName)}=${encodeURIComponent(plaintext)}`;
      break;
    }
  }

  return { headers, url };
}
