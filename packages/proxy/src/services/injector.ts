import type { Secret } from '@blindkey/core';

export interface InjectionResult {
  headers: Record<string, string>;
  url: string;
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
      const separator = url.includes('?') ? '&' : '?';
      url = `${url}${separator}${encodeURIComponent(paramName)}=${encodeURIComponent(plaintext)}`;
      break;
    }
  }

  return { headers, url };
}
