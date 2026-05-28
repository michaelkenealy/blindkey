import type { ProviderAdapter } from './types.js';

export const github: ProviderAdapter = {
  allowedDomains: ['api.github.com'],

  injectAuth(headers, plaintext) {
    headers['Authorization'] = `Bearer ${plaintext}`;
    headers['Accept'] = headers['Accept'] ?? 'application/vnd.github+json';
    headers['X-GitHub-Api-Version'] = headers['X-GitHub-Api-Version'] ?? '2022-11-28';
  },

  extractModel(_body) {
    return null;
  },

  estimateCostCents(_response) {
    return 0;
  },
};
