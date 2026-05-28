import type { ProviderAdapter } from './types.js';

export const stripe: ProviderAdapter = {
  allowedDomains: ['api.stripe.com'],

  injectAuth(headers, plaintext) {
    // Stripe uses HTTP Basic Auth: key as username, empty password
    headers['Authorization'] = `Basic ${Buffer.from(`${plaintext}:`).toString('base64')}`;
  },

  extractModel(_body) {
    return null;
  },

  estimateCostCents(_response) {
    return 0;
  },
};
