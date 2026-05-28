import type { ProviderAdapter } from './types.js';

export const openai: ProviderAdapter = {
  allowedDomains: ['api.openai.com'],

  injectAuth(headers, plaintext) {
    headers['Authorization'] = `Bearer ${plaintext}`;
  },

  extractModel(body) {
    if (body && typeof body === 'object' && 'model' in body) {
      return String((body as Record<string, unknown>).model);
    }
    return null;
  },

  estimateCostCents(response) {
    if (response && typeof response === 'object' && 'usage' in response) {
      const usage = (response as Record<string, unknown>).usage;
      if (usage && typeof usage === 'object' && 'total_tokens' in usage) {
        const tokens = Number((usage as Record<string, unknown>).total_tokens);
        // ~$0.002 per 1K tokens (gpt-4o-mini ballpark); real cost requires model-specific rates
        return Math.round((tokens / 1000) * 0.2);
      }
    }
    return 0;
  },
};
