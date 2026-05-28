import type { ProviderAdapter } from './types.js';

export const anthropic: ProviderAdapter = {
  allowedDomains: ['api.anthropic.com'],

  injectAuth(headers, plaintext) {
    headers['x-api-key'] = plaintext;
    headers['anthropic-version'] = headers['anthropic-version'] ?? '2023-06-01';
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
      if (usage && typeof usage === 'object') {
        const u = usage as Record<string, unknown>;
        const inputTokens = Number(u.input_tokens ?? 0);
        const outputTokens = Number(u.output_tokens ?? 0);
        // ~$0.003/1K input, $0.015/1K output (claude-3-sonnet ballpark)
        return Math.round((inputTokens / 1000) * 0.3 + (outputTokens / 1000) * 1.5);
      }
    }
    return 0;
  },
};
