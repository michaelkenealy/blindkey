export type { ProviderAdapter } from './types.js';
export { openai } from './openai.js';
export { anthropic } from './anthropic.js';
export { stripe } from './stripe.js';
export { github } from './github.js';

import { openai } from './openai.js';
import { anthropic } from './anthropic.js';
import { stripe } from './stripe.js';
import { github } from './github.js';
import type { ProviderAdapter } from './types.js';

const REGISTRY: Record<string, ProviderAdapter> = {
  openai,
  anthropic,
  stripe,
  github,
};

export function getProvider(name: string): ProviderAdapter | null {
  return REGISTRY[name.toLowerCase()] ?? null;
}

export function listProviders(): string[] {
  return Object.keys(REGISTRY);
}
