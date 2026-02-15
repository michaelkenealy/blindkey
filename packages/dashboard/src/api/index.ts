/**
 * Unified BlindKey dashboard API client.
 *
 * Detects mode at startup by probing the local-api config endpoint.
 * If the local-api is running (local mode), uses the local adapter.
 * Otherwise, uses the Docker adapter (JWT-authenticated API server).
 */

import { createDockerClient } from './docker-adapter';
import { createLocalClient } from './local-adapter';
import type { BlindKeyClient, BlindKeyMode } from './types';

export type {
  BlindKeyClient,
  BlindKeyMode,
  SecretItem,
  GrantItem,
  AuditItem,
  PolicyItem,
  CreateSecretInput,
  UpdateSecretInput,
  CreateGrantInput,
} from './types';

let resolvedClient: BlindKeyClient | null = null;
let resolvedMode: BlindKeyMode = 'detecting';

/**
 * Detect mode by probing the local-api config endpoint.
 * If /v1/config returns { mode: 'local' }, we are in local mode.
 * Otherwise, fall back to Docker mode.
 */
export async function detectMode(): Promise<BlindKeyMode> {
  if (resolvedMode !== 'detecting') return resolvedMode;

  try {
    const res = await fetch('/v1/config', {
      signal: AbortSignal.timeout(2000),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.mode === 'local') {
        resolvedMode = 'local';
        resolvedClient = createLocalClient();
        return 'local';
      }
    }
  } catch {
    // fetch failed — local-api not running → Docker mode
  }

  resolvedMode = 'docker';
  resolvedClient = createDockerClient();
  return 'docker';
}

/** Get the resolved client (async, triggers detection if needed). */
export async function getClient(): Promise<BlindKeyClient> {
  if (resolvedClient) return resolvedClient;
  await detectMode();
  return resolvedClient!;
}

/** Get the resolved client synchronously (null if detectMode hasn't run yet). */
export function getClientSync(): BlindKeyClient | null {
  return resolvedClient;
}

/** Get the resolved mode. */
export function getMode(): BlindKeyMode {
  return resolvedMode;
}
