const WEAK_SECRET_VALUES = new Set([
  'dev-secret-change-in-production',
  'change-me-in-production',
  'change-me-in-production-too',
  'password',
  'secret',
]);

function readEnv(name: string): string | undefined {
  const value = process.env[name];
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function requireEnv(name: string): string {
  const value = readEnv(name);
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export function parsePort(name: string, fallback: number): number {
  const raw = readEnv(name);
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`${name} must be a valid TCP port (1-65535)`);
  }
  return parsed;
}

export function requireStrongSecret(name: string, minLength = 32): string {
  const value = requireEnv(name);
  if (value.length < minLength) {
    throw new Error(`${name} must be at least ${minLength} characters long`);
  }
  if (WEAK_SECRET_VALUES.has(value.toLowerCase())) {
    throw new Error(`${name} is set to a weak placeholder value`);
  }
  return value;
}
