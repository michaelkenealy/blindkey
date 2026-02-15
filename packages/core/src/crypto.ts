import { createCipheriv, createDecipheriv, randomBytes, createHash, createHmac } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

function getMasterKey(): Buffer {
  const hex = process.env.VAULT_MASTER_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('VAULT_MASTER_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

function getTokenHashPepper(): string | null {
  const pepper = process.env.TOKEN_HASH_PEPPER;
  if (!pepper) return null;
  const trimmed = pepper.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function hashTokenLegacy(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function hashTokenV2(token: string, pepper: string): string {
  return createHmac('sha256', pepper).update(token).digest('hex');
}

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export function encrypt(plaintext: string): EncryptedData {
  const key = getMasterKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag };
}

export function decrypt(encrypted: Buffer, iv: Buffer, authTag: Buffer): string {
  const key = getMasterKey();
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

export function generateVaultRef(service: string): string {
  const id = randomBytes(12).toString('hex');
  return `bk://${service}-${id}`;
}

/**
 * Primary token hash format for new sessions.
 * - v2:<hmac_sha256(token, TOKEN_HASH_PEPPER)> when TOKEN_HASH_PEPPER is set
 * - v1:<sha256(token)> fallback for migration safety
 */
export function hashToken(token: string): string {
  const pepper = getTokenHashPepper();
  if (pepper) {
    return `v2:${hashTokenV2(token, pepper)}`;
  }
  return `v1:${hashTokenLegacy(token)}`;
}

/**
 * Candidate token hashes accepted during auth for backward compatibility.
 * Includes legacy unversioned sha256 hashes used by older BlindKey versions.
 */
export function getTokenHashCandidates(token: string): string[] {
  const legacy = hashTokenLegacy(token);
  const candidates = new Set<string>([legacy, `v1:${legacy}`]);

  const pepper = getTokenHashPepper();
  if (pepper) {
    candidates.add(`v2:${hashTokenV2(token, pepper)}`);
  }

  return Array.from(candidates);
}

export function generateSessionToken(): string {
  return `bk_${randomBytes(32).toString('base64url')}`;
}

export function hashBody(body: unknown): string {
  const json = JSON.stringify(body ?? '');
  return createHash('sha256').update(json).digest('hex');
}
