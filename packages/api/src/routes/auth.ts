import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import * as OTPAuth from 'otpauth';
import { ValidationError, AuthenticationError, encrypt, decrypt } from '@blindkey/core';

interface RegisterBody {
  email: string;
  password: string;
}

interface LoginBody {
  email: string;
  password: string;
}

interface VerifyTotpBody {
  totp_token: string;
  code: string;
}

interface SetupTotpBody {
  code: string;
}

interface JwtConfig {
  secret: string;
  issuer: string;
  audience: string;
}

interface LoginAttemptRow {
  bucket: string;
  failed_count: number;
  first_failed_at: string;
  last_failed_at: string;
  locked_until: string | null;
}

const SALT_ROUNDS = 12;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_FAILED_BY_EMAIL = 8;
const MAX_FAILED_BY_IP = 20;
const TOTP_TOKEN_EXPIRY = '5m';

function signJwt(payload: Record<string, unknown>, jwtConfig: JwtConfig, expiresIn: string): string {
  return jwt.sign(payload, jwtConfig.secret, {
    algorithm: 'HS256',
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
    expiresIn,
  });
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function getLoginBuckets(email: string, requestIp: string): { emailBucket: string; ipBucket: string } {
  const safeIp = requestIp.trim() || 'unknown';
  return {
    emailBucket: `email:${normalizeEmail(email)}`,
    ipBucket: `ip:${safeIp}`,
  };
}

async function getAttempt(db: Pool, bucket: string): Promise<LoginAttemptRow | null> {
  const result = await db.query<LoginAttemptRow>(
    `SELECT bucket, failed_count, first_failed_at, last_failed_at, locked_until
     FROM auth_login_attempts
     WHERE bucket = $1`,
    [bucket]
  );
  return result.rows[0] ?? null;
}

async function assertNotLocked(db: Pool, buckets: string[]): Promise<void> {
  for (const bucket of buckets) {
    const attempt = await getAttempt(db, bucket);
    if (!attempt?.locked_until) {
      continue;
    }

    const lockedUntil = new Date(attempt.locked_until);
    if (lockedUntil > new Date()) {
      throw new AuthenticationError('Too many login attempts. Please try again later.');
    }
  }
}

async function recordFailure(db: Pool, bucket: string, threshold: number): Promise<void> {
  const now = new Date();
  const attempt = await getAttempt(db, bucket);

  if (!attempt) {
    await db.query(
      `INSERT INTO auth_login_attempts (bucket, failed_count, first_failed_at, last_failed_at, locked_until)
       VALUES ($1, 1, $2, $2, NULL)`,
      [bucket, now]
    );
    return;
  }

  const firstFailedAt = new Date(attempt.first_failed_at);
  const inCurrentWindow = now.getTime() - firstFailedAt.getTime() <= LOGIN_WINDOW_MS;
  const nextCount = inCurrentWindow ? attempt.failed_count + 1 : 1;
  const nextFirstFailedAt = inCurrentWindow ? firstFailedAt : now;
  const lockUntil = nextCount >= threshold ? new Date(now.getTime() + LOCKOUT_MS) : null;

  await db.query(
    `UPDATE auth_login_attempts
     SET failed_count = $2,
         first_failed_at = $3,
         last_failed_at = $4,
         locked_until = $5
     WHERE bucket = $1`,
    [bucket, nextCount, nextFirstFailedAt, now, lockUntil]
  );
}

async function recordLoginFailure(db: Pool, emailBucket: string, ipBucket: string): Promise<void> {
  await recordFailure(db, emailBucket, MAX_FAILED_BY_EMAIL);
  await recordFailure(db, ipBucket, MAX_FAILED_BY_IP);
}

async function clearLoginFailures(db: Pool, emailBucket: string, ipBucket: string): Promise<void> {
  await db.query('DELETE FROM auth_login_attempts WHERE bucket = ANY($1::text[])', [[emailBucket, ipBucket]]);
}

export function registerAuthRoutes(app: FastifyInstance, db: Pool, jwtConfig: JwtConfig) {
  // Register a new user
  app.post<{ Body: RegisterBody }>('/v1/auth/register', async (request, reply) => {
    const { email, password } = request.body;

    if (!email || !password) {
      throw new ValidationError('email and password are required');
    }
    if (password.length < 8) {
      throw new ValidationError('password must be at least 8 characters');
    }

    const normalizedEmail = normalizeEmail(email);

    const existing = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      throw new ValidationError('A user with this email already exists');
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [normalizedEmail, passwordHash]
    );

    const user = result.rows[0];
    const token = signJwt({ sub: user.id, email: user.email }, jwtConfig, '24h');

    return reply.code(201).send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });

  // Login — returns JWT directly, or a short-lived totp_token if 2FA is enabled
  app.post<{ Body: LoginBody }>('/v1/auth/login', async (request, reply) => {
    const { email, password } = request.body;

    if (!email || !password) {
      throw new ValidationError('email and password are required');
    }

    const normalizedEmail = normalizeEmail(email);
    const { emailBucket, ipBucket } = getLoginBuckets(normalizedEmail, request.ip);

    await assertNotLocked(db, [emailBucket, ipBucket]);

    const result = await db.query(
      'SELECT id, email, password_hash, created_at, totp_enabled FROM users WHERE email = $1',
      [normalizedEmail]
    );
    if (result.rows.length === 0) {
      await recordLoginFailure(db, emailBucket, ipBucket);
      throw new AuthenticationError('Invalid email or password');
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await recordLoginFailure(db, emailBucket, ipBucket);
      throw new AuthenticationError('Invalid email or password');
    }

    await clearLoginFailures(db, emailBucket, ipBucket);

    // If 2FA is enabled, return a short-lived TOTP token instead of a full JWT
    if (user.totp_enabled) {
      const totpToken = signJwt({ sub: user.id, email: user.email, purpose: 'totp_verify' }, jwtConfig, TOTP_TOKEN_EXPIRY);
      return reply.send({
        requires_totp: true,
        totp_token: totpToken,
      });
    }

    const token = signJwt({ sub: user.id, email: user.email }, jwtConfig, '24h');

    return reply.send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });

  // Verify TOTP code to complete login
  app.post<{ Body: VerifyTotpBody }>('/v1/auth/verify-totp', async (request, reply) => {
    const { totp_token, code } = request.body;

    if (!totp_token || !code) {
      throw new ValidationError('totp_token and code are required');
    }

    let payload: { sub: string; email: string; purpose?: string };
    try {
      payload = jwt.verify(totp_token, jwtConfig.secret, {
        algorithms: ['HS256'],
        issuer: jwtConfig.issuer,
        audience: jwtConfig.audience,
      }) as typeof payload;
    } catch {
      throw new AuthenticationError('Invalid or expired TOTP token. Please log in again.');
    }

    if (payload.purpose !== 'totp_verify') {
      throw new AuthenticationError('Invalid token type');
    }

    const result = await db.query(
      'SELECT id, email, created_at, totp_secret, totp_iv, totp_auth_tag FROM users WHERE id = $1',
      [payload.sub]
    );
    if (result.rows.length === 0) {
      throw new AuthenticationError('User not found');
    }

    const user = result.rows[0];
    const secret = decrypt(user.totp_secret, user.totp_iv, user.totp_auth_tag);

    const totp = new OTPAuth.TOTP({
      issuer: 'BlindKey',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({ token: code, window: 1 });
    if (delta === null) {
      throw new AuthenticationError('Invalid TOTP code');
    }

    const token = signJwt({ sub: user.id, email: user.email }, jwtConfig, '24h');

    return reply.send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });

  // Begin TOTP setup — returns the otpauth URI for QR code generation
  // Requires JWT auth (user must be logged in)
  app.post('/v1/auth/setup-totp', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query('SELECT email, totp_enabled FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      throw new AuthenticationError('User not found');
    }

    const user = result.rows[0];
    if (user.totp_enabled) {
      throw new ValidationError('TOTP is already enabled. Disable it first to reconfigure.');
    }

    // Generate a new TOTP secret
    const secret = new OTPAuth.Secret({ size: 20 });
    const totp = new OTPAuth.TOTP({
      issuer: 'BlindKey',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    // Encrypt and store the secret (not yet enabled — user must confirm with a code)
    const { encrypted, iv, authTag } = encrypt(secret.base32);

    await db.query(
      `UPDATE users SET totp_secret = $1, totp_iv = $2, totp_auth_tag = $3
       WHERE id = $4`,
      [encrypted, iv, authTag, userId]
    );

    return reply.send({
      otpauth_uri: totp.toString(),
      secret: secret.base32,
    });
  });

  // Confirm TOTP setup — user sends a code to prove they scanned the QR
  app.post<{ Body: SetupTotpBody }>('/v1/auth/confirm-totp', async (request, reply) => {
    const userId = request.userId!;
    const { code } = request.body;

    if (!code) {
      throw new ValidationError('code is required');
    }

    const result = await db.query(
      'SELECT totp_secret, totp_iv, totp_auth_tag, totp_enabled, email FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) {
      throw new AuthenticationError('User not found');
    }

    const user = result.rows[0];
    if (user.totp_enabled) {
      throw new ValidationError('TOTP is already enabled');
    }
    if (!user.totp_secret) {
      throw new ValidationError('No TOTP secret configured. Call setup-totp first.');
    }

    const secret = decrypt(user.totp_secret, user.totp_iv, user.totp_auth_tag);

    const totp = new OTPAuth.TOTP({
      issuer: 'BlindKey',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({ token: code, window: 1 });
    if (delta === null) {
      throw new AuthenticationError('Invalid TOTP code. Make sure your authenticator app is synced.');
    }

    await db.query('UPDATE users SET totp_enabled = true WHERE id = $1', [userId]);

    return reply.send({ totp_enabled: true });
  });

  // Disable TOTP — requires a valid TOTP code as confirmation
  app.post<{ Body: SetupTotpBody }>('/v1/auth/disable-totp', async (request, reply) => {
    const userId = request.userId!;
    const { code } = request.body;

    if (!code) {
      throw new ValidationError('code is required to disable TOTP');
    }

    const result = await db.query(
      'SELECT totp_secret, totp_iv, totp_auth_tag, totp_enabled, email FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) {
      throw new AuthenticationError('User not found');
    }

    const user = result.rows[0];
    if (!user.totp_enabled) {
      throw new ValidationError('TOTP is not enabled');
    }

    const secret = decrypt(user.totp_secret, user.totp_iv, user.totp_auth_tag);

    const totp = new OTPAuth.TOTP({
      issuer: 'BlindKey',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({ token: code, window: 1 });
    if (delta === null) {
      throw new AuthenticationError('Invalid TOTP code');
    }

    await db.query(
      'UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_iv = NULL, totp_auth_tag = NULL WHERE id = $1',
      [userId]
    );

    return reply.send({ totp_enabled: false });
  });

  // Check TOTP status (for the UI)
  app.get('/v1/auth/totp-status', async (request, reply) => {
    const userId = request.userId!;

    const result = await db.query('SELECT totp_enabled FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      throw new AuthenticationError('User not found');
    }

    return reply.send({ totp_enabled: result.rows[0].totp_enabled });
  });
}

