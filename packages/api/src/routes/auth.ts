import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { ValidationError, AuthenticationError } from '@blindkey/core';

interface RegisterBody {
  email: string;
  password: string;
}

interface LoginBody {
  email: string;
  password: string;
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

export function registerAuthRoutes(app: FastifyInstance, db: Pool, jwtSecret: string) {
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
    const token = jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: '24h' });

    return reply.code(201).send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });

  // Login
  app.post<{ Body: LoginBody }>('/v1/auth/login', async (request, reply) => {
    const { email, password } = request.body;

    if (!email || !password) {
      throw new ValidationError('email and password are required');
    }

    const normalizedEmail = normalizeEmail(email);
    const { emailBucket, ipBucket } = getLoginBuckets(normalizedEmail, request.ip);

    await assertNotLocked(db, [emailBucket, ipBucket]);

    const result = await db.query('SELECT id, email, password_hash, created_at FROM users WHERE email = $1', [normalizedEmail]);
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

    const token = jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: '24h' });

    return reply.send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });
}
