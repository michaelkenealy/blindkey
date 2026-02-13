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

const SALT_ROUNDS = 12;

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

    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      throw new ValidationError('A user with this email already exists');
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, passwordHash]
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

    const result = await db.query('SELECT id, email, password_hash, created_at FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      throw new AuthenticationError('Invalid email or password');
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      throw new AuthenticationError('Invalid email or password');
    }

    const token = jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: '24h' });

    return reply.send({
      user: { id: user.id, email: user.email, created_at: user.created_at },
      token,
    });
  });
}
