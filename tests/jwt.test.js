import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import jwt from 'jsonwebtoken';
import { generateSessionToken, generateToken, verifyToken } from '../src/utils/jwt.js';

const originalEnv = { ...process.env };

beforeEach(() => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_ISSUER = 'https://auth.leia.ovh';
  process.env.JWT_AUDIENCE = 'leia-platform';
});

afterEach(() => {
  process.env = { ...originalEnv };
});

describe('environment-isolated JWTs', () => {
  const user = { id: 'user-1', email: 'user@leia.ovh', role: 'advanced' };

  test('creates a short-lived access token with issuer and audience', () => {
    const payload = verifyToken(generateToken(user));

    expect(payload).toMatchObject({
      id: user.id,
      email: user.email,
      role: user.role,
      type: 'access',
      iss: 'https://auth.leia.ovh',
      aud: 'leia-platform',
    });
  });

  test('creates a distinct central session token', () => {
    const payload = verifyToken(generateSessionToken(user));

    expect(payload).toMatchObject({
      id: user.id,
      role: user.role,
      type: 'session',
      iss: 'https://auth.leia.ovh',
      aud: 'leia-platform',
    });
  });

  test('rejects a token issued by preproduction', () => {
    const preToken = jwt.sign(
      { id: user.id, role: user.role, type: 'access' },
      process.env.JWT_SECRET,
      {
        issuer: 'https://pre.auth.leia.ovh',
        audience: process.env.JWT_AUDIENCE,
        expiresIn: '15m',
      },
    );

    expect(() => verifyToken(preToken)).toThrow();
  });
});
