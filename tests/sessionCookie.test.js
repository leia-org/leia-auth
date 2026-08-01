import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  clearSessionCookie,
  getSessionCookieOptions,
  readSessionCookie,
  setSessionCookie,
} from '../src/utils/sessionCookie.js';

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

describe('central Auth session cookie', () => {
  test('is host-only, HttpOnly and environment configurable', () => {
    process.env.NODE_ENV = 'production';
    process.env.SESSION_COOKIE_NAME = '__Host-leia_session';
    process.env.SESSION_COOKIE_MAX_AGE_SECONDS = '600';
    delete process.env.SESSION_COOKIE_DOMAIN;

    expect(getSessionCookieOptions()).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 600000,
    });
  });

  test('reads only the configured cookie', () => {
    process.env.SESSION_COOKIE_NAME = 'leia_session_pre';
    const req = {
      headers: { cookie: 'leia_session_prod=wrong; leia_session_pre=correct%2Ejwt' },
    };

    expect(readSessionCookie(req)).toBe('correct.jwt');
  });

  test('sets and clears the same cookie attributes', () => {
    process.env.SESSION_COOKIE_NAME = 'leia_session';
    process.env.SESSION_COOKIE_SECURE = 'false';
    const res = { cookie: vi.fn(), clearCookie: vi.fn() };

    setSessionCookie(res, 'session-jwt');
    clearSessionCookie(res);

    expect(res.cookie).toHaveBeenCalledWith(
      'leia_session',
      'session-jwt',
      expect.objectContaining({ httpOnly: true, secure: false, maxAge: 86400000 }),
    );
    expect(res.clearCookie).toHaveBeenCalledWith(
      'leia_session',
      expect.not.objectContaining({ maxAge: expect.anything() }),
    );
  });
});
