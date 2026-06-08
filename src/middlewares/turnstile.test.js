import { afterEach, describe, expect, it, vi } from 'vitest';
import axios from 'axios';
import { requireValidTurnstileToken } from './turnstile.js';

vi.mock('axios');
vi.mock('../utils/logger.js', () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
  },
}));

const createResponse = () => {
  const res = {};
  res.status = vi.fn(() => res);
  res.json = vi.fn(() => res);
  return res;
};

describe('requireValidTurnstileToken', () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
  });

  it('continues without validating when Turnstile is disabled', async () => {
    vi.stubEnv('TURNSTILE_ENABLED', 'false');
    const req = { body: { 'cf-turnstile-response': 'ignored-token', email: 'test@example.com' } };
    const res = createResponse();
    const next = vi.fn();

    await requireValidTurnstileToken(req, res, next);

    expect(axios.post).not.toHaveBeenCalled();
    expect(req.body).toEqual({ email: 'test@example.com' });
    expect(next).toHaveBeenCalledOnce();
  });

  it('rejects requests without a token', async () => {
    const req = { body: {}, headers: {} };
    const res = createResponse();
    const next = vi.fn();

    await requireValidTurnstileToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(axios.post).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('continues after a valid token and removes it from the body', async () => {
    vi.stubEnv('CLOUDFLARE_SECRET_KEY', 'secret');
    axios.post.mockResolvedValue({ data: { success: true } });
    const req = {
      body: { 'cf-turnstile-response': 'valid-token', email: 'test@example.com' },
      headers: { 'x-forwarded-for': '203.0.113.10, 198.51.100.1' },
      ip: '127.0.0.1',
    };
    const res = createResponse();
    const next = vi.fn();

    await requireValidTurnstileToken(req, res, next);

    expect(axios.post).toHaveBeenCalledWith(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        secret: 'secret',
        response: 'valid-token',
        remoteip: '203.0.113.10',
      },
      { timeout: 5000 }
    );
    expect(req.body).toEqual({ email: 'test@example.com' });
    expect(next).toHaveBeenCalledOnce();
  });

  it('rejects tokens rejected by Cloudflare', async () => {
    vi.stubEnv('CLOUDFLARE_SECRET_KEY', 'secret');
    axios.post.mockResolvedValue({
      data: { success: false, 'error-codes': ['timeout-or-duplicate'] },
    });
    const req = { body: { 'cf-turnstile-response': 'invalid-token' }, headers: {} };
    const res = createResponse();
    const next = vi.fn();

    await requireValidTurnstileToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns a temporary failure when Siteverify is unavailable', async () => {
    vi.stubEnv('CLOUDFLARE_SECRET_KEY', 'secret');
    axios.post.mockRejectedValue(new Error('network error'));
    const req = { body: { 'cf-turnstile-response': 'token' }, headers: {} };
    const res = createResponse();
    const next = vi.fn();

    await requireValidTurnstileToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(502);
    expect(next).not.toHaveBeenCalled();
  });
});
