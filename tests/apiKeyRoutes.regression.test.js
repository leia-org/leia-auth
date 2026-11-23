import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import express from 'express';
import jwt from 'jsonwebtoken';

// Keep the HTTP/auth/validation pipeline real; replace only service side effects.
vi.mock('../src/services/v1/ApiKeyService.js', () => ({ default: {
  getUserApiKeys: vi.fn(), getUserApiKeyById: vi.fn(), createSystemApiKey: vi.fn(),
} }));
vi.mock('../src/services/v1/ProviderService.js', () => ({ default: {
  verifyApiKeyIntegrity: vi.fn(),
} }));
vi.mock('../src/utils/logger.js', () => ({ default: { debug: vi.fn(), error: vi.fn() } }));

import ApiKeyService from '../src/services/v1/ApiKeyService.js';
import apiKeyRoutes from '../src/routes/v1/apiKeyRoutes.js';
import { auth } from '../src/middlewares/auth.js';
import errorHandler from '../src/middlewares/errorHandler.js';

let server, baseUrl;
const secret = 'regression-only-signing-secret';
const token = (role = 'instructor', extra = {}) => jwt.sign(
  { id: 'owner', role, type: 'access', ...extra }, secret, { expiresIn: '5m' },
);
const headers = (role) => ({ Authorization: `Bearer ${token(role)}` });
const request = (path = '', options = {}) => fetch(`${baseUrl}/api/v1/apikeys${path}`, options);

beforeAll(async () => {
  const app = express();
  app.use(express.json(), auth);
  app.use('/api/v1/apikeys', apiKeyRoutes);
  app.use(errorHandler);
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
afterAll(() => new Promise((resolve) => server.close(resolve)));
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv('JWT_SECRET', secret);
  vi.stubEnv('JWT_ISSUER', '');
  vi.stubEnv('JWT_AUDIENCE', '');
  vi.stubEnv('INTERN_TOKEN', 'regression-internal-secret');
  ApiKeyService.getUserApiKeys.mockResolvedValue([{ id: 'key', keyValue: '****1234' }]);
});
afterEach(() => vi.unstubAllEnvs());

describe('API key HTTP authorization regressions', () => {
  test.each(['instructor', 'advanced', 'admin'])('%s can list only their own keys', async (role) => {
    const res = await request('?userId=another-user', { headers: headers(role) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([{ id: 'key', keyValue: '****1234' }]);
    expect(ApiKeyService.getUserApiKeys).toHaveBeenCalledExactlyOnceWith('owner');
  });

  test.each([undefined, 'basic'])('rejects unauthenticated/basic key management (%s)', async (role) => {
    const res = await request('', { headers: role ? headers(role) : {} });
    expect(res.status).toBe(403);
    expect(ApiKeyService.getUserApiKeys).not.toHaveBeenCalled();
  });

  test.each([
    () => 'Bearer invalid.jwt.signature',
    () => `Bearer ${token('admin', { type: 'session' })}`,
    () => `Bearer ${jwt.sign({ id: 'owner', role: 'admin', type: 'access' }, secret, { expiresIn: -1 })}`,
  ])('rejects invalid, session, or expired bearer tokens before accessing keys', async (authorization) => {
    const res = await request('', { headers: { Authorization: authorization() } });
    expect(res.status).toBe(401);
    expect(ApiKeyService.getUserApiKeys).not.toHaveBeenCalled();
  });

  test.each(['instructor', 'advanced'])('%s cannot create a system key', async (role) => {
    const res = await request('/system', { method: 'POST', headers: headers(role) });
    expect(res.status).toBe(403);
    expect(ApiKeyService.createSystemApiKey).not.toHaveBeenCalled();
  });

  test.each([undefined, 'wrong-token'])('never exposes raw credentials without the internal token (%s)', async (internToken) => {
    const res = await request('/get-value', {
      method: 'POST', headers: { ...headers('admin'), ...(internToken ? { 'x-intern-token': internToken } : {}) },
    });
    expect(res.status).toBe(401);
    expect(ApiKeyService.getUserApiKeyById).not.toHaveBeenCalled();
  });

  test('resolves raw credentials and custom base URL only for the internal Runner call', async () => {
    ApiKeyService.getUserApiKeyById.mockResolvedValue({ provider: 'alma', keyValue: 'fixture-secret', baseUrl: 'https://alma.example/v1' });
    const res = await request('/get-value', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-intern-token': 'regression-internal-secret' },
      body: JSON.stringify({ provider: 'alma', apiKeyId: 'key', apiKeyRequesterId: 'requester' }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ keyValue: 'fixture-secret', baseUrl: 'https://alma.example/v1' });
    expect(ApiKeyService.getUserApiKeyById).toHaveBeenCalledExactlyOnceWith('requester', 'key', false);
  });

  test('does not disclose a key belonging to a different provider', async () => {
    ApiKeyService.getUserApiKeyById.mockResolvedValue({ provider: 'gemini', keyValue: 'fixture-secret' });
    const res = await request('/get-value', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-intern-token': 'regression-internal-secret' },
      body: JSON.stringify({ provider: 'openai', apiKeyId: 'key', apiKeyRequesterId: 'requester' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ message: 'API Key provider mismatch' });
  });
});
