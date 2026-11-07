import { afterAll, beforeAll, expect, test, vi } from 'vitest';
import express from 'express';
import User from '../../src/models/User.js';
import userRoutes from '../../src/routes/v1/userRoutes.js';
import apiKeyRoutes from '../../src/routes/v1/apiKeyRoutes.js';
import { auth } from '../../src/middlewares/auth.js';
import errorHandler from '../../src/middlewares/errorHandler.js';
import { connectMongo, closeMongo, listen } from './support.js';

let http, runner, owner, other;
const revocations = [];
const password = 'Integration-password-114';
const keyPayload = (description) => ({ description, provider: 'ollama', model: 'fixture-model', keyValue: `local-secret-${description}`, baseUrl: 'http://127.0.0.1:11434', isActive: true, isDefault: false });
const request = (path, method = 'GET', body, token) => fetch(`${http.url}/api/v1${path}`, {
  method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  ...(body ? { body: JSON.stringify(body) } : {}),
});
async function login(user, candidatePassword = password) {
  return request('/users/login', 'POST', { email: user.email, password: candidatePassword });
}

beforeAll(async () => {
  vi.stubEnv('JWT_SECRET', 'integration-signing-secret');
  vi.stubEnv('JWT_ISSUER', ''); vi.stubEnv('JWT_AUDIENCE', '');
  vi.stubEnv('TURNSTILE_ENABLED', 'false');
  vi.stubEnv('API_KEY_STORAGE_SECRET', 'ab'.repeat(32));
  vi.stubEnv('INTERN_TOKEN', 'integration-intern');
  vi.stubEnv('RUNNER_KEY', 'integration-runner');
  await connectMongo();
  await User.init();
  owner = await User.create({ email: 'owner@example.com', password, role: 'instructor' });
  other = await User.create({ email: 'other@example.com', password, role: 'instructor' });
  const peer = express(); peer.use(express.json());
  peer.post('/api/v1/revoke', (req, res) => { revocations.push({ ...req.body, authorization: req.headers.authorization }); res.sendStatus(204); });
  runner = await listen(peer);
  vi.stubEnv('RUNNER_URL', runner.url);
  const app = express(); app.use(express.json(), auth);
  app.use('/api/v1/users', userRoutes); app.use('/api/v1/apikeys', apiKeyRoutes); app.use(errorHandler);
  http = await listen(app);
});
afterAll(async () => {
  await http?.close(); await runner?.close(); await closeMongo(); vi.unstubAllEnvs();
});

test('login uses the stored password hash, issues a session cookie, refreshes an access token and clears the cookie on logout', async () => {
  expect((await User.findById(owner.id)).password).not.toBe(password);
  expect((await login(owner, 'wrong-password')).status).toBe(401);
  const res = await login(owner);
  expect(res.status).toBe(200);
  expect((await res.json()).token).toEqual(expect.any(String));
  const cookie = res.headers.get('set-cookie');
  expect(cookie).toContain('HttpOnly');
  const session = await fetch(`${http.url}/api/v1/users/session`, { headers: { Cookie: cookie.split(';')[0] } });
  expect(session.status).toBe(200);
  expect((await session.json()).token).toEqual(expect.any(String));
  const logout = await request('/users/logout', 'POST');
  expect(logout.status).toBe(204);
  expect(logout.headers.get('set-cookie')).toContain('Expires=Thu, 01 Jan 1970');
});

test('key creation, default switching, encrypted persistence, ownership and deletion work through the real API and MongoDB', async () => {
  const token = (await (await login(owner)).json()).token;
  const otherToken = (await (await login(other)).json()).token;
  const firstResponse = await request('/apikeys', 'POST', keyPayload('first'), token);
  expect(firstResponse.status).toBe(201);
  const first = await firstResponse.json();
  expect(first.isDefault).toBe(true);
  expect(first.keyValue).not.toBe(keyPayload('first').keyValue);
  const secondResponse = await request('/apikeys', 'POST', keyPayload('second'), token);
  expect(secondResponse.status).toBe(201);
  const second = await secondResponse.json();
  const stored = await User.findById(owner.id);
  expect(stored.apiKeys).toHaveLength(2);
  expect(stored.apiKeys[0].keyValue).toMatch(/^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
  expect((await request(`/apikeys/${first.id}`, 'GET', undefined, otherToken)).status).toBe(404);
  const switched = await request(`/apikeys/manage-default/${second.id}`, 'PUT', {}, token);
  expect(switched.status).toBe(200);
  const keys = await (await request('/apikeys', 'GET', undefined, token)).json();
  expect(keys.filter((key) => key.isDefault).map((key) => key.id)).toEqual([second.id]);
  const removed = await request(`/apikeys/${second.id}`, 'DELETE', undefined, token);
  expect(removed.status).toBe(204);
  const remaining = await (await request('/apikeys', 'GET', undefined, token)).json();
  expect(remaining.map((key) => key.id)).toEqual([first.id]);
  expect(remaining[0].isDefault).toBe(true);
  expect(revocations).toContainEqual({ apiKeyId: second.id, authorization: 'Bearer integration-runner' });
});
