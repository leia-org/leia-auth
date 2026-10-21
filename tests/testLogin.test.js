import express from 'express';
import { request as httpRequest } from 'node:http';
import { afterAll, beforeAll, afterEach, expect, it, vi } from 'vitest';
import { createTestLoginRouter, testLoginStatus } from '../src/routes/testLogin.js';
import { verifyToken } from '../src/utils/jwt.js';

const id = '0123456789abcdef01234567';
const user = { _id: id, email: 'test@example.org', role: 'admin', password: 'never-return', apiKeys: [{ keyValue: 'never-return' }] };
const leanUser = { _id: id, email: user.email, role: user.role };
const find = vi.fn(() => ({ select: vi.fn(() => ({ sort: () => ({ limit: () => ({ lean: async () => [leanUser] }) }) })) }));
const findById = vi.fn(() => ({ select: () => ({ lean: async () => leanUser }) }));
const audit = { info: vi.fn() };
const verify = vi.fn(async token => { if (token !== 'valid') throw Error('invalid'); return { subject: 'github-member', email: 'member@example.org' }; });
let server, base;
beforeAll(async () => {
  vi.stubEnv('LEIA_ENVIRONMENT', 'pre'); vi.stubEnv('PRE_TEST_LOGIN_ENABLED', 'true');
  vi.stubEnv('CLOUDFLARE_ACCESS_TEAM_DOMAIN', 'leia-test.cloudflareaccess.com');
  vi.stubEnv('CLOUDFLARE_ACCESS_TEST_LOGIN_AUD', 'a'.repeat(64)); vi.stubEnv('JWT_SECRET', 'test-key');
  const app = express(); app.get('/api/v1/test-login/status', testLoginStatus);
  app.use('/test-login', createTestLoginRouter({ verify, users: { find, findById }, audit }));
  server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
afterAll(async () => { await new Promise(resolve => server.close(resolve)); vi.unstubAllEnvs(); });
afterEach(() => { vi.clearAllMocks(); });
const request = (path, options = {}) => new Promise((resolve, reject) => {
  const body = options.body?.toString();
  const req = httpRequest(base + path, { method: options.method || 'GET',
    headers: { host: 'pre.auth.leia.ovh', ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}), ...options.headers } }, res => {
    const parts = []; res.on('data', chunk => parts.push(chunk));
    res.on('end', () => resolve(new Response(Buffer.concat(parts), { status: res.statusCode,
      headers: Object.entries(res.headers).flatMap(([name, value]) => (Array.isArray(value) ? value : [value]).map(item => [name, item])) })));
  });
  req.on('error', reject); req.end(body);
});
it('discloses no accounts without a valid Access assertion, even with a spoofed identity header', async () => {
  const response = await request('/test-login', { headers: { 'Cf-Access-Authenticated-User-Email': 'member@example.org' } });
  expect(response.status).toBe(403); expect(find).not.toHaveBeenCalled();
});
it('lists only projected account fields and escapes HTML', async () => {
  const response = await request('/test-login', { headers: { 'Cf-Access-Jwt-Assertion': 'valid' } });
  const html = await response.text(); expect(response.status).toBe(200);
  expect(find.mock.results[0].value.select).toHaveBeenCalledWith('_id email role');
  expect(html).toContain(user.email); expect(html).not.toContain('never-return');
  expect(response.headers.get('Cache-Control')).toBe('no-store');
  expect(response.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
});
it('requires the protected entry origin and a valid assertion before issuing a session', async () => {
  for (const [origin, assertion] of [['https://evil.org', 'valid'], ['https://test-login.leia.ovh', 'forged']]) {
    const response = await request('/test-login', { method: 'POST', headers: { Origin: origin },
      body: new URLSearchParams({ accountId: id, returnTo: 'https://pre.designer.leia.ovh/', accessAssertion: assertion }) });
    expect(response.status).toBe(403); expect(response.headers.get('Set-Cookie')).toBeNull();
  }
  expect(findById).not.toHaveBeenCalled();
});
it('issues an HttpOnly pre session, records actor and target and redirects without URL tokens', async () => {
  const response = await request('/test-login', { method: 'POST', headers: { Origin: 'https://test-login.leia.ovh' },
    body: new URLSearchParams({ accountId: id, returnTo: 'https://pre.designer.leia.ovh/', accessAssertion: 'valid' }) });
  expect(response.status).toBe(303); expect(response.headers.get('Location')).toBe('https://pre.designer.leia.ovh/');
  const cookie = response.headers.get('Set-Cookie'); expect(cookie).toContain('HttpOnly');
  const token = cookie.match(/leia_session=([^;]+)/)[1];
  expect(verifyToken(token)).toMatchObject({ id, email: user.email, role: 'admin', type: 'session' });
  expect(audit.info).toHaveBeenCalledWith(expect.stringContaining('github-member'));
  expect(audit.info).toHaveBeenCalledWith(expect.stringContaining(id));
  expect(audit.info.mock.calls[0][0]).not.toContain('valid');
});
it('rejects production redirects and invalid account IDs', async () => {
  for (const [accountId, returnTo] of [[id, 'https://designer.leia.ovh/'], ['{$ne:null}', 'https://pre.designer.leia.ovh/']]) {
    const response = await request('/test-login', { method: 'POST', headers: { Origin: 'https://test-login.leia.ovh' },
      body: new URLSearchParams({ accountId, returnTo, accessAssertion: 'valid' }) });
    expect(response.status).toBe(400); expect(response.headers.get('Set-Cookie')).toBeNull();
  }
});
it('keeps public status anonymous and disables every test endpoint in production', async () => {
  const publicStatus = await request('/api/v1/test-login/status'); expect(await publicStatus.json()).toMatchObject({ enabled: true, authenticated: false });
  vi.stubEnv('LEIA_ENVIRONMENT', 'production');
  try {
    for (const path of ['/test-login', '/api/v1/test-login/status']) expect((await request(path)).status).toBe(404);
    expect(find).not.toHaveBeenCalled();
  } finally { vi.stubEnv('LEIA_ENVIRONMENT', 'pre'); }
});
