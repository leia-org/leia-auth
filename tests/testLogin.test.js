import express from 'express';
import { request as httpRequest } from 'node:http';
import { afterAll, beforeAll, afterEach, expect, it, vi } from 'vitest';
import { createTestLoginRouter, createTestAccountApi, testLoginStatus } from '../src/routes/testLogin.js';
import { verifyToken } from '../src/utils/jwt.js';

const id = '0123456789abcdef01234567';
const user = { _id: id, email: 'test@example.org', role: 'admin' };
const find = vi.fn(() => ({ select: vi.fn(() => ({ sort: () => ({ limit: () => ({ lean: async () => [user] }) }) })) }));
const findById = vi.fn(() => ({ select: () => ({ lean: async () => user }) }));
const audit = { info: vi.fn() };
const verify = vi.fn(async token => { if (token !== 'valid') throw Error('invalid'); return { subject: 'github-member', email: 'member@example.org' }; });
let server, base;
beforeAll(async () => {
  vi.stubEnv('LEIA_ENVIRONMENT', 'pre'); vi.stubEnv('PRE_TEST_LOGIN_ENABLED', 'true');
  vi.stubEnv('CLOUDFLARE_ACCESS_TEAM_DOMAIN', 'leia-test.cloudflareaccess.com');
  vi.stubEnv('CLOUDFLARE_ACCESS_TEST_LOGIN_AUD', 'a'.repeat(64)); vi.stubEnv('JWT_SECRET', 'test-key');
  const app = express(); app.use(express.json()); app.get('/api/v1/test-login/status', testLoginStatus);
  app.use('/test-login', createTestLoginRouter({ verify, audit }));
  app.use('/api/v1/test-login', createTestAccountApi({ verify, users: { find, findById }, audit }));
  server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
afterAll(async () => { await new Promise(resolve => server.close(resolve)); vi.unstubAllEnvs(); });
afterEach(() => { vi.clearAllMocks(); });
const request = (path, options = {}) => new Promise((resolve, reject) => {
  const body = options.body?.toString();
  const req = httpRequest(base + path, { method: options.method || 'GET', headers: {
    host: 'pre.auth.leia.ovh', ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}), ...options.headers,
  } }, res => {
    const parts = []; res.on('data', chunk => parts.push(chunk));
    res.on('end', () => resolve(new Response(res.statusCode === 204 ? null : Buffer.concat(parts), { status: res.statusCode,
      headers: Object.entries(res.headers).flatMap(([name, value]) => (Array.isArray(value) ? value : [value]).map(item => [name, item])) })));
  });
  req.on('error', reject); req.end(body);
});
const capability = { Cookie: '__Host-leia_test_access=valid' };
const session = (accountId = id, origin = 'https://pre.designer.leia.ovh', contentType = 'application/json') => request('/api/v1/test-login/session', {
  method: 'POST', headers: { ...capability, Origin: origin, 'Content-Type': contentType }, body: JSON.stringify({ accountId }),
});

it('requires a real Access assertion on the identity bridge and ignores spoofed identity headers', async () => {
  const response = await request('/test-login', { headers: { 'Cf-Access-Authenticated-User-Email': 'member@example.org' } });
  expect(response.status).toBe(403); expect(find).not.toHaveBeenCalled();
});
it('forwards a verified assertion only in a protected form body, with a nonce script and preserved Origin', async () => {
  const response = await request('/test-login', { headers: { 'Cf-Access-Jwt-Assertion': 'valid' } });
  const html = await response.text(); expect(response.status).toBe(200); expect(find).not.toHaveBeenCalled();
  expect(html).toContain('method="post" action="https://pre.auth.leia.ovh/test-login"');
  expect(html).not.toContain(user.email); expect(response.headers.get('Cache-Control')).toBe('no-store');
  expect(response.headers.get('Referrer-Policy')).toBe('strict-origin');
  const nonce = html.match(/<script nonce="([^"]+)"/)[1];
  expect(response.headers.get('Content-Security-Policy')).toContain(`script-src 'nonce-${nonce}'`);
  expect(response.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
  expect(response.headers.get('Content-Security-Policy')).toContain('form-action https://pre.auth.leia.ovh https://pre.designer.leia.ovh;');
});
it('allows the validated Workbench redirect destination without widening form destinations', async () => {
  const response = await request('/test-login?returnTo=https%3A%2F%2Fpre-88.workbench.leia.ovh%2Fadministration', { headers: { 'Cf-Access-Jwt-Assertion': 'valid' } });
  expect(response.status).toBe(200);
  expect(response.headers.get('Content-Security-Policy')).toContain('form-action https://pre.auth.leia.ovh https://pre-88.workbench.leia.ovh;');
  const invalid = await request('/test-login?returnTo=https%3A%2F%2Fevil.org%2F', { headers: { 'Cf-Access-Jwt-Assertion': 'valid' } });
  expect(invalid.status).toBe(400);
});
it('rejects untrusted Origins and assertions before creating the Access capability', async () => {
  for (const [origin, assertion] of [['https://evil.org', 'valid'], ['https://test-login.leia.ovh', 'forged']]) {
    const response = await request('/test-login', { method: 'POST', headers: { Origin: origin },
      body: new URLSearchParams({ returnTo: 'https://pre.designer.leia.ovh/', accessAssertion: assertion }) });
    expect(response.status).toBe(403); expect(response.headers.get('Set-Cookie')).toBeNull();
  }
});
it('creates only an Access capability and opens the frontend modal without choosing an app account', async () => {
  const response = await request('/test-login', { method: 'POST', headers: { Origin: 'https://test-login.leia.ovh' },
    body: new URLSearchParams({ returnTo: 'https://pre.designer.leia.ovh/', accessAssertion: 'valid' }) });
  expect(response.status).toBe(303); expect(response.headers.get('Location')).toBe('https://pre.designer.leia.ovh/login?testAccount=1');
  const cookie = response.headers.get('Set-Cookie'); expect(cookie).toContain('__Host-leia_test_access=valid;');
  expect(cookie).toContain('HttpOnly'); expect(cookie).toContain('Secure'); expect(cookie).not.toContain('Domain=');
  expect(cookie).not.toContain('leia_session='); expect(findById).not.toHaveBeenCalled();
});
it('requires the Access capability for private accounts even if an app session or identity header is supplied', async () => {
  for (const headers of [{}, { Cookie: 'leia_session=valid' }, { 'Cf-Access-Jwt-Assertion': 'valid' }]) {
    expect((await request('/api/v1/test-login/accounts', { headers })).status).toBe(403);
  }
  expect(find).not.toHaveBeenCalled();
});
it('returns only IDs, emails and roles to the verified member and treats search as a literal', async () => {
  const response = await request('/api/v1/test-login/accounts?q=%2E%2A', { headers: capability });
  expect(response.status).toBe(200); expect(await response.json()).toEqual([{ id, email: user.email, role: 'admin' }]);
  expect(find).toHaveBeenCalledWith({ email: { $regex: '\\.\\*', $options: 'i' } });
  expect(find.mock.results[0].value.select).toHaveBeenCalledWith('_id email role');
});
it('requires JSON from a pre frontend, and denies production, cross-site and null Origins', async () => {
  for (const origin of ['https://evil.org', 'https://designer.leia.ovh', 'null']) expect((await session(id, origin)).status).toBe(403);
  expect((await session(id, 'https://pre.designer.leia.ovh', 'application/x-www-form-urlencoded')).status).toBe(403);
  expect(findById).not.toHaveBeenCalled();
});
it('creates the selected pre session with an audit record and returns no tokens to JavaScript', async () => {
  const response = await session(); expect(response.status).toBe(204); expect(await response.text()).toBe('');
  const cookie = response.headers.get('Set-Cookie'); expect(cookie).toContain('HttpOnly');
  const token = cookie.match(/leia_session=([^;]+)/)[1];
  expect(verifyToken(token)).toMatchObject({ id, email: user.email, role: 'admin', type: 'session' });
  expect(audit.info).toHaveBeenCalledWith(expect.stringContaining('github-member'));
  expect(audit.info).toHaveBeenCalledWith(expect.stringContaining(id));
  expect(audit.info.mock.calls[0][0]).not.toContain('valid');
});
it('rejects invalid IDs and stale selected accounts without issuing cookies', async () => {
  expect((await session('{$ne:null}')).status).toBe(400);
  findById.mockImplementationOnce(() => ({ select: () => ({ lean: async () => null }) }));
  const response = await session(); expect(response.status).toBe(404); expect(response.headers.get('Set-Cookie')).toBeNull();
});
it('keeps public status anonymous and disables all test endpoints in production', async () => {
  const status = await request('/api/v1/test-login/status'); expect(await status.json()).toMatchObject({ enabled: true, authenticated: false, mode: 'modal' });
  vi.stubEnv('LEIA_ENVIRONMENT', 'production');
  try {
    for (const path of ['/test-login', '/api/v1/test-login/status', '/api/v1/test-login/accounts']) expect((await request(path)).status).toBe(404);
    expect(find).not.toHaveBeenCalled();
  } finally { vi.stubEnv('LEIA_ENVIRONMENT', 'pre'); }
});
