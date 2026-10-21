import { beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { accessCookie, testLoginEnabled, testLoginReturnUrl, verifyAccessIdentity } from '../src/utils/cloudflareAccess.js';

const env = { LEIA_ENVIRONMENT: 'pre', PRE_TEST_LOGIN_ENABLED: 'true',
  CLOUDFLARE_ACCESS_TEAM_DOMAIN: 'leia-test.cloudflareaccess.com', CLOUDFLARE_ACCESS_TEST_LOGIN_AUD: 'a'.repeat(64) };
let privateKey, keySet;
beforeAll(async () => {
  const pair = await generateKeyPair('RS256'); privateKey = pair.privateKey;
  keySet = createLocalJWKSet({ keys: [{ ...await exportJWK(pair.publicKey), kid: 'test', alg: 'RS256', use: 'sig' }] });
});
const sign = async (claims = {}, header = {}) => new SignJWT({ email: 'member@example.org', type: 'app', ...claims })
  .setProtectedHeader({ alg: 'RS256', kid: 'test', ...header }).setSubject('github-user')
  .setIssuer(`https://${env.CLOUDFLARE_ACCESS_TEAM_DOMAIN}`).setAudience(env.CLOUDFLARE_ACCESS_TEST_LOGIN_AUD)
  .setIssuedAt().setExpirationTime('1h');
const verify = token => verifyAccessIdentity(token, { env, keySet });
describe('Access assertion validation', () => {
  it('accepts a correctly signed app token for this application', async () => {
    const token = await (await sign()).sign(privateKey);
    expect(await verify(token)).toEqual({ subject: 'github-user', email: 'member@example.org' });
  });
  it('rejects wrong issuer, audience, expired and future tokens', async () => {
    for (const mutate of [jwt => jwt.setIssuer('https://other.cloudflareaccess.com'), jwt => jwt.setAudience('other'),
      jwt => jwt.setExpirationTime(1), jwt => jwt.setNotBefore('1h')]) {
      await expect(verify(await mutate(await sign()).sign(privateKey))).rejects.toThrow();
    }
  });
  it('rejects missing identity, service tokens, unknown keys, altered signatures and HS256 tokens', async () => {
    for (const claims of [{ email: null }, { type: 'service' }]) await expect(verify(await (await sign(claims)).sign(privateKey))).rejects.toThrow();
    await expect(verify(await (await sign({}, { kid: 'untrusted' })).sign(privateKey))).rejects.toThrow();
    const other = await generateKeyPair('RS256');
    await expect(verify(await (await sign()).sign(other.privateKey))).rejects.toThrow();
    const hs = await new SignJWT({ email: 'attacker@example.org', type: 'app' }).setProtectedHeader({ alg: 'HS256' })
      .setIssuer(`https://${env.CLOUDFLARE_ACCESS_TEAM_DOMAIN}`).setAudience(env.CLOUDFLARE_ACCESS_TEST_LOGIN_AUD)
      .setSubject('attacker').setIssuedAt().setExpirationTime('1h').sign(new Uint8Array(32));
    await expect(verify(hs)).rejects.toThrow();
  });
  it('fails closed in production, previews, local and incomplete configurations', async () => {
    for (const changed of [{ LEIA_ENVIRONMENT: 'production' }, { LEIA_ENVIRONMENT: 'preview' }, { LEIA_ENVIRONMENT: 'local' },
      { PRE_TEST_LOGIN_ENABLED: 'false' }, { CLOUDFLARE_ACCESS_TEAM_DOMAIN: 'evil.org' }, { CLOUDFLARE_ACCESS_TEST_LOGIN_AUD: '' }]) {
      expect(testLoginEnabled({ ...env, ...changed })).toBe(false);
      await expect(verifyAccessIdentity(await (await sign()).sign(privateKey), { env: { ...env, ...changed }, keySet })).rejects.toThrow();
    }
  });
});
it('only returns to pre frontend entry points', () => {
  for (const value of ['https://pre.designer.leia.ovh/', 'https://pre-97.designer.leia.ovh/', 'https://pre.workbench.leia.ovh/administration']) expect(testLoginReturnUrl(value)).toBe(value);
  for (const value of ['https://designer.leia.ovh/', 'https://pre.designer.leia.ovh.evil.org/', 'https://evil.org/',
    'http://pre.designer.leia.ovh/', 'https://user@pre.designer.leia.ovh/', 'https://pre.designer.leia.ovh/?next=evil',
    'https://pre.designer.leia.ovh/administration', 'https://pre-0.designer.leia.ovh/', '//evil.org']) expect(() => testLoginReturnUrl(value)).toThrow();
});
it('handles malformed cookies without trusting their contents', () => {
  expect(accessCookie({ headers: { cookie: 'CF_Authorization=%broken' } })).toBeUndefined();
  expect(accessCookie({ headers: { cookie: 'a=b; CF_Authorization=token' } })).toBe('token');
});
