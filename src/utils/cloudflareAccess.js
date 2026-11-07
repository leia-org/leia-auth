import { createRemoteJWKSet, jwtVerify } from 'jose';

let resolver;
let resolverIssuer;

export function testLoginEnabled(env = process.env) {
  return env.LEIA_ENVIRONMENT === 'pre' && env.PRE_TEST_LOGIN_ENABLED === 'true' &&
    /^[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.CLOUDFLARE_ACCESS_TEAM_DOMAIN || '') &&
    /^[a-f0-9]{64}$/.test(env.CLOUDFLARE_ACCESS_TEST_LOGIN_AUD || '');
}

export async function verifyAccessIdentity(token, { env = process.env, keySet } = {}) {
  if (!testLoginEnabled(env) || typeof token !== 'string' || token.length > 16384) {
    throw new Error('Access authentication unavailable');
  }
  const issuer = `https://${env.CLOUDFLARE_ACCESS_TEAM_DOMAIN}`;
  if (!keySet && (!resolver || resolverIssuer !== issuer)) {
    resolverIssuer = issuer;
    resolver = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), {
      timeoutDuration: 5000, cooldownDuration: 30000, cacheMaxAge: 10 * 60 * 1000,
    });
  }
  const { payload } = await jwtVerify(token, keySet || resolver, {
    issuer, audience: env.CLOUDFLARE_ACCESS_TEST_LOGIN_AUD,
    algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub', 'email'], clockTolerance: 5,
  });
  if (payload.type !== 'app' || typeof payload.email !== 'string' || !payload.email ||
      typeof payload.sub !== 'string' || !payload.sub) throw new Error('Invalid Access identity');
  return { subject: payload.sub, email: payload.email };
}

export function accessCookie(req, name = 'CF_Authorization') {
  const value = (req.headers.cookie || '').split(';').map(part => part.trim())
    .find(part => part.startsWith(`${name}=`))?.slice(name.length + 1);
  try { return value ? decodeURIComponent(value) : undefined; } catch { return undefined; }
}

export function testLoginReturnUrl(value) {
  if (typeof value !== 'string' || value.length > 256) throw new Error('Invalid return URL');
  const url = new URL(value);
  // Keep the browser return target fixed to the public pre frontend entry points.
  if (url.protocol !== 'https:' || url.port || url.username || url.password ||
      !/^(?:pre|pre-[1-9]\d*)\.(?:designer|workbench)\.leia\.ovh$/.test(url.hostname) ||
      !['/', '/administration'].includes(url.pathname) || url.search || url.hash) throw new Error('Invalid return URL');
  if (url.pathname === '/administration' && !url.hostname.endsWith('.workbench.leia.ovh')) throw new Error('Invalid return URL');
  return url.href;
}
