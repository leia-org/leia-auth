import express from 'express';
import { randomBytes } from 'node:crypto';
import User from '../models/User.js';
import logger from '../utils/logger.js';
import { generateSessionToken } from '../utils/jwt.js';
import { setSessionCookie } from '../utils/sessionCookie.js';
import { accessCookie, testLoginEnabled, testLoginReturnUrl, verifyAccessIdentity } from '../utils/cloudflareAccess.js';

const entryOrigin = 'https://test-login.leia.ovh';
const capabilityCookie = '__Host-leia_test_access';
const capabilityOptions = { secure: true, httpOnly: true, sameSite: 'lax', path: '/', maxAge: 24 * 60 * 60 * 1000 };
const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));

function preOnly(req, res, next) {
  res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'strict-origin', 'X-Content-Type-Options': 'nosniff' });
  if (!testLoginEnabled() || req.hostname !== 'pre.auth.leia.ovh') return res.sendStatus(404);
  next();
}

/** Establish an Access capability on the Auth host without selecting an application account. */
export function createTestLoginRouter({ verify = verifyAccessIdentity, audit = logger } = {}) {
  const router = express.Router();
  router.use(preOnly);
  router.use(express.urlencoded({ extended: false, limit: '24kb' }));
  router.use(async (req, res, next) => {
    try {
      req.accessIdentity = await verify(req.method === 'POST' ? req.body.accessAssertion : req.get('Cf-Access-Jwt-Assertion'));
      next();
    } catch { res.status(403).send('Sign in through Cloudflare Access to use test accounts.'); }
  });
  router.get('/', (req, res) => {
    try {
      const returnTo = testLoginReturnUrl(req.query.returnTo || 'https://pre.designer.leia.ovh/');
      const nonce = randomBytes(18).toString('base64');
      // Chromium also checks the final destination of a form's 303 redirect.
      const frontendOrigin = new URL(returnTo).origin;
      res.set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; form-action https://pre.auth.leia.ovh ${frontendOrigin}; frame-ancestors 'none'; base-uri 'none'`);
      res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LEIA pre access</title><style>body{margin:48px auto;padding:24px;max-width:480px;color:#17213b;font:16px system-ui,sans-serif}button{padding:12px 20px;border:0;border-radius:8px;background:#245cf5;color:white;font:inherit;cursor:pointer}</style></head><body><h1>Opening LEIA pre</h1><p>Your GitHub session has been verified. Continue to choose a test account in LEIA.</p><form id="access-login" method="post" action="https://pre.auth.leia.ovh/test-login"><input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}"><input type="hidden" name="accessAssertion" value="${escapeHtml(req.get('Cf-Access-Jwt-Assertion'))}"><button type="submit">Continue to LEIA</button></form><script nonce="${nonce}">document.getElementById('access-login').requestSubmit();</script></body></html>`);
    } catch { res.sendStatus(400); }
  });
  router.post('/', (req, res) => {
    try {
      if (req.get('Origin') !== entryOrigin) return res.sendStatus(403);
      const returnTo = testLoginReturnUrl(req.body.returnTo);
      res.cookie(capabilityCookie, req.body.accessAssertion, capabilityOptions);
      audit.info(`Pre test access authorized ${JSON.stringify({ actor: req.accessIdentity })}`);
      const login = new URL('/login', returnTo);
      login.searchParams.set('testAccount', '1');
      res.redirect(303, login.href);
    } catch { res.sendStatus(400); }
  });
  return router;
}

/** Only the verified Access capability can list accounts or create a test session. */
export function createTestAccountApi({ verify = verifyAccessIdentity, users = User, audit = logger } = {}) {
  const router = express.Router();
  router.use(preOnly);
  router.use(async (req, res, next) => {
    try { req.accessIdentity = await verify(accessCookie(req, capabilityCookie)); next(); }
    catch { res.status(403).json({ message: 'A valid Cloudflare Access session is required.' }); }
  });
  router.get('/accounts', async (req, res, next) => {
    try {
      const query = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 120) : '';
      const filter = query ? { email: { $regex: query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } } : {};
      const accounts = await users.find(filter).select('_id email role').sort({ email: 1 }).limit(100).lean();
      res.json(accounts.map(user => ({ id: String(user._id), email: user.email, role: user.role })));
    } catch (error) { next(error); }
  });
  router.post('/session', async (req, res, next) => {
    try {
      // A JSON-only request from an allowed pre frontend prevents cross-site form CSRF.
      try { testLoginReturnUrl(`${req.get('Origin')}/`); } catch { return res.sendStatus(403); }
      if (!req.is('application/json')) return res.sendStatus(403);
      if (typeof req.body?.accountId !== 'string' || !/^[a-f0-9]{24}$/i.test(req.body.accountId)) return res.sendStatus(400);
      const user = await users.findById(req.body.accountId).select('_id email role').lean();
      if (!user) return res.sendStatus(404);
      audit.info(`Pre test account login ${JSON.stringify({ actor: req.accessIdentity, targetUserId: String(user._id), targetEmail: user.email })}`);
      setSessionCookie(res, generateSessionToken({ id: String(user._id), email: user.email, role: user.role }));
      res.sendStatus(204);
    } catch (error) { next(error); }
  });
  return router;
}

export async function testLoginStatus(req, res) {
  res.set('Cache-Control', 'no-store');
  if (!testLoginEnabled() || req.hostname !== 'pre.auth.leia.ovh') return res.status(404).json({ enabled: false });
  let authenticated = false;
  try { await verifyAccessIdentity(accessCookie(req, capabilityCookie)); authenticated = true; } catch { /* The public login stays available. */ }
  res.json({ enabled: true, authenticated, mode: 'modal', url: entryOrigin });
}
