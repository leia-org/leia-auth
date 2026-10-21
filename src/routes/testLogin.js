import express from 'express';
import User from '../models/User.js';
import logger from '../utils/logger.js';
import { generateSessionToken } from '../utils/jwt.js';
import { setSessionCookie } from '../utils/sessionCookie.js';
import { accessCookie, testLoginEnabled, testLoginReturnUrl, verifyAccessIdentity } from '../utils/cloudflareAccess.js';

const entryOrigin = 'https://test-login.leia.ovh';
const capabilityCookie = '__Secure-leia_test_access';
const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));

export function createTestLoginRouter({ verify = verifyAccessIdentity, users = User, audit = logger } = {}) {
  const router = express.Router();
  router.use((req, res, next) => {
    // Keep Origin on the cross-origin form POST without disclosing search/return parameters in Referer.
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'strict-origin', 'X-Content-Type-Options': 'nosniff' });
    if (!testLoginEnabled() || req.hostname !== 'pre.auth.leia.ovh') return res.sendStatus(404);
    next();
  });
  router.use(express.urlencoded({ extended: false, limit: '24kb' }));
  router.use(async (req, res, next) => {
    try {
      // Access injects this header only after applying the GitHub org policy. Verify it again at the origin.
      req.accessIdentity = await verify(req.method === 'POST' ? req.body.accessAssertion : req.get('Cf-Access-Jwt-Assertion'));
      next();
    } catch { res.status(403).send('Sign in through Cloudflare Access to use test accounts.'); }
  });
  router.get('/', async (req, res, next) => {
    try {
      const returnTo = testLoginReturnUrl(req.query.returnTo || 'https://pre.designer.leia.ovh/');
      const query = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 120) : '';
      const filter = query ? { email: { $regex: query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } } : {};
      const accounts = await users.find(filter).select('_id email role').sort({ email: 1 }).limit(100).lean();
      res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action https://test-login.leia.ovh https://pre.auth.leia.ovh; frame-ancestors 'none'; base-uri 'none'");
      const hidden = `<input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">`;
      res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LEIA pre test accounts</title><style>
        *{box-sizing:border-box}body{margin:0;background:#f6f7fb;color:#17213b;font:16px system-ui,sans-serif}main{max-width:680px;margin:6vh auto;padding:32px;background:white;border:1px solid #e0e4ec;border-radius:16px}h1{font-size:28px;margin:8px 0}p{line-height:1.5;color:#5d6578}.eyebrow{font-size:12px;font-weight:700;letter-spacing:.12em;color:#245cf5}label{display:block;margin:24px 0 8px;font-weight:600}input,select,button{font:inherit;border-radius:8px;padding:12px;border:1px solid #bbc3d3}input,select{width:100%;background:#fff}button{cursor:pointer;background:#245cf5;color:white;border:0;margin-top:16px}select{min-height:180px}a{color:#245cf5}footer{margin-top:24px;font-size:13px;color:#5d6578}@media(max-width:720px){main{margin:16px;padding:24px}}
        </style></head><body><main><div class="eyebrow">LEIA / PRE</div><h1>Choose a test account</h1><p>You are signed in as <strong>${escapeHtml(req.accessIdentity.email)}</strong> through GitHub. Choose an existing pre account to test its permissions.</p>
        <form method="get" action="https://test-login.leia.ovh/">${hidden}<label for="search">Find an account</label><input id="search" type="search" name="q" maxlength="120" value="${escapeHtml(query)}" placeholder="Search by email"><button type="submit">Search</button></form>
        <form method="post" action="https://pre.auth.leia.ovh/test-login">${hidden}<input type="hidden" name="accessAssertion" value="${escapeHtml(req.get('Cf-Access-Jwt-Assertion'))}"><label for="account">Pre account</label><select id="account" name="accountId" size="6" required aria-describedby="account-help">${accounts.map(account => `<option value="${escapeHtml(account._id)}">${escapeHtml(account.email)} (${escapeHtml(account.role)})</option>`).join('')}</select><p id="account-help">${accounts.length ? 'Up to 100 matches. Search to find another account.' : 'No accounts match your search.'}</p><button type="submit" ${accounts.length ? '' : 'disabled'}>Continue as selected account</button></form>
        <footer>This changes your session in pre. Your GitHub identity and selected account are recorded in the Auth audit log. <a href="${escapeHtml(new URL("/login?login=password", returnTo).href)}">Use the standard login</a></footer></main></body></html>`);
    } catch (error) {
      if (error.message === 'Invalid return URL' || error instanceof TypeError) return res.sendStatus(400);
      next(error);
    }
  });
  router.post('/', async (req, res, next) => {
    try {
      // Browser forms may only come from the protected chooser, and must carry its verified Access assertion.
      if (req.get('Origin') !== entryOrigin) return res.sendStatus(403);
      const returnTo = testLoginReturnUrl(req.body.returnTo);
      if (typeof req.body.accountId !== 'string' || !/^[a-f0-9]{24}$/i.test(req.body.accountId)) return res.sendStatus(400);
      const user = await users.findById(req.body.accountId).select('_id email role').lean();
      if (!user) return res.sendStatus(404);
      const session = generateSessionToken({ id: String(user._id), email: user.email, role: user.role });
      audit.info(`Pre test account login ${JSON.stringify({ actor: req.accessIdentity, targetUserId: String(user._id), targetEmail: user.email })}`);
      setSessionCookie(res, session);
      res.cookie(capabilityCookie, req.body.accessAssertion, { secure: true, httpOnly: true, sameSite: 'lax', path: '/', maxAge: 24 * 60 * 60 * 1000 });
      res.redirect(303, returnTo);
    } catch (error) {
      if (error.message === 'Invalid return URL' || error instanceof TypeError) return res.sendStatus(400);
      next(error);
    }
  });
  return router;
}

export async function testLoginStatus(req, res) {
  res.set('Cache-Control', 'no-store');
  if (!testLoginEnabled() || req.hostname !== 'pre.auth.leia.ovh') return res.status(404).json({ enabled: false });
  let authenticated = false;
  try { await verifyAccessIdentity(accessCookie(req, capabilityCookie)); authenticated = true; } catch { /* The public login stays available. */ }
  res.json({ enabled: true, authenticated, url: entryOrigin });
}
