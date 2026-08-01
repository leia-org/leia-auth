const DEFAULT_COOKIE_NAME = 'leia_session';
const DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60;

const parseBoolean = (value, fallback) => {
  if (value === undefined || value === '') return fallback;
  return value === 'true';
};

const parsePositiveInteger = (value, fallback) => {
  const parsed = Number.parseInt(value || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

export const getSessionCookieName = () =>
  process.env.SESSION_COOKIE_NAME || DEFAULT_COOKIE_NAME;

export const getSessionCookieOptions = () => {
  const secure = parseBoolean(
    process.env.SESSION_COOKIE_SECURE,
    process.env.NODE_ENV === 'production',
  );
  const configuredSameSite = (process.env.SESSION_COOKIE_SAME_SITE || 'lax').toLowerCase();
  const sameSite = ['lax', 'strict', 'none'].includes(configuredSameSite)
    ? configuredSameSite
    : 'lax';
  const maxAgeSeconds = parsePositiveInteger(
    process.env.SESSION_COOKIE_MAX_AGE_SECONDS,
    DEFAULT_MAX_AGE_SECONDS,
  );
  const options = {
    httpOnly: true,
    secure,
    sameSite,
    path: '/',
    maxAge: maxAgeSeconds * 1000,
  };

  if (process.env.SESSION_COOKIE_DOMAIN) {
    options.domain = process.env.SESSION_COOKIE_DOMAIN;
  }

  return options;
};

export const readSessionCookie = (req) => {
  const rawCookieHeader = req.headers?.cookie;
  if (!rawCookieHeader) return null;

  const cookieName = getSessionCookieName();
  for (const part of rawCookieHeader.split(';')) {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex < 0) continue;

    const name = part.slice(0, separatorIndex).trim();
    if (name !== cookieName) continue;

    const value = part.slice(separatorIndex + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  return null;
};

export const setSessionCookie = (res, token) => {
  res.cookie(getSessionCookieName(), token, getSessionCookieOptions());
};

export const clearSessionCookie = (res) => {
  const options = { ...getSessionCookieOptions() };
  delete options.maxAge;
  res.clearCookie(getSessionCookieName(), options);
};
