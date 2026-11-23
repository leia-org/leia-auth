import logger from '../utils/logger.js';

const requestLogger = (req, _res, next) => {
  // Access assertions, cookies and credentials must never enter debug logs.
  if (req.path.startsWith('/test-login') || req.path.startsWith('/api/v1/test-login')) return next();
  const headers = { ...req.headers };
  for (const key of ['authorization', 'cookie', 'cf-access-jwt-assertion', 'x-api-key', 'x-intern-token']) {
    if (headers[key]) headers[key] = '[REDACTED]';
  }
  const body = req.body && typeof req.body === 'object' ? { ...req.body } : req.body;
  if (body && typeof body === 'object') {
    for (const key of ['password', 'currentPassword', 'newPassword', 'cf-turnstile-response']) {
      if (body[key]) body[key] = '[REDACTED]';
    }
  }
  const logDetails = {
    method: req.method,
    url: req.originalUrl,
    headers,
    query: req.query,
    body,
  };
  logger.debug(JSON.stringify(logDetails, null, 2));
  return next();
};

export default requestLogger;
