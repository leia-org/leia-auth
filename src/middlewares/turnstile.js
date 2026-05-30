import axios from 'axios';
import logger from '../utils/logger.js';

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const isTurnstileEnabled = () => process.env.TURNSTILE_ENABLED?.toLowerCase() !== 'false';

const getRemoteIp = (req) => {
  const forwardedFor = req.headers['x-forwarded-for'];

  return (
    req.headers['cf-connecting-ip'] ||
    (typeof forwardedFor === 'string' ? forwardedFor.split(',')[0].trim() : undefined) ||
    req.ip
  );
};

export const requireValidTurnstileToken = async (req, res, next) => {
  if (!isTurnstileEnabled()) {
    delete req.body?.['cf-turnstile-response'];
    return next();
  }

  const token = req.body?.['cf-turnstile-response'];

  if (!token || typeof token !== 'string' || token.length > 2048) {
    return res.status(400).json({ message: 'Please complete the verification challenge.' });
  }

  if (!process.env.CLOUDFLARE_SECRET_KEY) {
    logger.error('CLOUDFLARE_SECRET_KEY is not configured');
    return res.status(500).json({ message: 'Verification service is not configured.' });
  }

  try {
    const { data } = await axios.post(
      SITEVERIFY_URL,
      {
        secret: process.env.CLOUDFLARE_SECRET_KEY,
        response: token,
        remoteip: getRemoteIp(req),
      },
      { timeout: 5000 }
    );

    if (!data.success) {
      logger.warn(`Turnstile validation failed: ${(data['error-codes'] || []).join(', ')}`);
      return res.status(400).json({ message: 'Verification failed. Please try again.' });
    }

    delete req.body['cf-turnstile-response'];
    next();
  } catch (error) {
    logger.error(`Turnstile validation request failed: ${error.message}`);
    return res.status(502).json({ message: 'Verification service is temporarily unavailable.' });
  }
};
