import jwt from 'jsonwebtoken';

const getSigningOptions = (expiresIn) => ({
  expiresIn,
  ...(process.env.JWT_ISSUER ? { issuer: process.env.JWT_ISSUER } : {}),
  ...(process.env.JWT_AUDIENCE ? { audience: process.env.JWT_AUDIENCE } : {}),
});

const getVerificationOptions = () => ({
  ...(process.env.JWT_ISSUER ? { issuer: process.env.JWT_ISSUER } : {}),
  ...(process.env.JWT_AUDIENCE ? { audience: process.env.JWT_AUDIENCE } : {}),
});

export const generateToken = (user) => {
  const toSign = {
    id: user.id,
    email: user.email,
    role: user.role,
    type: 'access',
  }
  return jwt.sign(
    toSign,
    process.env.JWT_SECRET,
    getSigningOptions(process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'),
  );
};

export const generateSessionToken = (user) => {
  const toSign = {
    id: user.id,
    email: user.email,
    role: user.role,
    type: 'session',
  };
  return jwt.sign(
    toSign,
    process.env.JWT_SECRET,
    getSigningOptions(process.env.SESSION_TOKEN_EXPIRES_IN || '1d'),
  );
};

export const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET, getVerificationOptions());
};

export const decodeToken = (token) => {
  return jwt.decode(token);
};
