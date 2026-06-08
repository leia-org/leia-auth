import { describe, expect, test, beforeEach, vi } from 'vitest';

vi.mock('../src/utils/jwt.js', () => ({
  verifyToken: vi.fn(),
}));
vi.mock('../src/utils/logger.js', () => ({
  default: { debug: vi.fn(), error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}));

import { verifyToken } from '../src/utils/jwt.js';
import {
  auth,
  requireAdmin,
  requireAdvanced,
  requireInstructor,
  requireInternToken,
} from '../src/middlewares/auth.js';

// Pequeña fábrica de dobles de Express para no repetir el andamiaje en cada test.
function buildContext({ headers = {}, auth: authState = null } = {}) {
  const req = { headers, auth: authState };
  const res = {};
  const next = vi.fn();
  return { req, res, next };
}

// next() se invoca con un Error cuando la autorización falla.
function nextError(next) {
  expect(next).toHaveBeenCalledTimes(1);
  return next.mock.calls[0][0];
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('auth() — autenticación transversal', () => {
  test('acepta un Bearer JWT válido y carga el payload en req.auth', () => {
    verifyToken.mockReturnValue({ id: 'u1', role: 'advanced' });
    const { req, res, next } = buildContext({ headers: { authorization: 'Bearer token-valido' } });

    auth(req, res, next);

    expect(verifyToken).toHaveBeenCalledWith('token-valido');
    expect(req.auth).toEqual({ method: 'JWT', payload: { id: 'u1', role: 'advanced' } });
    expect(next).toHaveBeenCalledWith();
  });

  test('rechaza con 401 un encabezado Authorization mal formado', () => {
    const { req, res, next } = buildContext({ headers: { authorization: 'TokenSinBearer' } });

    auth(req, res, next);

    expect(nextError(next).statusCode).toBe(401);
    expect(verifyToken).not.toHaveBeenCalled();
  });

  test('rechaza con 401 un token cuya verificación criptográfica falla', () => {
    verifyToken.mockImplementation(() => {
      throw new Error('jwt expired');
    });
    const { req, res, next } = buildContext({ headers: { authorization: 'Bearer caducado' } });

    auth(req, res, next);

    expect(nextError(next).statusCode).toBe(401);
  });

  test('acepta una x-api-key de servicio válida', () => {
    process.env.API_KEY = 'clave-de-servicio';
    const { req, res, next } = buildContext({ headers: { 'x-api-key': 'clave-de-servicio' } });

    auth(req, res, next);

    expect(req.auth).toEqual({ method: 'API_KEY', payload: { role: 'read' } });
    expect(next).toHaveBeenCalledWith();
  });

  test('rechaza con 401 una x-api-key de servicio incorrecta', () => {
    process.env.API_KEY = 'clave-de-servicio';
    const { req, res, next } = buildContext({ headers: { 'x-api-key': 'clave-equivocada' } });

    auth(req, res, next);

    expect(nextError(next).statusCode).toBe(401);
  });
});

describe('Control de acceso por rol', () => {
  test('requireAdmin solo deja pasar al rol admin', () => {
    const admin = buildContext({ auth: { payload: { role: 'admin' } } });
    requireAdmin(admin.req, admin.res, admin.next);
    expect(admin.next).toHaveBeenCalledWith();

    const advanced = buildContext({ auth: { payload: { role: 'advanced' } } });
    requireAdmin(advanced.req, advanced.res, advanced.next);
    expect(nextError(advanced.next).statusCode).toBe(403);
  });

  test('requireAdvanced autoriza a advanced y admin pero deniega a instructor', () => {
    for (const role of ['advanced', 'admin']) {
      const ctx = buildContext({ auth: { payload: { role } } });
      requireAdvanced(ctx.req, ctx.res, ctx.next);
      expect(ctx.next).toHaveBeenCalledWith();
    }

    const instructor = buildContext({ auth: { payload: { role: 'instructor' } } });
    requireAdvanced(instructor.req, instructor.res, instructor.next);
    expect(nextError(instructor.next).statusCode).toBe(403);
  });

  test('requireInstructor deniega a un rol distinto de instructor', () => {
    const ctx = buildContext({ auth: { payload: { role: 'advanced' } } });
    requireInstructor(ctx.req, ctx.res, ctx.next);
    expect(nextError(ctx.next).statusCode).toBe(403);
  });
});

describe('requireInternToken — comunicación interna protegida', () => {
  test('deja pasar la petición cuando el x-intern-token coincide', () => {
    process.env.INTERN_TOKEN = 'token-interno';
    const { req, res, next } = buildContext({ headers: { 'x-intern-token': 'token-interno' } });

    requireInternToken(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  test('rechaza con 401 cuando el x-intern-token no coincide o falta', () => {
    process.env.INTERN_TOKEN = 'token-interno';

    const wrong = buildContext({ headers: { 'x-intern-token': 'otro' } });
    requireInternToken(wrong.req, wrong.res, wrong.next);
    expect(nextError(wrong.next).statusCode).toBe(401);

    const missing = buildContext({ headers: {} });
    requireInternToken(missing.req, missing.res, missing.next);
    expect(nextError(missing.next).statusCode).toBe(401);
  });
});
