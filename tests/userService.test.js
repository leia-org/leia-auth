import { describe, expect, test, beforeEach, vi } from 'vitest';

vi.mock('../src/repositories/v1/UserRepository.js', () => ({
  default: { create: vi.fn(), findById: vi.fn() },
}));
vi.mock('../src/repositories/v1/ApiKeyRepository.js', () => ({
  default: {
    findAllSystemKeys: vi.fn(),
    setSystemApiKeyDefault: vi.fn(),
    markApiKeyAsDefault: vi.fn(),
  },
}));

import UserRepository from '../src/repositories/v1/UserRepository.js';
import ApiKeyRepository from '../src/repositories/v1/ApiKeyRepository.js';
import UserService from '../src/services/v1/UserService.js';

// Doble de usuario recién creado, tal como lo devuelve Mongoose tras save().
function newUser(overrides = {}) {
  return { _id: 'user1', apiKeys: [], defaultSystemApiKeyId: null, ...overrides };
}

beforeEach(() => {
  vi.clearAllMocks();
  ApiKeyRepository.findAllSystemKeys.mockResolvedValue([]);
});

describe('UserService.create — clave predeterminada al crear el usuario', () => {
  test('asigna como predeterminada la system key más antigua a un usuario que usa claves del sistema', async () => {
    const created = newUser({ useSystemApiKey: true });
    const withDefault = newUser({ useSystemApiKey: true, defaultSystemApiKeyId: 'sys-old' });
    UserRepository.create.mockResolvedValue(created);
    ApiKeyRepository.findAllSystemKeys.mockResolvedValue([
      { _id: 'sys-new', createdAt: '2026-08-01' },
      { _id: 'sys-old', createdAt: '2026-01-01' },
    ]);
    ApiKeyRepository.setSystemApiKeyDefault.mockResolvedValue(withDefault);

    const result = await UserService.create({ email: 'a@b.c', useSystemApiKey: true });

    expect(ApiKeyRepository.setSystemApiKeyDefault).toHaveBeenCalledWith('user1', 'sys-old', true);
    expect(result).toBe(withDefault);
  });

  test('no asigna nada a un usuario que no usa claves del sistema y no tiene claves propias', async () => {
    const created = newUser({ useSystemApiKey: false });
    UserRepository.create.mockResolvedValue(created);

    const result = await UserService.create({ email: 'a@b.c', useSystemApiKey: false });

    expect(ApiKeyRepository.findAllSystemKeys).not.toHaveBeenCalled();
    expect(ApiKeyRepository.setSystemApiKeyDefault).not.toHaveBeenCalled();
    expect(result).toBe(created);
  });

  test('devuelve el usuario creado cuando todavía no existe ninguna system key', async () => {
    const created = newUser({ useSystemApiKey: true });
    UserRepository.create.mockResolvedValue(created);

    const result = await UserService.create({ email: 'a@b.c', useSystemApiKey: true });

    expect(ApiKeyRepository.setSystemApiKeyDefault).not.toHaveBeenCalled();
    expect(result).toBe(created);
  });
});
