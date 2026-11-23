import { describe, expect, test, beforeEach, vi } from 'vitest';

vi.mock('../src/services/v1/ApiKeyService.js', () => ({
  default: {
    deleteUserApiKey: vi.fn(),
    updateUserApiKey: vi.fn(),
    getUserApiKeyById: vi.fn(),
    createUserApiKey: vi.fn(),
    getSystemApiKeyById: vi.fn(),
    updateSystemApiKey: vi.fn(),
    deleteSystemApiKey: vi.fn(),
    sendRevocationRequestToRunner: vi.fn(),
  },
}));
vi.mock('../src/services/v1/ProviderService.js', () => ({
  default: { verifyApiKeyIntegrity: vi.fn() },
}));
vi.mock('../src/validators/v1/apiKeyValidator.js', () => ({
  createApiKeyValidator: { validateAsync: vi.fn() },
  updateApiKeyValidator: { validateAsync: vi.fn() },
}));

import ApiKeyService from '../src/services/v1/ApiKeyService.js';
import ProviderService from '../src/services/v1/ProviderService.js';
import { createApiKeyValidator, updateApiKeyValidator } from '../src/validators/v1/apiKeyValidator.js';
import {
  createApiKey,
  updateApiKey,
  deleteApiKey,
  updateSystemApiKey,
  deleteSystemApiKey,
} from '../src/controllers/v1/apiKeyController.js';

// Doble de la respuesta de Express: status() encadena y json()/end() registran la salida.
function mockRes() {
  const res = {};
  res.status = vi.fn(() => res);
  res.json = vi.fn(() => res);
  res.end = vi.fn(() => res);
  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('apiKeyController — la edición/eliminación de una clave notifica la revocación al Runner', () => {
  test('deleteApiKey revoca la clave de usuario eliminada', async () => {
    const req = { auth: { payload: { id: 'user1' } }, params: { apiKeyId: 'k1' } };
    const res = mockRes();
    const next = vi.fn();
    ApiKeyService.deleteUserApiKey.mockResolvedValue(true);

    await deleteApiKey(req, res, next);

    expect(ApiKeyService.deleteUserApiKey).toHaveBeenCalledWith('user1', 'k1');
    expect(ApiKeyService.sendRevocationRequestToRunner).toHaveBeenCalledWith('k1');
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(204);
  });

  test('updateApiKey revoca la clave de usuario editada', async () => {
    const req = {
      auth: { payload: { id: 'user1' } },
      params: { apiKeyId: 'k1' },
      body: { description: 'nuevo nombre' },
    };
    const res = mockRes();
    const next = vi.fn();
    updateApiKeyValidator.validateAsync.mockResolvedValue({ description: 'nuevo nombre' });
    ApiKeyService.getUserApiKeyById.mockResolvedValue({ _id: 'k1', provider: 'openai' });
    ApiKeyService.updateUserApiKey.mockResolvedValue({ _id: 'k1' });

    await updateApiKey(req, res, next);

    expect(ApiKeyService.sendRevocationRequestToRunner).toHaveBeenCalledWith('k1');
    expect(next).not.toHaveBeenCalled();
  });

  test('updateSystemApiKey revoca la clave del sistema editada', async () => {
    const req = { params: { id: 'sys1' }, body: { description: 'nuevo nombre' } };
    const res = mockRes();
    const next = vi.fn();
    updateApiKeyValidator.validateAsync.mockResolvedValue({ description: 'nuevo nombre' });
    ApiKeyService.updateSystemApiKey.mockResolvedValue({ _id: 'sys1' });

    await updateSystemApiKey(req, res, next);

    expect(ApiKeyService.sendRevocationRequestToRunner).toHaveBeenCalledWith('sys1');
    expect(next).not.toHaveBeenCalled();
  });

  test('deleteSystemApiKey revoca la clave del sistema eliminada', async () => {
    const req = { params: { id: 'sys1' } };
    const res = mockRes();
    const next = vi.fn();
    ApiKeyService.deleteSystemApiKey.mockResolvedValue(true);

    await deleteSystemApiKey(req, res, next);

    expect(ApiKeyService.deleteSystemApiKey).toHaveBeenCalledWith('sys1');
    expect(ApiKeyService.sendRevocationRequestToRunner).toHaveBeenCalledWith('sys1');
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(204);
  });
});

describe('apiKeyController — ALMA se verifica contra la Base URL de la clave', () => {
  const baseUrl = 'https://alma.us.es/api/models/llama-3.1-8b-instruct/v1';

  test('createApiKey verifica la clave con su Base URL', async () => {
    const value = { provider: 'alma', keyValue: 'clave-alma', baseUrl };
    const req = { auth: { payload: { id: 'user1' } }, body: value };
    const res = mockRes();
    const next = vi.fn();
    createApiKeyValidator.validateAsync.mockResolvedValue(value);
    ApiKeyService.createUserApiKey.mockResolvedValue({ _id: 'k1' });

    await createApiKey(req, res, next);

    expect(ProviderService.verifyApiKeyIntegrity).toHaveBeenCalledWith('alma', 'clave-alma', baseUrl);
    expect(next).not.toHaveBeenCalled();
  });

  test('updateApiKey verifica una clave nueva con la Base URL ya guardada', async () => {
    const req = { auth: { payload: { id: 'user1' } }, params: { apiKeyId: 'k1' }, body: {} };
    const res = mockRes();
    const next = vi.fn();
    updateApiKeyValidator.validateAsync.mockResolvedValue({ provider: 'alma', keyValue: 'clave-nueva' });
    ApiKeyService.getUserApiKeyById.mockResolvedValue({ _id: 'k1', provider: 'alma', baseUrl });
    ApiKeyService.updateUserApiKey.mockResolvedValue({ _id: 'k1' });

    await updateApiKey(req, res, next);

    expect(ProviderService.verifyApiKeyIntegrity).toHaveBeenCalledWith('alma', 'clave-nueva', baseUrl);
    expect(next).not.toHaveBeenCalled();
  });

  test('updateSystemApiKey verifica una clave nueva de ALMA con la Base URL ya guardada', async () => {
    const req = { params: { id: 'sys1' }, body: {} };
    const res = mockRes();
    const next = vi.fn();
    updateApiKeyValidator.validateAsync.mockResolvedValue({ provider: 'alma', keyValue: 'clave-nueva' });
    ApiKeyService.getSystemApiKeyById.mockResolvedValue({ _id: 'sys1', provider: 'alma', baseUrl });
    ApiKeyService.updateSystemApiKey.mockResolvedValue({ _id: 'sys1' });

    await updateSystemApiKey(req, res, next);

    expect(ProviderService.verifyApiKeyIntegrity).toHaveBeenCalledWith('alma', 'clave-nueva', baseUrl);
    expect(next).not.toHaveBeenCalled();
  });

  test('un error de Base URL se asocia al campo baseUrl', async () => {
    const value = { provider: 'alma', keyValue: 'clave-alma', baseUrl };
    const req = { auth: { payload: { id: 'user1' } }, body: value };
    const next = vi.fn();
    createApiKeyValidator.validateAsync.mockResolvedValue(value);
    ProviderService.verifyApiKeyIntegrity.mockRejectedValueOnce(new Error('ALMA Base URL not found.'));

    await createApiKey(req, mockRes(), next);

    const [err] = next.mock.calls[0];
    expect(err.details).toEqual([{ path: ['baseUrl'], message: 'ALMA Base URL not found.' }]);
  });
});
