import { describe, expect, test, beforeEach, vi } from 'vitest';

vi.mock('../src/repositories/v1/ApiKeyRepository.js', () => ({
  default: {
    addApiKey: vi.fn(),
    updateApiKey: vi.fn(),
    deleteApiKey: vi.fn(),
    markApiKeyAsDefault: vi.fn(),
    unmarkApiKeyDefault: vi.fn(),
    setSystemApiKeyDefault: vi.fn(),
    setSystemApiKeyDefaultForAllUsers: vi.fn(),
    enableSystemApiKey: vi.fn(),
    findAllSystemKeys: vi.fn(),
    findDefaultSystemKey: vi.fn(),
    findSystemKeyById: vi.fn(),
    createSystemKey: vi.fn(),
    updateSystemKey: vi.fn(),
    deleteSystemKey: vi.fn(),
    clearSystemKeyFromAllUsers: vi.fn(),
  },
}));
vi.mock('../src/repositories/v1/UserRepository.js', () => ({
  default: { findById: vi.fn() },
}));
vi.mock('../src/utils/crypto.js', () => ({
  encrypt: vi.fn((text) => `ENC(${text})`),
  decryptApiKeyValue: vi.fn((key) => ({ ...key, keyValue: `DEC(${key.keyValue})` })),
  maskApiKeyValue: vi.fn((key) => ({ ...key, keyValue: 'MASKED' })),
}));
vi.mock('axios', () => ({ default: { post: vi.fn() } }));

import ApiKeyRepository from '../src/repositories/v1/ApiKeyRepository.js';
import UserRepository from '../src/repositories/v1/UserRepository.js';
import { encrypt } from '../src/utils/crypto.js';
import axios from 'axios';
import ApiKeyService from '../src/services/v1/ApiKeyService.js';

// Construye un doble de subdocumento de API Key tal como lo expone Mongoose: con _id
// accesible a nivel superior y el método toObject().
function apiKeySubdoc(data) {
  return { _id: data._id, toObject: () => ({ ...data }) };
}

// Doble de usuario con la colección embebida de claves y su método .id() de Mongoose.
function userDoc({ apiKeys = [], ...rest } = {}) {
  const collection = [...apiKeys];
  collection.id = vi.fn((kid) => {
    const found = apiKeys.find((k) => k._id === kid);
    return found ? apiKeySubdoc(found) : null;
  });
  return { apiKeys: collection, ...rest };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
  ApiKeyRepository.findDefaultSystemKey.mockResolvedValue(null);
  ApiKeyRepository.findAllSystemKeys.mockResolvedValue([]);
  ApiKeyRepository.enableSystemApiKey.mockResolvedValue(null);
});

describe('createUserApiKey — alta de clave de usuario', () => {
  test('cifra el valor antes de persistirlo y devuelve la clave enmascarada', async () => {
    ApiKeyRepository.addApiKey.mockResolvedValue({ apiKeys: [{ _id: 'k1' }] });
    const masked = { _id: 'k1', provider: 'openai', keyValue: 'MASKED' };
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue(masked);

    const result = await ApiKeyService.createUserApiKey('user1', {
      provider: 'openai',
      keyValue: 'sk-plaintext-secret',
      isDefault: false,
    });

    expect(encrypt).toHaveBeenCalledWith('sk-plaintext-secret');
    const persisted = ApiKeyRepository.addApiKey.mock.calls[0][1];
    // El valor pasa por encrypt() antes de llegar al repositorio (el cifrado real
    // y la ausencia de texto plano se prueban en crypto.test.js).
    expect(persisted.keyValue).toBe('ENC(sk-plaintext-secret)');
    expect(result.keyValue).toBe('MASKED');
  });

  test('marca la clave como predeterminada cuando isDefault es true', async () => {
    ApiKeyRepository.addApiKey.mockResolvedValue({ apiKeys: [{ _id: 'k1' }] });
    const markSpy = vi.spyOn(ApiKeyService, 'markKeyAsDefault').mockResolvedValue({});
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'k1' });

    await ApiKeyService.createUserApiKey('user1', { provider: 'openai', keyValue: 'sk-x', isDefault: true });

    expect(markSpy).toHaveBeenCalledWith('user1', 'k1');
  });

  test('rechaza con 401 si no se aporta el identificador de usuario', async () => {
    await expect(ApiKeyService.createUserApiKey(null, {})).rejects.toMatchObject({ statusCode: 401 });
  });
});

describe('getUserApiKeys — listado de claves', () => {
  test('devuelve las claves del usuario y activa system api keys por defecto', async () => {
    UserRepository.findById.mockResolvedValue({
      useSystemApiKey: false,
      apiKeys: [apiKeySubdoc({ _id: 'k1', keyValue: 'cifrada' })],
    });

    const result = await ApiKeyService.getUserApiKeys('user1');

    expect(result).toHaveLength(1);
    expect(result[0].keyValue).toBe('MASKED');
    expect(ApiKeyRepository.findDefaultSystemKey).toHaveBeenCalled();
    expect(ApiKeyRepository.findAllSystemKeys).toHaveBeenCalled();
  });

  test('antepone las claves del sistema cuando el usuario tiene permiso', async () => {
    UserRepository.findById.mockResolvedValue({
      useSystemApiKey: true,
      defaultSystemApiKeyId: 'sys1',
      apiKeys: [apiKeySubdoc({ _id: 'k1', keyValue: 'cifrada' })],
    });
    // getAllSystemApiKeys es lógica aparte; la aislamos con un spy.
    vi.spyOn(ApiKeyService, 'getAllSystemApiKeys').mockResolvedValue([{ _id: 'sys1', keyValue: 'MASKED' }]);

    const result = await ApiKeyService.getUserApiKeys('user1');

    expect(result).toHaveLength(2);
    expect(result[0]._id).toBe('sys1');
    expect(result[0].isDefault).toBe(true);
  });

  test('rechaza con 404 si el usuario no existe', async () => {
    UserRepository.findById.mockResolvedValue(null);
    await expect(ApiKeyService.getUserApiKeys('fantasma')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('rechaza con 401 si no se aporta el identificador de usuario', async () => {
    await expect(ApiKeyService.getUserApiKeys(null)).rejects.toMatchObject({ statusCode: 401 });
  });
});

describe('updateUserApiKey — edición de clave', () => {
  test('exige el valor de la clave cuando se cambia el proveedor', async () => {
    await expect(
      ApiKeyService.updateUserApiKey('user1', 'k1', { provider: 'gemini' })
    ).rejects.toMatchObject({ statusCode: 400 });
    expect(ApiKeyRepository.updateApiKey).not.toHaveBeenCalled();
  });

  test('cifra el nuevo valor antes de persistir la edición', async () => {
    ApiKeyRepository.updateApiKey.mockResolvedValue({ _id: 'k1' });
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'k1', keyValue: 'MASKED' });

    await ApiKeyService.updateUserApiKey('user1', 'k1', { provider: 'openai', keyValue: 'sk-nueva' });

    expect(encrypt).toHaveBeenCalledWith('sk-nueva');
    const persisted = ApiKeyRepository.updateApiKey.mock.calls[0][2];
    expect(persisted.keyValue).toBe('ENC(sk-nueva)');
  });
});

describe('markKeyAsDefault — clave predeterminada', () => {
  test('usa la ruta de clave de usuario cuando el id no es de una clave del sistema', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue(null);
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'k1' });
    ApiKeyRepository.markApiKeyAsDefault.mockResolvedValue({ _id: 'user1' });

    await ApiKeyService.markKeyAsDefault('user1', 'k1');

    expect(ApiKeyRepository.markApiKeyAsDefault).toHaveBeenCalledWith('user1', 'k1');
    expect(ApiKeyRepository.setSystemApiKeyDefault).not.toHaveBeenCalled();
  });

  test('usa la ruta de clave del sistema cuando el id corresponde a una clave del sistema', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue({ _id: 'sys1' });
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'sys1' });
    ApiKeyRepository.setSystemApiKeyDefault.mockResolvedValue({ _id: 'user1' });

    await ApiKeyService.markKeyAsDefault('user1', 'sys1');

    expect(ApiKeyRepository.setSystemApiKeyDefault).toHaveBeenCalledWith('user1', 'sys1', true);
    expect(ApiKeyRepository.markApiKeyAsDefault).not.toHaveBeenCalled();
  });
});

describe('deleteUserApiKey — borrado de clave', () => {
  test('elimina la clave cuando el repositorio confirma el borrado', async () => {
    ApiKeyRepository.deleteApiKey.mockResolvedValue([true, 'API Key deleted successfully']);

    await expect(ApiKeyService.deleteUserApiKey('user1', 'k1')).resolves.toBe(true);
  });

  test('rechaza con 404 si la clave no existe', async () => {
    ApiKeyRepository.deleteApiKey.mockResolvedValue([false, 'API Key not found']);

    await expect(ApiKeyService.deleteUserApiKey('user1', 'inexistente')).rejects.toMatchObject({
      statusCode: 404,
    });
  });

  test('rechaza con 401 si no se aporta el identificador de usuario', async () => {
    await expect(ApiKeyService.deleteUserApiKey(null, 'k1')).rejects.toMatchObject({ statusCode: 401 });
  });
});

// Ramas adicionales del alta y la consulta de claves de usuario.
describe('createUserApiKey y getUserApiKeyById — ramas de error y de clave del sistema', () => {
  test('createUserApiKey rechaza con 404 si el usuario no existe', async () => {
    ApiKeyRepository.addApiKey.mockResolvedValue(null);
    await expect(
      ApiKeyService.createUserApiKey('fantasma', { provider: 'openai', keyValue: 'sk-x' })
    ).rejects.toMatchObject({ statusCode: 404 });
  });

  test('getUserApiKeyById devuelve la clave de usuario enmascarada', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(null);
    UserRepository.findById.mockResolvedValue(userDoc({ apiKeys: [{ _id: 'k1', keyValue: 'cifrada' }] }));

    const result = await ApiKeyService.getUserApiKeyById('user1', 'k1');

    expect(result.keyValue).toBe('MASKED');
  });

  test('getUserApiKeyById devuelve el valor descifrado cuando maskValue es false', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(null);
    UserRepository.findById.mockResolvedValue(userDoc({ apiKeys: [{ _id: 'k1', keyValue: 'cifrada' }] }));

    const result = await ApiKeyService.getUserApiKeyById('user1', 'k1', false);

    expect(result.keyValue).toBe('DEC(cifrada)');
  });

  test('getUserApiKeyById resuelve una clave del sistema si el usuario tiene permiso', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'cif' }));
    UserRepository.findById.mockResolvedValue(userDoc({ useSystemApiKey: true, defaultSystemApiKeyId: 'sys1' }));

    const result = await ApiKeyService.getUserApiKeyById('user1', 'sys1');

    expect(result._id).toBe('sys1');
    expect(result.isDefault).toBe(true);
  });

  test('getUserApiKeyById habilita system keys para usuarios antiguos sin permiso explícito', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'cif' }));
    UserRepository.findById.mockResolvedValue(userDoc({ useSystemApiKey: false }));

    const result = await ApiKeyService.getUserApiKeyById('user1', 'sys1');

    expect(result._id).toBe('sys1');
    expect(result.isDefault).toBe(false);
  });

  test('getUserApiKeyById rechaza con 404 si la clave de usuario no existe', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(null);
    UserRepository.findById.mockResolvedValue(userDoc({ apiKeys: [] }));

    await expect(ApiKeyService.getUserApiKeyById('user1', 'inexistente')).rejects.toMatchObject({
      statusCode: 404,
    });
  });

  test('getUserApiKeyById rechaza con 404 si el usuario no existe', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(null);
    UserRepository.findById.mockResolvedValue(null);

    await expect(ApiKeyService.getUserApiKeyById('fantasma', 'k1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('getUserApiKeyById rechaza con 401 sin identificador de usuario', async () => {
    await expect(ApiKeyService.getUserApiKeyById(null, 'k1')).rejects.toMatchObject({ statusCode: 401 });
  });
});

// Ramas de error de la edición y de la marca/desmarca de clave predeterminada.
describe('updateUserApiKey y (un)markKeyAsDefault — ramas de error', () => {
  test('updateUserApiKey rechaza con 401 sin identificador de usuario', async () => {
    await expect(ApiKeyService.updateUserApiKey(null, 'k1', {})).rejects.toMatchObject({ statusCode: 401 });
  });

  test('updateUserApiKey rechaza con 404 si la clave no existe', async () => {
    ApiKeyRepository.updateApiKey.mockResolvedValue(null);
    await expect(
      ApiKeyService.updateUserApiKey('user1', 'k1', { description: 'nueva' })
    ).rejects.toMatchObject({ statusCode: 404 });
  });

  test('markKeyAsDefault rechaza con 404 si la clave de usuario no existe', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue(null);
    ApiKeyRepository.markApiKeyAsDefault.mockResolvedValue(null);

    await expect(ApiKeyService.markKeyAsDefault('user1', 'k1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('markKeyAsDefault rechaza con 404 (ruta de clave del sistema) si el usuario no existe', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue({ _id: 'sys1' });
    ApiKeyRepository.setSystemApiKeyDefault.mockResolvedValue(null);

    await expect(ApiKeyService.markKeyAsDefault('user1', 'sys1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('unMarkDefaultKey desmarca una clave de usuario', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue(null);
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'k1' });
    ApiKeyRepository.unmarkApiKeyDefault.mockResolvedValue({ _id: 'user1' });

    await ApiKeyService.unMarkDefaultKey('user1', 'k1');

    expect(ApiKeyRepository.unmarkApiKeyDefault).toHaveBeenCalledWith('user1', 'k1');
    expect(ApiKeyRepository.setSystemApiKeyDefault).not.toHaveBeenCalled();
  });

  test('unMarkDefaultKey desmarca una clave del sistema', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue({ _id: 'sys1' });
    vi.spyOn(ApiKeyService, 'getUserApiKeyById').mockResolvedValue({ _id: 'sys1' });
    ApiKeyRepository.setSystemApiKeyDefault.mockResolvedValue({ _id: 'user1' });

    await ApiKeyService.unMarkDefaultKey('user1', 'sys1');

    expect(ApiKeyRepository.setSystemApiKeyDefault).toHaveBeenCalledWith('user1', 'sys1', false);
    expect(ApiKeyRepository.unmarkApiKeyDefault).not.toHaveBeenCalled();
  });

  test('unMarkDefaultKey rechaza con 404 si la clave de usuario no existe', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue(null);
    ApiKeyRepository.unmarkApiKeyDefault.mockResolvedValue(null);

    await expect(ApiKeyService.unMarkDefaultKey('user1', 'k1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('unMarkDefaultKey rechaza con 404 (ruta de clave del sistema) si el usuario no existe', async () => {
    vi.spyOn(ApiKeyService, 'getSystemApiKeyById').mockResolvedValue({ _id: 'sys1' });
    ApiKeyRepository.setSystemApiKeyDefault.mockResolvedValue(null);

    await expect(ApiKeyService.unMarkDefaultKey('user1', 'sys1')).rejects.toMatchObject({ statusCode: 404 });
  });
});

describe('Gestión de claves del sistema', () => {
  test('getAllSystemApiKeys devuelve las claves descifradas y enmascaradas', async () => {
    ApiKeyRepository.findAllSystemKeys.mockResolvedValue([
      apiKeySubdoc({ _id: 'sys1', keyValue: 'c1' }),
      apiKeySubdoc({ _id: 'sys2', keyValue: 'c2' }),
    ]);

    const result = await ApiKeyService.getAllSystemApiKeys();

    expect(result).toHaveLength(2);
    expect(result[0].keyValue).toBe('MASKED');
  });

  test('getSystemApiKeyById devuelve null si la clave no existe', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(null);
    await expect(ApiKeyService.getSystemApiKeyById('inexistente')).resolves.toBeNull();
  });

  test('getSystemApiKeyById devuelve el valor descifrado cuando maskValue es false', async () => {
    ApiKeyRepository.findSystemKeyById.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'cif' }));
    const result = await ApiKeyService.getSystemApiKeyById('sys1', false);
    expect(result.keyValue).toBe('DEC(cif)');
  });

  test('createSystemApiKey cifra el valor y marca la predeterminada cuando isDefault es true', async () => {
    ApiKeyRepository.createSystemKey.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'ENC(sk-sys)' }));
    ApiKeyRepository.setSystemApiKeyDefaultForAllUsers.mockResolvedValue({});

    const result = await ApiKeyService.createSystemApiKey('admin1', {
      provider: 'openai',
      keyValue: 'sk-sys',
      isDefault: true,
    });

    expect(ApiKeyRepository.setSystemApiKeyDefaultForAllUsers).toHaveBeenCalledWith('sys1');
    expect(result.keyValue).toBe('MASKED');
  });

  test('createSystemApiKey marca la primera system key activa como predeterminada para todos', async () => {
    ApiKeyRepository.createSystemKey.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'ENC(sk-sys)' }));
    ApiKeyRepository.setSystemApiKeyDefaultForAllUsers.mockResolvedValue({});

    await ApiKeyService.createSystemApiKey('admin1', {
      provider: 'openai',
      keyValue: 'sk-sys',
      isActive: true,
      isDefault: false,
    });

    expect(ApiKeyRepository.setSystemApiKeyDefaultForAllUsers).toHaveBeenCalledWith('sys1');
  });

  test('updateSystemApiKey rechaza con 400 si se cambia el proveedor sin valor', async () => {
    await expect(
      ApiKeyService.updateSystemApiKey('sys1', { provider: 'gemini' })
    ).rejects.toMatchObject({ statusCode: 400 });
    expect(ApiKeyRepository.updateSystemKey).not.toHaveBeenCalled();
  });

  test('updateSystemApiKey rechaza con 404 si la clave no existe', async () => {
    ApiKeyRepository.updateSystemKey.mockResolvedValue(null);
    await expect(
      ApiKeyService.updateSystemApiKey('sys1', { description: 'nueva' })
    ).rejects.toMatchObject({ statusCode: 404 });
  });

  test('updateSystemApiKey devuelve la clave actualizada y enmascarada', async () => {
    ApiKeyRepository.updateSystemKey.mockResolvedValue(apiKeySubdoc({ _id: 'sys1', keyValue: 'cif' }));
    const result = await ApiKeyService.updateSystemApiKey('sys1', { description: 'nueva' });
    expect(result.keyValue).toBe('MASKED');
  });

  test('deleteSystemApiKey rechaza con 404 si la clave no existe', async () => {
    ApiKeyRepository.deleteSystemKey.mockResolvedValue(null);
    await expect(ApiKeyService.deleteSystemApiKey('sys1')).rejects.toMatchObject({ statusCode: 404 });
  });

  test('deleteSystemApiKey la borra y la retira de todos los usuarios', async () => {
    ApiKeyRepository.deleteSystemKey.mockResolvedValue({ _id: 'sys1' });
    ApiKeyRepository.clearSystemKeyFromAllUsers.mockResolvedValue();

    await expect(ApiKeyService.deleteSystemApiKey('sys1')).resolves.toBe(true);
    expect(ApiKeyRepository.clearSystemKeyFromAllUsers).toHaveBeenCalledWith('sys1');
  });
});

describe('sendRevocationRequestToRunner — notificación de revocación al Runner', () => {
  test('envía la petición de revocación al Runner con el token de servicio', async () => {
    process.env.RUNNER_URL = 'http://runner.local';
    process.env.RUNNER_KEY = 'runner-secret';
    axios.post.mockResolvedValue({});

    await ApiKeyService.sendRevocationRequestToRunner('key1');

    expect(axios.post).toHaveBeenCalledWith(
      'http://runner.local/api/v1/revoke',
      { apiKeyId: 'key1' },
      { headers: { Authorization: 'Bearer runner-secret' } }
    );
  });

  test('no propaga el error si el Runner no responde (fallo tolerado)', async () => {
    axios.post.mockRejectedValue(new Error('connect ECONNREFUSED'));
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(ApiKeyService.sendRevocationRequestToRunner('key1')).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
  });
});
