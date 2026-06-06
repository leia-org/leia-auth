import { describe, expect, test } from 'vitest';
import { createApiKeyValidator, updateApiKeyValidator } from '../src/validators/v1/apiKeyValidator.js';

// Base válida reutilizable para el alta; cada test sobreescribe lo que necesita probar.
const validBase = {
  description: 'Mi clave',
  provider: 'openai',
  keyValue: 'sk-abcDEF123456',
  isActive: true,
  isDefault: false,
};

// Helper: ejecuta la validación y devuelve el error de Joi (o null si valida).
function validateCreate(payload) {
  const { error } = createApiKeyValidator.validate(payload, { abortEarly: false });
  return error;
}

describe('Validación de formato por proveedor', () => {
  test('acepta una clave de OpenAI con el prefijo sk-', () => {
    expect(validateCreate(validBase)).toBeUndefined();
  });

  test('acepta una clave de Gemini con el prefijo AIzaSy', () => {
    const error = validateCreate({ ...validBase, provider: 'gemini', keyValue: 'AIzaSyABC123_def' });
    expect(error).toBeUndefined();
  });

  test('acepta una clave de Anthropic con el prefijo sk-ant-', () => {
    const error = validateCreate({ ...validBase, provider: 'anthropic', keyValue: 'sk-ant-XYZ789' });
    expect(error).toBeUndefined();
  });

  test('rechaza una clave de OpenAI con formato incorrecto', () => {
    const error = validateCreate({ ...validBase, keyValue: 'clave-sin-prefijo' });
    expect(error).toBeDefined();
    expect(error.message).toMatch(/OpenAI/);
  });

  test('rechaza un proveedor no soportado por el sistema', () => {
    const error = validateCreate({ ...validBase, provider: 'cohere' });
    expect(error).toBeDefined();
    expect(error.message).toMatch(/provider no lo gestionamos/);
  });
});

describe('Coherencia proveedor-clave y URL base local', () => {
  test('exige baseUrl para un proveedor local (ollama)', () => {
    const error = validateCreate({ ...validBase, provider: 'ollama', keyValue: 'cualquier-cosa' });
    expect(error).toBeDefined();
    expect(error.message).toMatch(/base ?url/i);
  });

  test('acepta ollama cuando se aporta una baseUrl válida', () => {
    const error = validateCreate({
      ...validBase,
      provider: 'ollama',
      keyValue: 'cualquier-cosa',
      baseUrl: 'http://localhost:11434',
    });
    expect(error).toBeUndefined();
  });

  test('no exige baseUrl para un proveedor en la nube (openai)', () => {
    const { baseUrl, ...withoutBaseUrl } = validBase;
    void baseUrl;
    expect(validateCreate(withoutBaseUrl)).toBeUndefined();
  });

  test('al actualizar, no permite cambiar el valor de la clave sin indicar el proveedor', () => {
    const { error } = updateApiKeyValidator.validate({ keyValue: 'sk-nuevaClave123' });
    expect(error).toBeDefined();
    expect(error.message).toMatch(/provider asociado/);
  });

  test('al actualizar, acepta un nuevo valor junto con su proveedor', () => {
    const { error } = updateApiKeyValidator.validate({ provider: 'openai', keyValue: 'sk-nuevaClave123' });
    expect(error).toBeUndefined();
  });
});
