import { describe, expect, test } from 'vitest';
import { createApiKeyValidator, updateApiKeyValidator } from '../src/validators/v1/apiKeyValidator.js';

// Base válida reutilizable para el alta; cada test sobreescribe lo que necesita probar.
const validBase = {
  description: 'Mi clave',
  provider: 'openai',
  model: 'gpt-4o-mini',
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
  test('exige un modelo por defecto al crear la clave', () => {
    const { model, ...withoutModel } = validBase;
    void model;
    expect(validateCreate(withoutModel)).toBeDefined();
  });

  test('rechaza un modelo por defecto vacío', () => {
    expect(validateCreate({ ...validBase, model: '' })).toBeDefined();
  });

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

  test.each([null, '', '   '])('al actualizar, no permite vaciar el modelo por defecto (%p)', (model) => {
    const { error } = updateApiKeyValidator.validate({ model });
    expect(error).toBeDefined();
  });

  test('al actualizar, permite cambiar el modelo por defecto', () => {
    const { error } = updateApiKeyValidator.validate({ model: 'gpt-4.1-mini' });
    expect(error).toBeUndefined();
  });
});

describe('Claves de ALMA', () => {
  const almaBase = {
    ...validBase,
    provider: 'alma',
    model: 'meta-llama/Llama-3.1-8B-Instruct',
    keyValue: 'a1b2c3d4e5f6',
    baseUrl: 'https://alma.us.es/api/models/llama-3.1-8b-instruct/v1',
  };

  test('acepta una clave de ALMA con la Base URL de su modelo', () => {
    expect(validateCreate(almaBase)).toBeUndefined();
  });

  test('exige la Base URL para ALMA', () => {
    const { baseUrl, ...withoutBaseUrl } = almaBase;
    void baseUrl;
    const error = validateCreate(withoutBaseUrl);
    expect(error).toBeDefined();
    expect(error.message).toMatch(/ALMA, la Base URL/);
  });

  test('rechaza una Base URL vacía para ALMA', () => {
    expect(validateCreate({ ...almaBase, baseUrl: '' })).toBeDefined();
  });

  test('rechaza una clave de ALMA con espacios', () => {
    const error = validateCreate({ ...almaBase, keyValue: 'clave con espacios' });
    expect(error).toBeDefined();
    expect(error.message).toMatch(/ALMA/);
  });

  test('al actualizar, no permite vaciar la Base URL de ALMA', () => {
    const { error } = updateApiKeyValidator.validate({ provider: 'alma', keyValue: 'nueva', baseUrl: '' });
    expect(error).toBeDefined();
  });
});
