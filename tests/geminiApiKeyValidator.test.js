import { describe, expect, test } from 'vitest';
import { createApiKeyValidator, updateApiKeyValidator } from '../src/validators/v1/apiKeyValidator.js';

const validBase = {
  description: 'Mi clave de Gemini',
  provider: 'gemini',
  model: 'gemini-test-model',
  isActive: true,
  isDefault: false,
};

describe('Claves de Gemini sin restricción de prefijo', () => {
  test.each(['AIzaSyABC123_def', 'AQ.example-gemini-key', 'clave-sin-prefijo'])(
    'permite crear una clave con cualquier prefijo (%s)', (keyValue) => {
      const { error } = createApiKeyValidator.validate({ ...validBase, keyValue });
      expect(error).toBeUndefined();
    },
  );

  test.each(['AIzaSyABC123_def', 'AQ.example-gemini-key', 'clave-sin-prefijo'])(
    'permite actualizar una clave con cualquier prefijo (%s)', (keyValue) => {
      const { error } = updateApiKeyValidator.validate({ provider: 'gemini', keyValue });
      expect(error).toBeUndefined();
    },
  );

  test.each([undefined, '', null, 123])('rechaza valores ausentes, vacíos o no textuales al crear (%p)', (keyValue) => {
    const { error } = createApiKeyValidator.validate({ ...validBase, keyValue });
    expect(error).toBeDefined();
  });
});
