import { describe, expect, test, beforeEach, vi } from 'vitest';

// Mockeamos axios para no realizar peticiones reales al proveedor durante la prueba.
vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

import axios from 'axios';
import ProviderService from '../src/services/v1/ProviderService.js';

// Simula la respuesta de error HTTP que devuelve axios (error.response.status).
function httpError(status) {
  const error = new Error(`Request failed with status code ${status}`);
  error.response = { status };
  return error;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Verificación activa de la clave contra el proveedor', () => {
  test('acepta una clave de OpenAI cuando el proveedor responde con éxito', async () => {
    axios.get.mockResolvedValue({ status: 200, data: { data: [] } });

    await expect(ProviderService.verifyApiKeyIntegrity('openai', 'sk-valida')).resolves.toBe(true);
  });

  test('rechaza una clave de OpenAI inactiva o revocada (401 del proveedor)', async () => {
    axios.get.mockRejectedValue(httpError(401));

    await expect(ProviderService.verifyApiKeyIntegrity('openai', 'sk-revocada')).rejects.toThrow(
      'OpenAI has rejected the API key.'
    );
  });

  test('distingue un fallo del servicio del proveedor de una clave inválida', async () => {
    axios.get.mockRejectedValue(httpError(503));

    await expect(ProviderService.verifyApiKeyIntegrity('openai', 'sk-valida')).rejects.toThrow(
      /service is not available/
    );
  });

  test('rechaza una clave de Gemini inválida (400 del proveedor)', async () => {
    axios.get.mockRejectedValue(httpError(400));

    await expect(ProviderService.verifyApiKeyIntegrity('gemini', 'AIzaSyInvalida')).rejects.toThrow(
      'Gemini has rejected the API key.'
    );
  });

  test('considera siempre válida la clave de un proveedor local (ollama) sin llamar a la red', async () => {
    await expect(ProviderService.verifyApiKeyIntegrity('ollama', 'lo-que-sea')).resolves.toBe(true);
    expect(axios.get).not.toHaveBeenCalled();
  });

  test('rechaza un proveedor no soportado', async () => {
    await expect(ProviderService.verifyApiKeyIntegrity('desconocido', 'x')).rejects.toThrow(/Unsupported provider/);
  });
});

describe('La verificación no consume tokens', () => {
  test('OpenAI se valida contra el endpoint de listado de modelos, no de generación', async () => {
    axios.get.mockResolvedValue({ status: 200, data: { data: [] } });

    await ProviderService.verifyApiKeyIntegrity('openai', 'sk-valida');

    const [url, config] = axios.get.mock.calls[0];
    // El endpoint /v1/models lista modelos sin generar texto: cero tokens consumidos.
    expect(url).toBe('https://api.openai.com/v1/models');
    expect(config.headers.Authorization).toBe('Bearer sk-valida');
  });

  test('Gemini se valida contra el endpoint de listado de modelos', async () => {
    axios.get.mockResolvedValue({ status: 200, data: { models: [] } });

    await ProviderService.verifyApiKeyIntegrity('gemini', 'AIzaSyValida');

    const [url] = axios.get.mock.calls[0];
    expect(url).toContain('/v1beta/models');
  });
});
