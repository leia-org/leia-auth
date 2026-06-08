import { describe, expect, test, beforeAll, afterAll } from 'vitest';
import { encrypt, decrypt, decryptApiKeyValue, maskApiKeyValue } from '../src/utils/crypto.js';

// Secreto de prueba: 64 caracteres hexadecimales = 32 bytes = clave AES-256 válida.
const TEST_SECRET = 'a'.repeat(64);

let originalSecret;

// Fijamos el secreto antes de toda la suite y lo restauramos al final para no
// contaminar el entorno de otras pruebas que pudieran ejecutarse en paralelo.
beforeAll(() => {
  originalSecret = process.env.API_KEY_STORAGE_SECRET;
  process.env.API_KEY_STORAGE_SECRET = TEST_SECRET;
});

afterAll(() => {
  if (typeof originalSecret === 'undefined') {
    delete process.env.API_KEY_STORAGE_SECRET;
    return;
  }
  process.env.API_KEY_STORAGE_SECRET = originalSecret;
});

describe('Cifrado autenticado de claves (RNF-02)', () => {
  test('cifra y descifra recuperando el texto original (ida y vuelta)', () => {
    const plain = 'sk-secret-openai-key-1234567890';

    const encrypted = encrypt(plain);

    expect(encrypted).not.toBe(plain);
    expect(encrypted).not.toContain(plain);
    expect(decrypt(encrypted)).toBe(plain);
  });

  test('produce el formato "iv:authTag:textoCifrado" con longitudes propias de GCM', () => {
    const encrypted = encrypt('sk-some-key');
    const parts = encrypted.split(':');

    expect(parts).toHaveLength(3);
    // IV de 12 bytes -> 24 caracteres hex; authTag de 16 bytes -> 32 caracteres hex.
    expect(parts[0]).toMatch(/^[0-9a-f]{24}$/);
    expect(parts[1]).toMatch(/^[0-9a-f]{32}$/);
    expect(parts[2]).toMatch(/^[0-9a-f]+$/);
  });

  test('el mismo texto cifrado dos veces produce criptogramas distintos (IV aleatorio)', () => {
    const plain = 'sk-deterministic-input';

    const first = encrypt(plain);
    const second = encrypt(plain);

    expect(first).not.toBe(second);
    // Pese a ser distintos, ambos descifran al mismo texto original.
    expect(decrypt(first)).toBe(plain);
    expect(decrypt(second)).toBe(plain);
  });

  test('un criptograma manipulado es rechazado por la verificación de integridad (AEAD)', () => {
    const encrypted = encrypt('sk-tamper-me');
    const [iv, tag, cipherText] = encrypted.split(':');

    // Alteramos un carácter del texto cifrado: GCM debe detectar la manipulación.
    const flipped = cipherText[0] === 'a' ? 'b' : 'a';
    const tampered = `${iv}:${tag}:${flipped}${cipherText.slice(1)}`;

    expect(() => decrypt(tampered)).toThrow();
  });

  test('rechaza un texto cifrado con formato inválido', () => {
    expect(() => decrypt('no-tiene-separadores')).toThrow('El formato del texto cifrado es inválido.');
  });

  test('devuelve el valor tal cual cuando la entrada es vacía o nula', () => {
    expect(encrypt('')).toBe('');
    expect(encrypt(null)).toBe(null);
    expect(decrypt('')).toBe('');
  });
});

describe('Validación fail-fast del secreto de cifrado', () => {
  test('lanza un error si el secreto no está definido', () => {
    const previous = process.env.API_KEY_STORAGE_SECRET;
    delete process.env.API_KEY_STORAGE_SECRET;

    expect(() => encrypt('sk-key')).toThrow(/API_KEY_STORAGE_SECRET/);

    process.env.API_KEY_STORAGE_SECRET = previous;
  });

  test('lanza un error si el secreto no mide 64 caracteres', () => {
    const previous = process.env.API_KEY_STORAGE_SECRET;
    process.env.API_KEY_STORAGE_SECRET = 'demasiado-corto';

    expect(() => encrypt('sk-key')).toThrow(/64 caracteres/);

    process.env.API_KEY_STORAGE_SECRET = previous;
  });
});

describe('Enmascarado del valor de la clave', () => {
  test('oculta el cuerpo de la clave dejando solo prefijo y sufijo', () => {
    const masked = maskApiKeyValue({ keyValue: 'sk-1234567890ABCD' });

    expect(masked.keyValue).not.toContain('1234567890');
    expect(masked.keyValue.startsWith('sk')).toBe(true);
    expect(masked.keyValue.endsWith('ABCD')).toBe(true);
    expect(masked.keyValue).toContain('•');
  });

  test('enmascara por completo una clave demasiado corta', () => {
    const masked = maskApiKeyValue({ keyValue: 'abc' });

    expect(masked.keyValue).not.toContain('abc');
    expect(masked.keyValue).toMatch(/^•+$/);
  });

  test('lanza un error 500 si se intenta enmascarar una clave nula', () => {
    expect(() => maskApiKeyValue(null)).toThrow();
  });
});

describe('Descifrado de la clave embebida (decryptApiKeyValue)', () => {
  test('descifra el campo keyValue de un objeto API Key', () => {
    const apiKey = { description: 'mi clave', keyValue: encrypt('sk-embedded') };

    const result = decryptApiKeyValue(apiKey);

    expect(result.keyValue).toBe('sk-embedded');
  });

  test('lanza un error 500 si el objeto no contiene valor de clave', () => {
    expect(() => decryptApiKeyValue({ description: 'sin valor' })).toThrow('Corrupted API Key data detected.');
  });
});
