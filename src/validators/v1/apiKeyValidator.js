import Joi from 'joi';

const PROVIDER_CONFIG = {
  openai: {
    regex: /^sk-[a-zA-Z0-9_-]+$/,
    error: 'La API Key no se corresponde con el formato de OpenAI (debe empezar por "sk-").'
  },
  gemini: {
    regex: /^AIzaSy[a-zA-Z0-9_-]+$/,
    error: 'La API Key no se corresponde con el formato de Gemini (debe empezar por "AIzaSy").'
  },
  anthropic: {
    regex: /^sk-ant-[a-zA-Z0-9_-]+$/,
    error: 'La API Key no se corresponde con el formato de Anthropic (debe empezar por "sk-ant-").'
  },
  ollama: {
    regex: /^.+$/,
    error: 'La API Key para Ollama puede contener cualquier carácter.'
}
};

const localProviderErrorMessages = {
    'string.empty': 'Para un provider local, la Base URL no puede enviarse vacía.',
    'any.invalid': 'Para un provider local, la Base URL no puede enviarse vacía.',
    'string.base': 'Para un provider local, la Base URL no puede ser nula.',
    'string.uri': 'La Base URL debe ser un enlace válido (ej: http://localhost:11434).'
  };

const providerSchema = Joi.string()
  .valid(...Object.keys(PROVIDER_CONFIG))
  .messages({
    'any.only': 'Ese provider no lo gestionamos en el sistema.'
  });

  const keyValueSchema = Joi.string().when('provider', {
  switch: Object.entries(PROVIDER_CONFIG).map(([name, config]) => ({
    is: name,
    then: Joi.string().pattern(config.regex).messages({
      'string.pattern.base': config.error
    })
  }))
});

// Cada vez que se añada un provider local habria que meterlo en el switch y en el PROVIDER_CONFIG
export const createApiKeyValidator = Joi.object({
  description: Joi.string().required(),
  provider: providerSchema.required(),
  baseUrl: Joi.string().uri().optional().allow(null, '').when('provider', {
    switch: [
      { is: 'ollama', then: Joi.string().uri().required().invalid(null, '').messages(localProviderErrorMessages) },
    ]
  }),
  keyValue: keyValueSchema.required(),
  managementUrl: Joi.string().uri().allow(null, '').optional(),
  // Default model to use with this key (one-time choice; consumers preselect it).
  model: Joi.string().allow(null, '').optional(),
  isActive: Joi.boolean().required(),
  isDefault: Joi.boolean().required(),
});

export const updateApiKeyValidator = Joi.object({
  description: Joi.string().optional(),
  provider: providerSchema.optional(),
  baseUrl: Joi.string().uri().allow(null, '').optional().when('provider', {
    switch: [
      { is: 'ollama', then: Joi.string().uri().optional().invalid(null,'').messages(localProviderErrorMessages) },
    ]
  }),
  keyValue: keyValueSchema.optional().allow(null, ''),
  managementUrl: Joi.string().uri().allow(null, '').optional(),
  model: Joi.string().allow(null, '').optional(),
  isActive: Joi.boolean().optional(),
})
.min(1)
.with('keyValue', 'provider')
.messages({
  'object.with': 'Para actualizar la API Key, es obligatorio enviar también el provider asociado para validarla.'
});
