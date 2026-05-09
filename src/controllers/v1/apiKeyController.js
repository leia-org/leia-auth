import ApiKeyService from '../../services/v1/ApiKeyService.js';
import ProviderService from '../../services/v1/ProviderService.js';
import { createApiKeyValidator, updateApiKeyValidator } from '../../validators/v1/apiKeyValidator.js';

// USER API KEYS

export const createApiKey = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const value = await createApiKeyValidator.validateAsync(req.body, { abortEarly: false });
    await ProviderService.verifyApiKeyIntegrity(value.provider, value.keyValue);
    const savedApiKey = await ApiKeyService.createUserApiKey(userId, value);
    res.status(201).json(savedApiKey);
  } catch (err) {
    if (err.message.startsWith('Invalid API Key') || err.message.includes('service is not available')) {
      err.isJoi = true;
      err.details = [{
        path: ['keyValue'],
        message: err.message,
      }];
    }
    next(err);
  }
}

export const getApiKeys = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const apiKeys = await ApiKeyService.getUserApiKeys(userId);
    res.json(apiKeys);
  } catch (err) {
    next(err);
  }
}

export const deleteApiKey = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const apiKeyId = req.params.apiKeyId;
    await ApiKeyService.deleteUserApiKey(userId, apiKeyId);
    await ApiKeyService.sendRevocationRequestToRunner(apiKeyId);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
}

export const updateApiKey = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const apiKeyId = req.params.apiKeyId;
    const value = await updateApiKeyValidator.validateAsync(req.body, { abortEarly: true });

    const originalKey = await ApiKeyService.getUserApiKeyById(userId, apiKeyId);
    if(!originalKey) {
      const error = new Error('API Key not found');
      error.statusCode = 404;
      throw error;
    }

    const isProviderChanged = value.provider && value.provider !== originalKey.provider;
    const isNewKeyProvided = value.keyValue && value.keyValue !== '';
    if (isProviderChanged && !isNewKeyProvided) {
      const err = new Error('Si cambias el provider, es obligatorio introducir una nueva API Key.');
      err.isJoi = true;
      err.details = [{ path: ['keyValue'], message: err.message }];
      throw err;
    }

    if (isNewKeyProvided) {
      const providerToVerify = value.provider || originalKey.provider;
      await ProviderService.verifyApiKeyIntegrity(providerToVerify, value.keyValue);
    } else {
      delete value.keyValue;
    }
    if(!isProviderChanged) {
      delete value.provider;
    }
    const updatedKey = await ApiKeyService.updateUserApiKey(userId, apiKeyId, value);
    await ApiKeyService.sendRevocationRequestToRunner(updatedKey._id);
    res.json(updatedKey);
  } catch (err) {
    if (err.message.startsWith('Invalid API Key') || err.message.includes('service is not available')) {
        err.isJoi = true;
        err.details = [{
          path: ['keyValue'],
          message: err.message,
        }];
      }
    next(err);
  }
}

export const manageDefaultKey = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const apiKeyId = req.params.apiKeyId;
    const apiKey = await ApiKeyService.getUserApiKeyById(userId, apiKeyId);
    let updatedKey = null;
    if (apiKey.isDefault) {
      updatedKey = await ApiKeyService.unMarkDefaultKey(userId, apiKeyId);
    } else {
      updatedKey = await ApiKeyService.markKeyAsDefault(userId, apiKeyId);
    }
    res.json(updatedKey);
  } catch (err) {
    next(err);
  }
}

export const getApiKeyById = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const apiKeyId = req.params.apiKeyId;
    const apiKey = await ApiKeyService.getUserApiKeyById(userId, apiKeyId);
    res.json(apiKey);
  } catch (err) {
    next(err);
  }
}
// INTERNAL ENDPOINTS
export const getApiKeyValueForLeiaRunner = async (req, res, next) => {
  try {
    const { provider, apiKeyId, apiKeyRequesterId } = req.body;
    const apiKey = await ApiKeyService.getUserApiKeyById(apiKeyRequesterId, apiKeyId, false);
    if (!apiKey) {
      const error = new Error('API Key not found');
      error.statusCode = 404;
      throw error;
    }
    if (apiKey.provider !== provider) {
      const error = new Error('API Key provider mismatch');
      error.statusCode = 400;
      throw error;
    }

    res.json({ keyValue: apiKey.keyValue });
  } catch (err) {
    next(err);
  }
}
export const isCompatibleApiKeyProviderForLeiaRunner = async (req, res, next) => {
  try {
    const { provider, apiKeyId, apiKeyRequesterId } = req.body;
    const apiKey = await ApiKeyService.getUserApiKeyById(apiKeyRequesterId, apiKeyId);
    if (!apiKey) {
      const error = new Error('API Key not found');
      error.statusCode = 404;
      throw error;
    }
    if (apiKey.provider !== provider) {
      const error = new Error('API Key provider mismatch');
      error.statusCode = 400;
      throw error;
    }

    res.json({ isCompatible: true });
  } catch (err) {
    next(err);
  }
}

// SYSTEM API KEYS

export const createSystemApiKey = async (req, res, next) => {
  try {
    const userId = req.auth?.payload?.id;
    const value = await createApiKeyValidator.validateAsync(req.body, { abortEarly: false });
    await ProviderService.verifyApiKeyIntegrity(value.provider, value.keyValue);
    const savedApiKey = await ApiKeyService.createSystemApiKey(userId, value);
    res.status(201).json(savedApiKey);
  } catch (err) {
    if (err.message.startsWith('Invalid API Key') || err.message.includes('service is not available')) {
        err.isJoi = true;
        err.details = [{
          path: ['keyValue'],
          message: err.message,
        }];
      }
    next(err);
  }
};

export const updateSystemApiKey = async (req, res, next) => {
  try {
    const id = req.params.id;
    const value = await updateApiKeyValidator.validateAsync(req.body, { abortEarly: true });
    if (value.keyValue && value.keyValue !== '') {
        await ProviderService.verifyApiKeyIntegrity(value.provider, value.keyValue);
    } else {
        delete value.keyValue;
    }
    const updatedKey = await ApiKeyService.updateSystemApiKey(id, value);
    await ApiKeyService.sendRevocationRequestToRunner(updatedKey._id);
    res.json(updatedKey);
  } catch (err) {
    if (err.message.startsWith('Invalid API Key') || err.message.includes('service is not available')) {
        err.isJoi = true;
        err.details = [{
          path: ['keyValue'],
          message: err.message,
        }];
      }
    next(err);
  }
};

export const deleteSystemApiKey = async (req, res, next) => {
  try {
    const id = req.params.id;

    await ApiKeyService.deleteSystemApiKey(id);
    await ApiKeyService.sendRevocationRequestToRunner(id);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
};