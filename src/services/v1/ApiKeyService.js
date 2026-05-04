import ApiKeyRepository from '../../repositories/v1/ApiKeyRepository.js';
import UserRepository from '../../repositories/v1/UserRepository.js';
import { encrypt, decryptApiKeyValue, maskApiKeyValue } from '../../utils/crypto.js';
import axios from 'axios';

class ApiKeyService {

  // MÉTODOS DE SYSTEM API KEYS

  async getAllSystemApiKeys() {
    const keys = await ApiKeyRepository.findAllSystemKeys();
    return keys.map(key => {
      const decrypted = decryptApiKeyValue(key.toObject ? key.toObject({ virtuals: true }) : key);
      return maskApiKeyValue(decrypted);
    });
  }

  async getSystemApiKeyById(id, maskValue = true) {
    const key = await ApiKeyRepository.findSystemKeyById(id);
    if (!key) return null;

    const decrypted = decryptApiKeyValue(key.toObject ? key.toObject({ virtuals: true }) : key);
    return maskValue ? maskApiKeyValue(decrypted) : decrypted;
  }

  async createSystemApiKey(userId, data) {
    const newKey = await ApiKeyRepository.createSystemKey(data);
    const decrypted = decryptApiKeyValue(newKey.toObject({ virtuals: true }));
    if (data.isDefault) {
      await ApiKeyRepository.setSystemApiKeyDefault(userId, newKey._id);
    }
    return maskApiKeyValue(decrypted);
  }

  async updateSystemApiKey(id, data) {
    if (data.provider && !data.keyValue) {
      const error = new Error('API Key value is required when updating provider');
      error.statusCode = 400;
      throw error;
    }
    const updatedKey = await ApiKeyRepository.updateSystemKey(id, data);
    if (!updatedKey) {
      const error = new Error('System API Key not found');
      error.statusCode = 404;
      throw error;
    }
    const decrypted = decryptApiKeyValue(updatedKey.toObject({ virtuals: true }));
    return maskApiKeyValue(decrypted);
  }

  async deleteSystemApiKey(id) {
    const result = await ApiKeyRepository.deleteSystemKey(id);
    if (!result) {
      const error = new Error('System API Key not found');
      error.statusCode = 404;
      throw error;
    }
    await ApiKeyRepository.clearSystemKeyFromAllUsers(id);
    return true;
  }

  async sendRevocationRequestToRunner(apiKeyId) {
    try {
      const config = {
        headers: {
          Authorization: 'Bearer ' + process.env.RUNNER_KEY,
        }
      };

      await axios.post(`${process.env.RUNNER_URL}/api/v1/revoke`, { apiKeyId }, config);
    } catch (err) {
      console.error(`Failed to send revocation request for API Key ${apiKeyId}:`, err.message);
    }
  }

  // MÉTODOS DE USER API KEYS

  async createUserApiKey(userId, apiKeyData) {
    if (!userId) {
      const error = new Error('Unauthorized');
      error.statusCode = 401;
      throw error;
    }
    apiKeyData.keyValue = encrypt(apiKeyData.keyValue);
    const editedUser = await ApiKeyRepository.addApiKey(userId, apiKeyData);
    if (!editedUser) {
      const error = new Error('User not found');
      error.statusCode = 404;
      throw error;
    }
    const newApiKey = editedUser.apiKeys[editedUser.apiKeys.length - 1];
    console.log('New API Key created with ID:', newApiKey);
    if (apiKeyData.isDefault) {
      await this.markKeyAsDefault(userId, newApiKey._id);
    }
    return this.getUserApiKeyById(userId, newApiKey._id);
  }

  async deleteUserApiKey(userId, apiKeyId) {
    if (!userId) {
      const error = new Error('Unauthorized');
      error.statusCode = 401;
      throw error;
    }

    const [isDeleted, message] = await ApiKeyRepository.deleteApiKey(userId, apiKeyId);
    if (!isDeleted) {
      const error = new Error(message);
      error.statusCode = 404;
      throw error;
    }
    return isDeleted;
  }

  async getUserApiKeys(userId) {
    if (!userId) {
      const error = new Error('Unauthorized');
      error.statusCode = 401;
      throw error;
    }

    const user = await UserRepository.findById(userId);
    if (!user) {
      const error = new Error('User not found');
      error.statusCode = 404;
      throw error;
    }
    const apiKeys = user.apiKeys.map(apiKey => {
      const decrypted = decryptApiKeyValue(apiKey.toObject({virtuals: true}));
      return maskApiKeyValue(decrypted);
    });

    if (user.useSystemApiKey) {
      const systemKeysDocs = await this.getAllSystemApiKeys();
      const systemApiKeys = systemKeysDocs.map(sysKey => {
        sysKey.isDefault = user.defaultSystemApiKeyId && user.defaultSystemApiKeyId.toString() === sysKey._id.toString();
        return sysKey;
      });

      return [...systemApiKeys, ...apiKeys];
    }

    return apiKeys;
  }

  async getUserApiKeyById(userId, apiKeyId, maskValue = true) {
    if (!userId) {
      const error = new Error('Unauthorized');
      error.statusCode = 401;
      throw error;
    }
    const user = await UserRepository.findById(userId);
    if (!user) {
      const error = new Error('User not found');
      error.statusCode = 404;
      throw error;
    }
    const systemKey = await this.getSystemApiKeyById(apiKeyId, maskValue);
    if (systemKey) {
      if (!user.useSystemApiKey) {
        const error = new Error('User does not have access to the system API keys');
        error.statusCode = 403;
        throw error;
      }
      systemKey.isDefault = user.defaultSystemApiKeyId && user.defaultSystemApiKeyId.toString() === systemKey._id.toString();
      return systemKey;
    }
    const apiKey = user.apiKeys.id(apiKeyId);
    if (!apiKey) {
      const error = new Error('API Key not found');
      error.statusCode = 404;
      throw error;
    }
    const decryptedApiKey = decryptApiKeyValue(apiKey.toObject({virtuals: true}));
    return maskValue ? maskApiKeyValue(decryptedApiKey) : decryptedApiKey;
  }

  async updateUserApiKey(userId, apiKeyId, apiKeyData) {
    if (!userId) {
      const error = new Error('Unauthorized');
      error.statusCode = 401;
      throw error;
    }
    if (apiKeyData.provider && !apiKeyData.keyValue) {
      const error = new Error('API Key value is required when updating provider');
      error.statusCode = 400;
      throw error;
    }
    if (apiKeyData.keyValue) {
      apiKeyData.keyValue = encrypt(apiKeyData.keyValue);
    }
    const updatedKey = await ApiKeyRepository.updateApiKey(userId, apiKeyId, apiKeyData);
    if (!updatedKey) {
      const error = new Error('API Key not found or does not belong to this user');
      error.statusCode = 404;
      throw error;
    }

    return this.getUserApiKeyById(userId, apiKeyId);
  }

  async markKeyAsDefault(userId, apiKeyId) {
    const systemKey = await this.getSystemApiKeyById(apiKeyId);

    if (systemKey) {
      const updatedUser = await ApiKeyRepository.setSystemApiKeyDefault(userId, apiKeyId, true);
      if (!updatedUser) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }
      return this.getUserApiKeyById(userId, apiKeyId);
    }

    const updatedUser = await ApiKeyRepository.markApiKeyAsDefault(userId, apiKeyId);
    if (!updatedUser) {
      const error = new Error('API Key not found or does not belong to this user');
      error.statusCode = 404;
      throw error;
    }

    return this.getUserApiKeyById(userId, apiKeyId);
  }

  async unMarkDefaultKey(userId, apiKeyId) {
    const systemKey = await this.getSystemApiKeyById(apiKeyId);

    if (systemKey) {
      const updatedUser = await ApiKeyRepository.setSystemApiKeyDefault(userId, apiKeyId, false);
      if (!updatedUser) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }
      return this.getUserApiKeyById(userId, apiKeyId);
    }

    const updatedUser = await ApiKeyRepository.unmarkApiKeyDefault(userId, apiKeyId);
    if (!updatedUser) {
      const error = new Error('API Key not found or does not belong to this user');
      error.statusCode = 404;
      throw error;
    }

    return this.getUserApiKeyById(userId, apiKeyId);
  }
}

export default new ApiKeyService();