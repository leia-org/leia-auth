import User from '../../models/User.js';
import SystemApiKey from '../../models/SystemApiKey.js';

class ApiKeyRepository {

  // SYSTEM API KEYS

  async findAllSystemKeys() {
    return await SystemApiKey.find();
  }

  async findDefaultSystemKey() {
    return await SystemApiKey.findOne({ isActive: true }).sort({ createdAt: 1, _id: 1 });
  }

  async findSystemKeyById(id) {
    return await SystemApiKey.findById(id);
  }

  async createSystemKey(data) {
    const systemApiKey = new SystemApiKey(data);
    return await systemApiKey.save();
  }

  async updateSystemKey(id, data) {
    return await SystemApiKey.findByIdAndUpdate(id, data, { new: true });
  }

  async deleteSystemKey(id) {
    return await SystemApiKey.findByIdAndDelete(id);
  }

  // USER API KEYS

  async getApiKeyById(userId, apiKeyId) {
    const user = await User.findById(userId);
    if (!user) return null;
    return user.apiKeys.id(apiKeyId);
  }

  async addApiKey(userId, apiKeyData) {
    return await User.findByIdAndUpdate(
      userId,
      { $push: { apiKeys: apiKeyData } },
      { new: true }
    );
  }

  async updateApiKey(userId, apiKeyId, apiKeyData) {
    const user = await User.findById(userId);
    if (!user) return null;

    const apiKey = user.apiKeys.id(apiKeyId);
    if (!apiKey) return null;
    // eslint-disable-next-line no-unused-vars
    const { _id, id, createdAt, updatedAt, ...safeData } = apiKeyData;
    apiKey.set(safeData);
    await user.save();
    return apiKey;
  }

  async markApiKeyAsDefault(userId, apiKeyId) {
    const updatedUser = await User.findOneAndUpdate(
      { _id: userId, 'apiKeys._id': apiKeyId },
      {
        $set: {
          'apiKeys.$[others].isDefault': false,
          'apiKeys.$[target].isDefault': true,
          isSystemApiKeyDefault: false,
          defaultSystemApiKeyId: null
        }
      },
      { new: true, arrayFilters: [{'others._id': { $ne: apiKeyId }},{ 'target._id': apiKeyId }] }
    );
    return updatedUser;
  }

  async unmarkApiKeyDefault(userId, apiKeyId) {
    const updatedUser = await User.findOneAndUpdate(
      { _id: userId, 'apiKeys._id': apiKeyId },
      { $set: { 'apiKeys.$[target].isDefault': false } },
      { new: true, arrayFilters: [{ 'target._id': apiKeyId }] }
    );
    return updatedUser;
  }

  async setSystemApiKeyDefault(userId, apiKeyId, isDefault = true) {
    const user = await User.findById(userId);
    if (!user) return null;

    if (isDefault) {
      user.apiKeys.forEach(apiKey => {
        apiKey.isDefault = false;
      });
      user.useSystemApiKey = true;
      user.isSystemApiKeyDefault = true;
      user.defaultSystemApiKeyId = apiKeyId;
    } else {
      user.isSystemApiKeyDefault = false;
      user.defaultSystemApiKeyId = null;
    }

    return await user.save();
  }

  async enableSystemApiKey(userId, apiKeyId = null) {
    const update = apiKeyId
      ? { useSystemApiKey: true, isSystemApiKeyDefault: true, defaultSystemApiKeyId: apiKeyId }
      : { useSystemApiKey: true };

    return await User.findByIdAndUpdate(userId, { $set: update }, { new: true });
  }

  async setSystemApiKeyDefaultForAllUsers(apiKeyId) {
    const users = await User.find();
    for (const user of users) {
      user.apiKeys.forEach(apiKey => {
        apiKey.isDefault = false;
      });
      user.useSystemApiKey = true;
      user.isSystemApiKeyDefault = true;
      user.defaultSystemApiKeyId = apiKeyId;
      await user.save();
    }
    return { modifiedCount: users.length };
  }

  async clearSystemKeyFromAllUsers(systemApiKeyId) {
    const result = await User.updateMany(
      { defaultSystemApiKeyId: systemApiKeyId },
      {
        $set: {
          defaultSystemApiKeyId: null,
          isSystemApiKeyDefault: false
        }
      }
    );
    return result;
  }

  async deleteApiKey(userId, apiKeyId) {
    const result = await User.updateOne(
      {
        _id: userId,
        "apiKeys._id": apiKeyId
      },
      {
        $pull: { apiKeys: { _id: apiKeyId } }
      }
    );
    if (result.modifiedCount > 0) {
      return [true, "API Key deleted successfully"];
    }
    const userExists = await User.exists({ _id: userId });
    if (!userExists) {
      return [false, "User not found"];
    } else {
      return [false, "API Key not found"];
    }
  }
}

export default new ApiKeyRepository();
