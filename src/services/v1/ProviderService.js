import axios from 'axios';
class ProviderService {

    async verifyApiKeyIntegrity(provider, keyValue, baseUrl) {
        switch (provider) {
        case 'openai':
            return await this.verifyOpenAIApiKey(keyValue);
        case 'gemini':
            return await this.verifyGeminiApiKey(keyValue);
        case 'ollama':
            return true;
        case 'alma':
            return await this.verifyAlmaApiKey(keyValue, baseUrl);
        default:
            throw new Error('Unsupported provider. Please choose a valid provider.');
        }
    }
    async verifyOpenAIApiKey(keyValue) {
        try {
            await axios.get('https://api.openai.com/v1/models', {
                headers: {
                    Authorization: 'Bearer ' + keyValue
                }
            });
            return true;
        } catch (error) {
            if (error.response && error.response.status === 401) {
                throw new Error('OpenAI has rejected the API key. Please verify that the key is correct and has the necessary permissions.');
            }
            throw new Error('OpenAI service is not available. Please try again later.');
        }
    }

    async verifyGeminiApiKey(keyValue) {
        try {
            await axios.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${keyValue}`);
            return true;
        } catch (error) {
            if (error.response && error.response.status === 400) {
                throw new Error('Gemini has rejected the API key. Please verify that the key is correct and has the necessary permissions.');
            }
            throw new Error('Gemini service is not available. Please try again later.');
        }
    }

    // ALMA serves each model behind its own OpenAI-compatible base URL
    // (https://alma.us.es/api/models/{model}/v1). Listing that model costs no
    // quota and checks in one call both the key and that its plan covers the model.
    async verifyAlmaApiKey(keyValue, baseUrl) {
        if (!baseUrl) {
            throw new Error('ALMA Base URL is required.');
        }
        try {
            await axios.get(`${baseUrl.replace(/\/+$/, '')}/models`, {
                headers: {
                    apikey: keyValue
                }
            });
            return true;
        } catch (error) {
            const status = error.response && error.response.status;
            if (status === 401 || status === 403) {
                throw new Error('ALMA has rejected the API key. Please verify that the key is correct and that its plan includes the model of the Base URL.');
            }
            if (status === 404) {
                throw new Error('ALMA Base URL not found. Use the base URL of a single model, e.g. https://alma.us.es/api/models/{model}/v1.');
            }
            throw new Error('ALMA service is not available. Please try again later.');
        }
    }
}
export default new ProviderService();