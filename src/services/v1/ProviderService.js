import axios from 'axios';
class ProviderService {

    async verifyApiKeyIntegrity(provider, keyValue) {
        switch (provider) {
        case 'openai':
            return await this.verifyOpenAIApiKey(keyValue);
        case 'gemini':
            return await this.verifyGeminiApiKey(keyValue);
        case 'ollama':
            return true;
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
}
export default new ProviderService();