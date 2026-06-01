import express from 'express';
import {
  createApiKey,
  getApiKeys,
  deleteApiKey,
  updateApiKey,
  getApiKeyById,
  manageDefaultKey,
  getApiKeyDataForLeiaRunner,
  isCompatibleApiKeyProviderForLeiaRunner,
  createSystemApiKey,
  updateSystemApiKey,
  deleteSystemApiKey
} from '../../controllers/v1/apiKeyController.js';

import { requireAdmin, requireInternToken, requireUserApiKeyManagement } from '../../middlewares/auth.js';

const router = express.Router();

// RUTAS INTERNAS (Comunicación entre microservicios)
router.post('/get-value', requireInternToken, getApiKeyDataForLeiaRunner);
router.post('/validate-provider', requireInternToken, isCompatibleApiKeyProviderForLeiaRunner);
// RUTAS DE SYSTEM API KEYS (Solo Admin)
router.post('/system', requireAdmin, createSystemApiKey);
router.put('/system/:id', requireAdmin, updateSystemApiKey);
router.delete('/system/:id', requireAdmin, deleteSystemApiKey);


// RUTAS DE USER API KEYS (Instructor / Advanced / Admin)

// POST
router.post('/', requireUserApiKeyManagement, createApiKey);

// GET
router.get('/', requireUserApiKeyManagement, getApiKeys);
router.get('/:apiKeyId', requireUserApiKeyManagement, getApiKeyById);

// PUT
router.put('/manage-default/:apiKeyId', requireUserApiKeyManagement, manageDefaultKey);
router.put('/:apiKeyId', requireUserApiKeyManagement, updateApiKey);

// DELETE
router.delete('/:apiKeyId', requireUserApiKeyManagement, deleteApiKey);

export default router;
