import express from 'express';
import {
  createApiKey,
  getApiKeys,
  deleteApiKey,
  updateApiKey,
  getApiKeyById,
  manageDefaultKey,
  getApiKeyValueForLeiaRunner,
  createSystemApiKey,
  updateSystemApiKey,
  deleteSystemApiKey
} from '../../controllers/v1/apiKeyController.js';

import { requireAdmin, requireAdvanced, requireInternToken } from '../../middlewares/auth.js';

const router = express.Router();

// RUTAS INTERNAS (Comunicación entre microservicios)
router.post('/get-value', requireInternToken, getApiKeyValueForLeiaRunner);

// RUTAS DE SYSTEM API KEYS (Solo Admin)
router.post('/system', requireAdmin, createSystemApiKey);
router.put('/system/:id', requireAdmin, updateSystemApiKey);
router.delete('/system/:id', requireAdmin, deleteSystemApiKey);


// RUTAS DE USER API KEYS (Advanced / Admin)

// POST
router.post('/', requireAdvanced, createApiKey);

// GET
router.get('/', requireAdvanced, getApiKeys);
router.get('/:apiKeyId', requireAdvanced, getApiKeyById);

// PUT
router.put('/manage-default/:apiKeyId', requireAdvanced, manageDefaultKey);
router.put('/:apiKeyId', requireAdvanced, updateApiKey);

// DELETE
router.delete('/:apiKeyId', requireAdvanced, deleteApiKey);

export default router;