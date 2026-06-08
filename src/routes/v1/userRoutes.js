import express from 'express';
import {
  login,
  register,
  createUser,
  getUserById,
  getUsers,
  updateUser,
  deleteUser,
  getUserByEmail,
  updateProfile,
  changePassword,
} from '../../controllers/v1/userController.js';

import { requireAdmin, requireInternToken, requireJwtAuthentication } from '../../middlewares/auth.js';
import { requireValidTurnstileToken } from '../../middlewares/turnstile.js';
const router = express.Router();

// POST
router.post('/login', requireValidTurnstileToken, login);
router.post('/register', requireValidTurnstileToken, register);
router.post('/', requireAdmin, createUser);
// GET
router.get('/', requireAdmin, getUsers);
router.get('/email/:email', requireAdmin, getUserByEmail);
router.get('/intern/:id', requireInternToken, getUserById);
router.get('/:id', requireAdmin, getUserById);
// PUT
router.put('/profile/update', requireJwtAuthentication, updateProfile);
router.put('/profile/change-password', requireJwtAuthentication, changePassword);
router.put('/:id', requireJwtAuthentication, updateUser);

// DELETE
router.delete('/:id', requireAdmin, deleteUser);

export default router;
