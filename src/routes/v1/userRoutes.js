import express from 'express';
import {
  login,
  logout,
  getSession,
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

import {
  requireAdmin,
  requireInternToken,
  requireJwtAuthentication,
  requireSessionAuthentication,
} from '../../middlewares/auth.js';
import { requireValidTurnstileToken } from '../../middlewares/turnstile.js';
const router = express.Router();

// POST
router.post('/login', requireValidTurnstileToken, login);
router.post('/logout', logout);
router.post('/register', requireValidTurnstileToken, register);
router.post('/', requireAdmin, createUser);
// GET
router.get('/', requireAdmin, getUsers);
router.get('/session', requireSessionAuthentication, getSession);
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
