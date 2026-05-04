import express from 'express';
import {
  login,
  createUser,
  getUserById,
  getUsers,
  updateUser,
  deleteUser,
  getUserByEmail,
  updateProfile,
  changePassword,
} from '../../controllers/v1/userController.js';

import { requireAdmin, requireJwtAuthentication } from '../../middlewares/auth.js';
const router = express.Router();

// POST
router.post('/login', login);
router.post('/', requireAdmin, createUser);
// GET
router.get('/', requireAdmin, getUsers);
router.get('/email/:email', requireAdmin, getUserByEmail);
router.get('/:id', requireAdmin, getUserById);
// PUT
router.put('/profile/update', requireJwtAuthentication, updateProfile);
router.put('/profile/change-password', requireJwtAuthentication, changePassword);
router.put('/:id', requireJwtAuthentication, updateUser);

// DELETE
router.delete('/:id', requireAdmin, deleteUser);

export default router;
