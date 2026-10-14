import Joi from 'joi';

const email = Joi.string().email().required();
const password = Joi.string().required();
const newPassword = password; // Luego definimos los requisitos de newPassword
const role = Joi.string().valid('admin', 'instructor', 'advanced').required();
const useSystemApiKey = Joi.boolean().default(true);

export const credentialsValidator = Joi.object({
  email,
  password,
});

export const registrationValidator = Joi.object({
  email,
  password: newPassword,
});

export const createUserValidator = registrationValidator.keys({
  role,
  useSystemApiKey,
});

export const updateUserValidator = Joi.object({
  email: email.optional(),
  password: newPassword.optional(),
  role: role.optional(),
  useSystemApiKey: useSystemApiKey.optional(),
});
