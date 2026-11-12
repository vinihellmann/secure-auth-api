import { z } from 'zod';
import { emailSchema, passwordSchema } from '../users/users.schemas';

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

// Login deliberately does not apply the password policy: it must behave the same for any input.
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(1024),
});

export const loginMfaSchema = z
  .object({
    mfaToken: z.string().min(1).max(4096),
    code: z
      .string()
      .regex(/^\d{6}$/, 'Code must be 6 digits')
      .optional(),
    recoveryCode: z.string().min(8).max(32).optional(),
  })
  .refine((v) => Boolean(v.code) !== Boolean(v.recoveryCode), {
    message: 'Provide exactly one of code or recoveryCode',
    path: ['code'],
  });

export const refreshSchema = z.object({
  refreshToken: z.string().min(20).max(256),
});
