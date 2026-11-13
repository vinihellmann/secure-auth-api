import { z } from 'zod';

export const setupMfaSchema = z.object({
  password: z.string().min(1).max(1024),
});

export const enableMfaSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Code must be 6 digits'),
});

export const disableMfaSchema = z
  .object({
    password: z.string().min(1).max(1024),
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
