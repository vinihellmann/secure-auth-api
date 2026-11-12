import { z } from 'zod';

export const emailSchema = z.string().trim().toLowerCase().email().max(254);

/**
 * Password policy: 12-128 chars, mixed case, digit and symbol, at most 72 bytes
 * (bcrypt silently truncates beyond 72 bytes, so longer input is rejected, not truncated),
 * and no trivially guessable "password" substring.
 */
export const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters')
  .regex(/[a-z]/, 'Password must contain a lowercase letter')
  .regex(/[A-Z]/, 'Password must contain an uppercase letter')
  .regex(/\d/, 'Password must contain a digit')
  .regex(/[^A-Za-z0-9]/, 'Password must contain a symbol')
  .refine((p) => Buffer.byteLength(p, 'utf8') <= 72, 'Password must be at most 72 bytes')
  .refine((p) => !/password/i.test(p), 'Password must not contain the word "password"');

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(1024),
  newPassword: passwordSchema,
});

export const userIdParamSchema = z.object({ id: z.string().uuid() });
