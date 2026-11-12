import { passwordSchema } from './users.schemas';
import type { PasswordHasher } from './password-hasher';
import type { UsersRepository } from './users.repository';

/**
 * Idempotently ensures the admin account from ADMIN_EMAIL / ADMIN_PASSWORD exists
 * and has the admin role. An existing account's password is never overwritten.
 */
export async function seedAdmin(
  users: UsersRepository,
  hasher: PasswordHasher,
  admin: { email: string; password: string },
): Promise<'created' | 'promoted' | 'unchanged'> {
  const existing = await users.findByEmail(admin.email);
  if (existing) {
    if (existing.roles.includes('admin')) return 'unchanged';
    await users.setRoles(existing.id, [...new Set([...existing.roles, 'admin'])]);
    return 'promoted';
  }
  const parsed = passwordSchema.safeParse(admin.password);
  if (!parsed.success) {
    throw new Error(
      `ADMIN_PASSWORD does not satisfy the password policy: ${parsed.error.issues
        .map((i) => i.message)
        .join('; ')}`,
    );
  }
  await users.create({
    email: admin.email,
    passwordHash: await hasher.hash(admin.password),
    roles: ['user', 'admin'],
  });
  return 'created';
}
