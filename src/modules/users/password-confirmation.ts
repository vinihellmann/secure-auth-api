import { tooManyRequests } from '../../shared/errors';
import type { LoginLockout } from '../auth/lockout';
import type { PasswordHasher } from './password-hasher';

/**
 * Re-authentication for sensitive actions by an already-authenticated user (change password,
 * disable 2FA). Failures are rate-limited per user so a stolen access token cannot be used to
 * brute-force the current password.
 */
export class PasswordConfirmer {
  constructor(
    private readonly hasher: PasswordHasher,
    private readonly lockout: LoginLockout,
  ) {}

  /** Throws 429 while locked. Returns whether the password matched. */
  async confirm(userId: string, password: string, passwordHash: string): Promise<boolean> {
    const key = `reauth:${userId}`;
    const lockedForMs = await this.lockout.remainingLockMs(key);
    if (lockedForMs > 0) {
      throw tooManyRequests(
        lockedForMs / 1000,
        'too_many_failed_attempts',
        'Too many failed attempts, try again later',
      );
    }
    if (await this.hasher.verify(password, passwordHash)) {
      await this.lockout.reset(key);
      return true;
    }
    await this.lockout.registerFailure(key);
    return false;
  }
}
