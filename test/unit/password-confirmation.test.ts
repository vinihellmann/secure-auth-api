import { LoginLockout, type LockoutStore } from '../../src/modules/auth/lockout';
import { PasswordConfirmer } from '../../src/modules/users/password-confirmation';
import type { PasswordHasher } from '../../src/modules/users/password-hasher';
import { AppError } from '../../src/shared/errors';

class MemoryLockoutStore implements LockoutStore {
  failures = new Map<string, number>();
  locks = new Map<string, number>();
  async getLockTtlMs(key: string) {
    return this.locks.get(key) ?? 0;
  }
  async incrementFailures(key: string) {
    const n = (this.failures.get(key) ?? 0) + 1;
    this.failures.set(key, n);
    return n;
  }
  async setLock(key: string, ms: number) {
    this.locks.set(key, ms);
  }
  async clear(key: string) {
    this.failures.delete(key);
    this.locks.delete(key);
  }
}

const hasher: PasswordHasher = {
  hash: async (p) => `h:${p}`,
  verify: async (p, h) => h === `h:${p}`,
  needsRehash: () => false,
};

function setup() {
  const store = new MemoryLockoutStore();
  return { store, confirmer: new PasswordConfirmer(hasher, new LoginLockout(store)) };
}

describe('PasswordConfirmer', () => {
  it('returns true and resets the counter on success', async () => {
    const { store, confirmer } = setup();
    await confirmer.confirm('u1', 'bad', 'h:good');
    await confirmer.confirm('u1', 'bad', 'h:good');
    expect(store.failures.get('reauth:u1')).toBe(2);
    await expect(confirmer.confirm('u1', 'good', 'h:good')).resolves.toBe(true);
    expect(store.failures.has('reauth:u1')).toBe(false);
  });

  it('locks after the threshold, even for the correct password', async () => {
    const { store, confirmer } = setup();
    for (let i = 0; i < 5; i++) {
      await expect(confirmer.confirm('u1', 'bad', 'h:good')).resolves.toBe(false);
    }
    expect(store.locks.get('reauth:u1')).toBeGreaterThan(0);
    const err = await confirmer.confirm('u1', 'good', 'h:good').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect((err as AppError).status).toBe(429);
    expect((err as AppError).code).toBe('too_many_failed_attempts');
  });

  it('keeps counters per user', async () => {
    const { confirmer } = setup();
    for (let i = 0; i < 5; i++) await confirmer.confirm('u1', 'bad', 'h:good');
    await expect(confirmer.confirm('u2', 'good', 'h:good')).resolves.toBe(true);
  });
});
