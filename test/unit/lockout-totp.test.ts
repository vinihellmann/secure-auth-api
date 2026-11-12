import { randomBytes } from 'node:crypto';
import { MacKeyring } from '../../src/infra/crypto/mac';
import { sha256Hex } from '../../src/infra/crypto/hash';
import {
  DEFAULT_LOCKOUT_POLICY,
  LoginLockout,
  lockDurationMs,
  type LockoutStore,
} from '../../src/modules/auth/lockout';
import {
  TotpVerifier,
  codeForStep,
  generateTotpSecret,
  matchTotp,
  timeStep,
  type TotpStepStore,
} from '../../src/modules/mfa/totp';
import {
  generateRecoveryCode,
  RecoveryCodeHasher,
  normalizeRecoveryCode,
} from '../../src/modules/mfa/recovery-codes';

describe('lockDurationMs (exponential backoff)', () => {
  it.each([
    [1, 0],
    [4, 0],
    [5, 30_000],
    [6, 60_000],
    [7, 120_000],
    [9, 480_000],
    [10, 900_000], // capped at 15 min
    [50, 900_000],
  ])('%i failures -> %i ms', (failures, expected) => {
    expect(lockDurationMs(failures, DEFAULT_LOCKOUT_POLICY)).toBe(expected);
  });
});

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

describe('LoginLockout', () => {
  it('locks after the threshold with growing durations and resets on success', async () => {
    const store = new MemoryLockoutStore();
    const lockout = new LoginLockout(store);
    const applied: number[] = [];
    for (let i = 0; i < 7; i++) applied.push(await lockout.registerFailure('login:a@example.com'));

    expect(applied).toEqual([0, 0, 0, 0, 30_000, 60_000, 120_000]);
    expect(await lockout.remainingLockMs('login:a@example.com')).toBe(120_000);

    await lockout.reset('login:a@example.com');
    expect(await lockout.remainingLockMs('login:a@example.com')).toBe(0);
    expect(store.failures.size).toBe(0);
  });
});

class MemoryStepStore implements TotpStepStore {
  last = new Map<string, number>();
  async claimStep(userId: string, step: number) {
    const prev = this.last.get(userId);
    if (prev !== undefined && prev >= step) return false;
    this.last.set(userId, step);
    return true;
  }
}

describe('TOTP', () => {
  it('matches the RFC 6238 SHA-1 test vector (T = 59s)', () => {
    // base32 of the ASCII secret "12345678901234567890"
    expect(codeForStep('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', timeStep(59_000))).toBe('287082');
  });

  const secret = generateTotpSecret();
  const now = Date.UTC(2025, 5, 1, 12, 0, 10);
  const step = timeStep(now);

  it('accepts the current step and one step of drift either way', () => {
    expect(matchTotp(secret, codeForStep(secret, step), now)).toBe(step);
    expect(matchTotp(secret, codeForStep(secret, step - 1), now)).toBe(step - 1);
    expect(matchTotp(secret, codeForStep(secret, step + 1), now)).toBe(step + 1);
    expect(matchTotp(secret, codeForStep(secret, step - 2), now)).toBeNull();
    expect(matchTotp(secret, '12345', now)).toBeNull();
    expect(matchTotp(secret, 'abcdef', now)).toBeNull();
  });

  it('rejects a replayed code (anti-replay of the time-step)', async () => {
    const verifier = new TotpVerifier(new MemoryStepStore(), () => now);
    const code = codeForStep(secret, step);
    await expect(verifier.verify('user-1', secret, code)).resolves.toBe(true);
    await expect(verifier.verify('user-1', secret, code)).resolves.toBe(false);
  });

  it('rejects an older code once a newer one was used', async () => {
    const verifier = new TotpVerifier(new MemoryStepStore(), () => now);
    await expect(verifier.verify('u', secret, codeForStep(secret, step + 1))).resolves.toBe(true);
    await expect(verifier.verify('u', secret, codeForStep(secret, step))).resolves.toBe(false);
  });

  it('tracks steps per user', async () => {
    const verifier = new TotpVerifier(new MemoryStepStore(), () => now);
    const code = codeForStep(secret, step);
    await expect(verifier.verify('alice', secret, code)).resolves.toBe(true);
    await expect(verifier.verify('bob', secret, code)).resolves.toBe(true);
  });
});

describe('recovery codes', () => {
  const keyring = new MacKeyring(
    new Map([
      ['1', randomBytes(32)],
      ['2', randomBytes(32)],
    ]),
    '2',
  );
  const hasher = new RecoveryCodeHasher(keyring);

  it('generates readable, unique codes and normalizes them', () => {
    const codes = new Set(Array.from({ length: 50 }, generateRecoveryCode));
    expect(codes.size).toBe(50);
    for (const code of codes) expect(code).toMatch(/^[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$/);

    const [code] = [...codes] as [string];
    expect(normalizeRecoveryCode(code.toLowerCase())).toBe(code.replace('-', ''));
    expect(hasher.hash('u1', code.toLowerCase().replace('-', ' '))).toBe(hasher.hash('u1', code));
  });

  it('hashes as m1.<activeVersion>.<64 hex>', () => {
    expect(hasher.hash('u1', 'ABCDE-FGHJK')).toMatch(/^m1\.2\.[0-9a-f]{64}$/);
  });

  it('binds the hash to the user', () => {
    expect(hasher.hash('u1', 'ABCDE-FGHJK')).not.toBe(hasher.hash('u2', 'ABCDE-FGHJK'));
  });

  it('depends on the server key', () => {
    const other = new RecoveryCodeHasher(new MacKeyring(new Map([['2', randomBytes(32)]]), '2'));
    expect(other.hash('u1', 'ABCDE-FGHJK')).not.toBe(hasher.hash('u1', 'ABCDE-FGHJK'));
  });

  it('lists candidates for every key version plus the legacy unsalted hash', () => {
    const candidates = hasher.candidates('u1', 'abcde fghjk');
    expect(candidates).toHaveLength(3);
    expect(candidates).toContain(hasher.hash('u1', 'ABCDE-FGHJK'));
    expect(candidates.some((c) => c.startsWith('m1.1.'))).toBe(true);
    expect(candidates).toContain(sha256Hex('ABCDEFGHJK'));
  });
});
