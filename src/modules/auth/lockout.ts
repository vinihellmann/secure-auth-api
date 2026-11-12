/** Storage port for failed-login counters and temporary locks (Redis in production). */
export interface LockoutStore {
  /** Remaining lock time in ms, 0 when not locked. */
  getLockTtlMs(key: string): Promise<number>;
  /** Increments the failure counter (sliding expiry of `ttlMs`) and returns the new count. */
  incrementFailures(key: string, ttlMs: number): Promise<number>;
  setLock(key: string, ms: number): Promise<void>;
  clear(key: string): Promise<void>;
}

export interface LockoutPolicy {
  /** Failures tolerated before the first lock. */
  threshold: number;
  /** Duration of the first lock. Each further failure doubles it. */
  baseLockMs: number;
  maxLockMs: number;
  /** Failures older than this (without a new one) are forgotten. */
  failureWindowMs: number;
}

export const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  threshold: 5,
  baseLockMs: 30_000,
  maxLockMs: 15 * 60_000,
  failureWindowMs: 60 * 60_000,
};

/**
 * Exponential backoff: no lock below the threshold, then base * 2^(failures - threshold),
 * capped. With the defaults: 5 failures -> 30s, 6 -> 60s, 7 -> 2min, ... 10+ -> 15min.
 */
export function lockDurationMs(failures: number, policy: LockoutPolicy): number {
  if (failures < policy.threshold) return 0;
  const exponent = Math.min(failures - policy.threshold, 30);
  return Math.min(policy.baseLockMs * 2 ** exponent, policy.maxLockMs);
}

/**
 * Per-account lockout. The key is the normalized email whether or not the account exists, so
 * unknown and known emails behave identically (no user enumeration through lockout).
 */
export class LoginLockout {
  constructor(
    private readonly store: LockoutStore,
    private readonly policy: LockoutPolicy = DEFAULT_LOCKOUT_POLICY,
  ) {}

  remainingLockMs(key: string): Promise<number> {
    return this.store.getLockTtlMs(key);
  }

  /** Records a failure and returns the lock applied because of it (0 when none). */
  async registerFailure(key: string): Promise<number> {
    const failures = await this.store.incrementFailures(key, this.policy.failureWindowMs);
    const lockMs = lockDurationMs(failures, this.policy);
    if (lockMs > 0) await this.store.setLock(key, lockMs);
    return lockMs;
  }

  reset(key: string): Promise<void> {
    return this.store.clear(key);
  }
}
