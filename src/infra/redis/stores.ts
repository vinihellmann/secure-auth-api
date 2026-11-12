import type { Redis } from 'ioredis';
import type { MfaChallengeStore } from '../../modules/auth/auth.service';
import type { LockoutStore } from '../../modules/auth/lockout';
import type { TotpStepStore } from '../../modules/mfa/totp';
import type { RevokedSessionCache } from '../../modules/sessions/sessions.service';

/** Failure counter + lock key per subject. */
export class RedisLockoutStore implements LockoutStore {
  constructor(private readonly redis: Redis) {}

  async getLockTtlMs(key: string): Promise<number> {
    const ttl = await this.redis.pttl(`lockout:lock:${key}`);
    return ttl > 0 ? ttl : 0;
  }

  async incrementFailures(key: string, ttlMs: number): Promise<number> {
    const k = `lockout:fails:${key}`;
    const res = await this.redis.multi().incr(k).pexpire(k, ttlMs).exec();
    return Number(res?.[0]?.[1] ?? 0);
  }

  async setLock(key: string, ms: number): Promise<void> {
    await this.redis.set(`lockout:lock:${key}`, '1', 'PX', ms);
  }

  async clear(key: string): Promise<void> {
    await this.redis.del(`lockout:fails:${key}`, `lockout:lock:${key}`);
  }
}

const CLAIM_STEP_LUA = `
local cur = redis.call('GET', KEYS[1])
if cur and tonumber(cur) >= tonumber(ARGV[1]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return 1
`;

type ClaimStepFn = (key: string, step: number, ttlSeconds: number) => Promise<number>;

/**
 * Atomically records the last accepted TOTP time-step per user: a step is only
 * accepted if it is strictly greater than the last one, so a code can never be
 * used twice and an older code cannot be replayed after a newer one.
 */
export class RedisTotpStepStore implements TotpStepStore {
  private readonly claim: ClaimStepFn;

  constructor(redis: Redis) {
    redis.defineCommand('totpClaimStep', { numberOfKeys: 1, lua: CLAIM_STEP_LUA });
    this.claim = (redis as unknown as { totpClaimStep: ClaimStepFn }).totpClaimStep.bind(redis);
  }

  async claimStep(userId: string, step: number, ttlSeconds: number): Promise<boolean> {
    return (await this.claim(`totp:last-step:${userId}`, step, ttlSeconds)) === 1;
  }
}

/** Revoked session ids; entries only need to outlive the access token TTL. */
export class RedisRevokedSessionCache implements RevokedSessionCache {
  constructor(
    private readonly redis: Redis,
    private readonly ttlSeconds: number,
  ) {}

  async markRevoked(sessionIds: string[]): Promise<void> {
    if (sessionIds.length === 0) return;
    const pipeline = this.redis.pipeline();
    for (const id of sessionIds) pipeline.set(`revoked:session:${id}`, '1', 'EX', this.ttlSeconds);
    await pipeline.exec();
  }

  async isRevoked(sessionId: string): Promise<boolean> {
    return (await this.redis.exists(`revoked:session:${sessionId}`)) === 1;
  }
}

/** Single-use MFA challenge ids: SET NX succeeds only for the first consumer. */
export class RedisMfaChallengeStore implements MfaChallengeStore {
  constructor(private readonly redis: Redis) {}

  async isConsumed(jti: string): Promise<boolean> {
    return (await this.redis.exists(`mfa:challenge:used:${jti}`)) === 1;
  }

  async consume(jti: string, ttlSeconds: number): Promise<boolean> {
    const res = await this.redis.set(`mfa:challenge:used:${jti}`, '1', 'EX', ttlSeconds, 'NX');
    return res === 'OK';
  }
}
