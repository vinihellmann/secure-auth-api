import { randomUUID } from 'node:crypto';
import type { Redis } from 'ioredis';

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Milliseconds until the oldest hit leaves the window (a slot frees up). */
  resetMs: number;
}

export interface RateLimiter {
  consume(key: string, limit: number, windowMs: number): Promise<RateLimitDecision>;
}

/**
 * Sliding-window log limiter in a single atomic Lua script.
 *
 * State: one sorted set per key, score = hit timestamp (ms), member = unique id.
 *  1. ZREMRANGEBYSCORE drops hits older than the window
 *  2. ZCARD counts the hits still inside the window
 *  3. if below the limit: ZADD the new hit and PEXPIRE the key to the window length
 *  4. the oldest remaining hit tells us when the next slot frees up
 *
 * Time comes from Redis (TIME), not from the app servers, so clock skew between
 * instances cannot break the window. Unlike a fixed window there is no boundary
 * burst (2x limit across a window edge). Cost is O(log n) per hit with memory
 * bounded by `limit` entries per key.
 */
const SLIDING_WINDOW_LUA = `
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
if count < limit then
  redis.call('ZADD', KEYS[1], now, member)
  redis.call('PEXPIRE', KEYS[1], window)
  count = count + 1
  allowed = 1
end

local reset = window
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
if oldest[2] then
  reset = tonumber(oldest[2]) + window - now
end
if reset < 0 then reset = 0 end
return { allowed, limit - count, reset }
`;

type SlidingWindowFn = (
  key: string,
  windowMs: number,
  limit: number,
  member: string,
) => Promise<number[]>;

export class SlidingWindowLimiter implements RateLimiter {
  private readonly run: SlidingWindowFn;

  constructor(redis: Redis) {
    redis.defineCommand('slidingWindowConsume', { numberOfKeys: 1, lua: SLIDING_WINDOW_LUA });
    this.run = (
      redis as unknown as { slidingWindowConsume: SlidingWindowFn }
    ).slidingWindowConsume.bind(redis);
  }

  async consume(key: string, limit: number, windowMs: number): Promise<RateLimitDecision> {
    const [allowed, remaining, resetMs] = await this.run(key, windowMs, limit, randomUUID());
    return {
      allowed: Number(allowed) === 1,
      limit,
      remaining: Math.max(0, Number(remaining)),
      resetMs: Math.max(0, Number(resetMs)),
    };
  }
}
