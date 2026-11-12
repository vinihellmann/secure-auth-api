import type { Request, RequestHandler } from 'express';
import type { RateLimiter } from '../../infra/rate-limit/sliding-window';
import { tooManyRequests } from '../../shared/errors';

export interface RatePolicy {
  name: string;
  limit: number;
  windowMs: number;
  /** Bucket key for the request; defaults to the client IP. */
  key?: (req: Request) => string;
}

/**
 * Route-level policies. Login is limited per IP here and additionally per account by the
 * lockout; registration is the most expensive endpoint (bcrypt cost 12), hence the tight limit.
 */
export const POLICIES = {
  global: { name: 'global', limit: 300, windowMs: 60_000 },
  register: { name: 'register', limit: 5, windowMs: 60 * 60_000 },
  login: { name: 'login', limit: 10, windowMs: 60_000 },
  loginMfa: { name: 'login_mfa', limit: 10, windowMs: 60_000 },
  refresh: { name: 'refresh', limit: 30, windowMs: 60_000 },
  sensitive: { name: 'sensitive', limit: 10, windowMs: 60_000 },
} satisfies Record<string, RatePolicy>;

/**
 * Applies a sliding-window policy and advertises it with the IETF RateLimit headers
 * (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy`).
 */
export function rateLimit(
  limiter: RateLimiter,
  policy: RatePolicy,
  enabled = true,
): RequestHandler {
  const windowSeconds = Math.ceil(policy.windowMs / 1000);
  return async (req, res, next) => {
    if (!enabled) {
      next();
      return;
    }
    const subject = policy.key ? policy.key(req) : (req.ip ?? 'unknown');
    const decision = await limiter.consume(
      `rl:${policy.name}:${subject}`,
      policy.limit,
      policy.windowMs,
    );
    const resetSeconds = Math.ceil(decision.resetMs / 1000);

    res.setHeader('RateLimit-Limit', String(decision.limit));
    res.setHeader('RateLimit-Remaining', String(decision.remaining));
    res.setHeader('RateLimit-Reset', String(resetSeconds));
    res.setHeader('RateLimit-Policy', `${policy.limit};w=${windowSeconds}`);

    if (!decision.allowed) {
      throw tooManyRequests(resetSeconds, 'rate_limited', 'Too many requests, slow down');
    }
    next();
  };
}
