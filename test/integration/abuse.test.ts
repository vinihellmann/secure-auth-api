import type { Response } from 'supertest';
import { client, registerAndLogin, startApp, uniqueEmail, type TestContext } from './helpers';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startApp();
});

afterAll(async () => {
  await ctx?.container.close();
});

describe('sliding-window rate limiting', () => {
  it('answers 429 with Retry-After and RateLimit headers once the login policy is exhausted', async () => {
    const api = client(ctx); // one IP, a different email each time (no lockout involved)
    const statuses: number[] = [];
    let last: Response | undefined;
    for (let i = 0; i < 11; i++) {
      last = await api.post('/v1/auth/login', { email: uniqueEmail('rl'), password: 'Wrong-Password-1!' });
      statuses.push(last.status);
    }
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(last?.status).toBe(429);
    expect(last?.body.code).toBe('rate_limited');
    expect(Number(last?.headers['retry-after'])).toBeGreaterThan(0);
    expect(last?.headers['ratelimit-limit']).toBe('10');
    expect(last?.headers['ratelimit-remaining']).toBe('0');
    expect(last?.headers['ratelimit-policy']).toBe('10;w=60');
  });

  it('keys limits per client: another IP is unaffected', async () => {
    const res = await client(ctx).post('/v1/auth/login', { email: uniqueEmail(), password: 'x' });
    expect(res.status).toBe(401);
    expect(res.headers['ratelimit-remaining']).toBe('9');
  });
});

describe('account lockout', () => {
  it('locks an account after repeated failures from any IP, with backoff', async () => {
    const user = await registerAndLogin(ctx);
    for (let i = 0; i < 5; i++) {
      const res = await client(ctx).post('/v1/auth/login', { email: user.email, password: 'Wrong-Password-1!' });
      expect(res.status).toBe(401);
    }
    // Even the correct password is refused while locked.
    const locked = await client(ctx).post('/v1/auth/login', { email: user.email, password: user.password });
    expect(locked.status).toBe(429);
    expect(locked.body.code).toBe('too_many_failed_attempts');
    const retryAfter = Number(locked.headers['retry-after']);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(30);
  });

  it('does not reveal whether an email is registered', async () => {
    const user = await registerAndLogin(ctx);
    const known = await client(ctx).post('/v1/auth/login', { email: user.email, password: 'Wrong-Password-1!' });
    const unknown = await client(ctx).post('/v1/auth/login', {
      email: uniqueEmail('ghost'),
      password: 'Wrong-Password-1!',
    });
    expect(known.status).toBe(401);
    expect(unknown.status).toBe(401);
    const strip = (b: Record<string, unknown>) => ({ ...b, requestId: undefined, instance: undefined });
    expect(strip(unknown.body)).toEqual(strip(known.body));

    // Unknown emails are locked out exactly like real ones.
    const ghost = uniqueEmail('ghost');
    for (let i = 0; i < 5; i++) await client(ctx).post('/v1/auth/login', { email: ghost, password: 'x' });
    const res = await client(ctx).post('/v1/auth/login', { email: ghost, password: 'x' });
    expect(res.status).toBe(429);
    expect(res.body.code).toBe('too_many_failed_attempts');
  });
});
