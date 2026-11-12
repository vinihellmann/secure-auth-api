import {
  STRONG_PASSWORD,
  client,
  loginAdmin,
  registerAndLogin,
  startApp,
  uniqueEmail,
  type TestContext,
} from './helpers';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startApp();
});

afterAll(async () => {
  await ctx?.container.close();
});

describe('probes and discovery', () => {
  it('serves health, readiness and a JWKS with every rotation key', async () => {
    const api = client(ctx);
    expect((await api.get('/health')).status).toBe(200);

    const ready = await api.get('/ready');
    expect(ready.status).toBe(200);
    expect(ready.body.checks).toEqual({ postgres: true, redis: true });

    const jwks = await api.get('/.well-known/jwks.json');
    expect(jwks.status).toBe(200);
    expect(jwks.headers['cache-control']).toContain('max-age');
    const kids = jwks.body.keys.map((k: { kid: string }) => k.kid);
    expect(kids).toEqual(expect.arrayContaining(['k1', 'k2']));
    expect(jwks.body.keys.every((k: Record<string, unknown>) => !('d' in k))).toBe(true);
  });

  it('answers unknown routes and bad input with problem+json', async () => {
    const api = client(ctx);
    const missing = await api.get('/v1/nope');
    expect(missing.status).toBe(404);
    expect(missing.headers['content-type']).toContain('application/problem+json');

    const invalid = await api.post('/v1/auth/register', { email: 'not-an-email', password: 'x' });
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe('validation_error');

    const big = await api.post('/v1/auth/login', { email: 'a@b.co', password: 'x'.repeat(20_000) });
    expect(big.status).toBe(413);
  });
});

describe('registration and login', () => {
  it('registers, logs in and returns the profile', async () => {
    const user = await registerAndLogin(ctx);
    const me = await client(ctx).get('/v1/me', user.accessToken);
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({ id: user.id, email: user.email, roles: ['user'], mfaEnabled: false });
  });

  it('rejects duplicate emails and weak passwords', async () => {
    const api = client(ctx);
    const email = uniqueEmail();
    expect((await api.post('/v1/auth/register', { email, password: STRONG_PASSWORD })).status).toBe(201);
    const dup = await api.post('/v1/auth/register', { email: email.toUpperCase(), password: STRONG_PASSWORD });
    expect(dup.status).toBe(409);

    const weak = await client(ctx).post('/v1/auth/register', { email: uniqueEmail(), password: 'password1234' });
    expect(weak.status).toBe(400);
  });

  it('requires a valid bearer token', async () => {
    const api = client(ctx);
    expect((await api.get('/v1/me')).status).toBe(401);
    const bad = await api.get('/v1/me', 'not.a.jwt');
    expect(bad.status).toBe(401);
    expect(bad.headers['www-authenticate']).toBe('Bearer');
  });
});

describe('refresh token rotation', () => {
  it('rotates on every use', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);

    const first = await api.post('/v1/auth/refresh', { refreshToken: user.refreshToken });
    expect(first.status).toBe(200);
    expect(first.headers['cache-control']).toBe('no-store');
    expect(first.body.refreshToken).not.toBe(user.refreshToken);

    const second = await api.post('/v1/auth/refresh', { refreshToken: first.body.refreshToken });
    expect(second.status).toBe(200);
    expect((await api.get('/v1/me', second.body.accessToken)).status).toBe(200);
  });

  it('detects reuse of a rotated token and revokes the whole family', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);

    const rotated = await api.post('/v1/auth/refresh', { refreshToken: user.refreshToken });
    expect(rotated.status).toBe(200);

    // An attacker replays the old token.
    const reuse = await api.post('/v1/auth/refresh', { refreshToken: user.refreshToken });
    expect(reuse.status).toBe(401);
    expect(reuse.body.code).toBe('refresh_token_reused');

    // The legitimate client's newer token is dead too, and so is its access token.
    const victim = await api.post('/v1/auth/refresh', { refreshToken: rotated.body.refreshToken });
    expect(victim.status).toBe(401);
    const me = await api.get('/v1/me', rotated.body.accessToken);
    expect(me.status).toBe(401);
    expect(me.body.code).toBe('session_revoked');
  });

  it('serializes concurrent refreshes of the same token (row lock): one wins', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);
    const results = await Promise.all([
      api.post('/v1/auth/refresh', { refreshToken: user.refreshToken }),
      api.post('/v1/auth/refresh', { refreshToken: user.refreshToken }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('rejects unknown refresh tokens', async () => {
    const res = await client(ctx).post('/v1/auth/refresh', { refreshToken: 'x'.repeat(43) });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('invalid_refresh_token');
  });
});

describe('sessions', () => {
  it('lists sessions and revokes another device, killing its access token immediately', async () => {
    const user = await registerAndLogin(ctx);
    const laptop = client(ctx);
    const phoneLogin = await laptop.post('/v1/auth/login', { email: user.email, password: user.password });
    const phoneToken = phoneLogin.body.accessToken as string;

    const list = await laptop.get('/v1/sessions', user.accessToken);
    expect(list.status).toBe(200);
    expect(list.body.items).toHaveLength(2);
    const other = list.body.items.find((s: { current: boolean }) => !s.current);

    expect((await laptop.get('/v1/me', phoneToken)).status).toBe(200);
    expect((await laptop.delete(`/v1/sessions/${other.id}`, user.accessToken)).status).toBe(204);

    const revoked = await laptop.get('/v1/me', phoneToken);
    expect(revoked.status).toBe(401);
    expect(revoked.body.code).toBe('session_revoked');
    const refresh = await laptop.post('/v1/auth/refresh', { refreshToken: phoneLogin.body.refreshToken });
    expect(refresh.status).toBe(401);
    expect((await laptop.get('/v1/me', user.accessToken)).status).toBe(200);
  });

  it('logout revokes the current session', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);
    expect((await api.post('/v1/auth/logout', undefined, user.accessToken)).status).toBe(204);
    expect((await api.get('/v1/me', user.accessToken)).status).toBe(401);
    expect((await api.post('/v1/auth/refresh', { refreshToken: user.refreshToken })).status).toBe(401);
  });

  it('changing the password revokes every other session but keeps the current one', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);
    const other = await api.post('/v1/auth/login', { email: user.email, password: user.password });

    const wrong = await api.post(
      '/v1/me/password',
      { currentPassword: 'nope', newPassword: 'Another-Strong-7-Secret' },
      user.accessToken,
    );
    expect(wrong.status).toBe(403);

    const changed = await api.post(
      '/v1/me/password',
      { currentPassword: user.password, newPassword: 'Another-Strong-7-Secret' },
      user.accessToken,
    );
    expect(changed.status).toBe(204);

    expect((await api.get('/v1/me', other.body.accessToken)).status).toBe(401);
    expect((await api.get('/v1/me', user.accessToken)).status).toBe(200);

    const oldPassword = await api.post('/v1/auth/login', { email: user.email, password: user.password });
    expect(oldPassword.status).toBe(401);
    const newPassword = await api.post('/v1/auth/login', {
      email: user.email,
      password: 'Another-Strong-7-Secret',
    });
    expect(newPassword.status).toBe(200);
  });
});

describe('RBAC and admin actions', () => {
  it('keeps admin routes away from regular users', async () => {
    const user = await registerAndLogin(ctx);
    const res = await client(ctx).get('/v1/admin/audit-events', user.accessToken);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('insufficient_role');
  });

  it('locks a user (revoking sessions) and unlocks them', async () => {
    const adminToken = await loginAdmin(ctx);
    const user = await registerAndLogin(ctx);
    const api = client(ctx);

    expect((await api.post(`/v1/admin/users/${user.id}/lock`, undefined, adminToken)).status).toBe(204);
    expect((await api.get('/v1/me', user.accessToken)).status).toBe(401);
    const blocked = await api.post('/v1/auth/login', { email: user.email, password: user.password });
    expect(blocked.status).toBe(403);
    expect(blocked.body.code).toBe('account_locked');

    expect((await api.post(`/v1/admin/users/${user.id}/unlock`, undefined, adminToken)).status).toBe(204);
    expect((await api.post('/v1/auth/login', { email: user.email, password: user.password })).status).toBe(200);
  });
});
