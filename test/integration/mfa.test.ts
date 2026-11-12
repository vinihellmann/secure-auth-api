import { QueryTypes } from 'sequelize';
import { codeForStep, timeStep } from '../../src/modules/mfa/totp';
import { client, registerAndLogin, startApp, type LoggedInUser, type TestContext } from './helpers';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startApp();
});

afterAll(async () => {
  await ctx?.container.close();
});

const currentStep = (): number => timeStep(Date.now());

async function enableMfa(user: LoggedInUser): Promise<{ secret: string; recoveryCodes: string[]; step: number }> {
  const api = client(ctx);
  const setup = await api.post('/v1/mfa/totp/setup', undefined, user.accessToken);
  expect(setup.status).toBe(200);
  const secret = setup.body.secret as string;

  const step = currentStep();
  const enable = await api.post('/v1/mfa/totp/enable', { code: codeForStep(secret, step) }, user.accessToken);
  expect(enable.status).toBe(200);
  return { secret, recoveryCodes: enable.body.recoveryCodes as string[], step };
}

async function passwordStep(user: LoggedInUser): Promise<string> {
  const res = await client(ctx).post('/v1/auth/login', { email: user.email, password: user.password });
  expect(res.status).toBe(200);
  expect(res.body.mfaRequired).toBe(true);
  expect(res.body).not.toHaveProperty('accessToken');
  return res.body.mfaToken as string;
}

describe('TOTP two-factor authentication', () => {
  it('runs the full enrollment and two-step login flow', async () => {
    const user = await registerAndLogin(ctx);
    const api = client(ctx);

    const setup = await api.post('/v1/mfa/totp/setup', undefined, user.accessToken);
    expect(setup.status).toBe(200);
    expect(setup.body.otpauthUri).toMatch(/^otpauth:\/\/totp\/.+secret=/);
    expect(setup.body.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
    const secret = setup.body.secret as string;

    // The secret is stored envelope-encrypted, never in clear text.
    const [row] = await ctx.container.sequelize.query<{ secret_enc: string; status: string }>(
      'SELECT secret_enc, status FROM mfa_credentials WHERE user_id = :id',
      { type: QueryTypes.SELECT, replacements: { id: user.id } },
    );
    expect(row?.status).toBe('pending');
    expect(row?.secret_enc).toMatch(/^v1\.[A-Za-z0-9_-]+\./);
    expect(row?.secret_enc).not.toContain(secret);

    const wrong = await api.post('/v1/mfa/totp/enable', { code: '000000' }, user.accessToken);
    expect(wrong.status).toBe(400);

    const step = currentStep();
    const enabled = await api.post('/v1/mfa/totp/enable', { code: codeForStep(secret, step) }, user.accessToken);
    expect(enabled.status).toBe(200);
    expect(enabled.body.recoveryCodes).toHaveLength(10);
    expect((await api.get('/v1/me', user.accessToken)).body.mfaEnabled).toBe(true);

    // Login now stops after the password and hands out a short-lived challenge.
    const mfaToken = await passwordStep(user);

    // Anti-replay: the code used to enable 2FA cannot be used again.
    const replay = await api.post('/v1/auth/login/mfa', { mfaToken, code: codeForStep(secret, step) });
    expect(replay.status).toBe(401);
    expect(replay.body.code).toBe('invalid_mfa_code');

    // The next time-step is inside the drift window and newer than the last accepted one.
    const ok = await api.post('/v1/auth/login/mfa', { mfaToken, code: codeForStep(secret, step + 1) });
    expect(ok.status).toBe(200);
    expect((await api.get('/v1/me', ok.body.accessToken)).status).toBe(200);

    // The challenge is single use.
    const again = await api.post('/v1/auth/login/mfa', {
      mfaToken,
      recoveryCode: enabled.body.recoveryCodes[0],
    });
    expect(again.status).toBe(401);
    expect(again.body.code).toBe('invalid_mfa_token');
  });

  it('does not accept the MFA challenge as an access token', async () => {
    const user = await registerAndLogin(ctx);
    await enableMfa(user);
    const mfaToken = await passwordStep(user);
    expect((await client(ctx).get('/v1/me', mfaToken)).status).toBe(401);
  });

  it('accepts each recovery code exactly once', async () => {
    const user = await registerAndLogin(ctx);
    const { recoveryCodes } = await enableMfa(user);
    const api = client(ctx);
    const code = recoveryCodes[0] as string;

    const first = await api.post('/v1/auth/login/mfa', {
      mfaToken: await passwordStep(user),
      recoveryCode: code.toLowerCase(), // formatting-insensitive
    });
    expect(first.status).toBe(200);

    const second = await api.post('/v1/auth/login/mfa', { mfaToken: await passwordStep(user), recoveryCode: code });
    expect(second.status).toBe(401);
    expect(second.body.code).toBe('invalid_mfa_code');

    const [{ unused }] = (await ctx.container.sequelize.query(
      'SELECT count(*)::int AS unused FROM recovery_codes WHERE user_id = :id AND used_at IS NULL',
      { type: QueryTypes.SELECT, replacements: { id: user.id } },
    )) as [{ unused: number }];
    expect(unused).toBe(9);
  });

  it('disables 2FA only with the password and a second factor', async () => {
    const user = await registerAndLogin(ctx);
    const { recoveryCodes } = await enableMfa(user);
    const api = client(ctx);

    const noFactor = await api.post(
      '/v1/mfa/totp/disable',
      { password: user.password, recoveryCode: 'AAAAA-BBBBB' },
      user.accessToken,
    );
    expect(noFactor.status).toBe(403);

    const disabled = await api.post(
      '/v1/mfa/totp/disable',
      { password: user.password, recoveryCode: recoveryCodes[1] },
      user.accessToken,
    );
    expect(disabled.status).toBe(204);
    expect((await api.get('/v1/me', user.accessToken)).body.mfaEnabled).toBe(false);

    const login = await api.post('/v1/auth/login', { email: user.email, password: user.password });
    expect(login.body.mfaRequired).toBe(false);
  });
});
