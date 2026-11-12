import { createHmac, generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { KeyStore, keyFromPem, type JwtKey } from '../../src/infra/crypto/jwt-keys';
import { TokenService } from '../../src/modules/auth/tokens';
import { AppError } from '../../src/shared/errors';

function ecKey(kid: string): JwtKey {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return keyFromPem(kid, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
}

function rsaKey(kid: string): JwtKey {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return keyFromPem(kid, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
}

const k1 = rsaKey('k1');
const k2 = rsaKey('k2');
const e1 = ecKey('e1');
const settings = {
  issuer: 'test-issuer',
  audience: 'test-aud',
  accessTtlSeconds: 900,
  mfaTtlSeconds: 300,
};
const claims = { userId: 'user-1', sessionId: 'session-1', roles: ['user'] };

const service = (active: string, keys: JwtKey[] = [k1, k2]) =>
  new TokenService(new KeyStore(keys, active), settings);

function authError(fn: () => unknown): AppError {
  try {
    fn();
  } catch (err) {
    if (err instanceof AppError) return err;
    throw err;
  }
  throw new Error('expected an authentication error');
}

describe('TokenService', () => {
  it('signs RS256 access tokens with the active kid and verifies them', () => {
    const tokens = service('k1');
    const token = tokens.signAccess(claims);
    const decoded = jwt.decode(token, { complete: true });

    expect(decoded?.header).toMatchObject({ alg: 'RS256', kid: 'k1', typ: 'at+jwt' });
    expect(decoded?.payload).toMatchObject({
      sub: 'user-1',
      sid: 'session-1',
      iss: 'test-issuer',
      aud: 'test-aud',
      token_use: 'access',
    });
    expect(tokens.verifyAccess(token)).toEqual(claims);
  });

  it('keeps accepting tokens signed by a previous key after rotation', () => {
    const before = service('k1').signAccess(claims);
    const afterRotation = service('k2');
    expect(jwt.decode(afterRotation.signAccess(claims), { complete: true })?.header.kid).toBe('k2');
    expect(afterRotation.verifyAccess(before)).toEqual(claims);
  });

  it('rejects tokens whose kid is no longer loaded', () => {
    const token = service('k1').signAccess(claims);
    expect(authError(() => service('k2', [k2]).verifyAccess(token))).toMatchObject({
      status: 401,
      code: 'invalid_token',
    });
  });

  it('rejects a token whose signature does not match the kid', () => {
    const signedWithK2 = jwt.sign({ sid: 's', roles: [], token_use: 'access' }, k2.privateKey, {
      algorithm: 'RS256',
      header: { alg: 'RS256', typ: 'at+jwt', kid: 'k1' }, // lies about the key
      issuer: settings.issuer,
      audience: settings.audience,
      subject: 'user-1',
    });
    expect(authError(() => service('k1').verifyAccess(signedWithK2))).toMatchObject({
      status: 401,
      code: 'invalid_token',
    });
  });

  it('rejects alg confusion (HS256 signed with the public key)', () => {
    const publicPem = k1.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const forged = [
      Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' })).toString('base64url'),
      Buffer.from(
        JSON.stringify({ sub: 'admin', sid: 's', roles: ['admin'], token_use: 'access' }),
      ).toString('base64url'),
    ].join('.');
    const signature = createHmac('sha256', publicPem).update(forged).digest('base64url');
    expect(authError(() => service('k1').verifyAccess(`${forged}.${signature}`))).toMatchObject({
      status: 401,
      code: 'invalid_token',
    });
  });

  it('rejects tampered payloads and expired tokens', () => {
    const tokens = service('k1');
    const [h, , s] = tokens.signAccess(claims).split('.');
    const evil = Buffer.from(JSON.stringify({ ...claims, roles: ['admin'] })).toString('base64url');
    expect(authError(() => tokens.verifyAccess(`${h}.${evil}.${s}`))).toMatchObject({
      status: 401,
      code: 'invalid_token',
    });

    const expired = jwt.sign(
      { sid: 's', roles: [], token_use: 'access', exp: Math.floor(Date.now() / 1000) - 10 },
      k1.privateKey,
      {
        algorithm: 'RS256',
        header: { alg: 'RS256', typ: 'at+jwt', kid: 'k1' },
        issuer: settings.issuer,
        audience: settings.audience,
        subject: 'u',
      },
    );
    expect(authError(() => tokens.verifyAccess(expired))).toMatchObject({
      status: 401,
      code: 'token_expired',
    });
  });

  it('keeps MFA challenge tokens and access tokens apart', () => {
    const tokens = service('k1');
    const challenge = tokens.signMfaChallenge('user-1');
    expect(tokens.verifyMfaChallenge(challenge.token)).toEqual({
      userId: 'user-1',
      jti: challenge.jti,
    });
    expect(authError(() => tokens.verifyAccess(challenge.token))).toMatchObject({
      status: 401,
      code: 'invalid_token',
    });
    expect(authError(() => tokens.verifyMfaChallenge(tokens.signAccess(claims)))).toMatchObject({
      status: 401,
      code: 'invalid_mfa_token',
    });
  });

  it('publishes every loaded public key in the JWKS', () => {
    const jwks = new KeyStore([k1, k2], 'k1').jwks();
    expect(jwks.keys.map((k) => k.kid)).toEqual(['k1', 'k2']);
    for (const key of jwks.keys) {
      expect(key).toMatchObject({ kty: 'RSA', use: 'sig', alg: 'RS256', e: 'AQAB' });
      expect(key).not.toHaveProperty('d'); // no private material
    }
  });
});

describe('TokenService: ES256 and algorithm pinning', () => {
  const claimsBody = { sid: 's', roles: [], token_use: 'access' };
  const base = { issuer: settings.issuer, audience: settings.audience, subject: 'user-1' };

  it('signs and verifies ES256 tokens with an EC P-256 key', () => {
    const tokens = service('e1', [k1, e1]);
    const token = tokens.signAccess(claims);
    expect(jwt.decode(token, { complete: true })?.header).toEqual({
      alg: 'ES256',
      typ: 'at+jwt',
      kid: 'e1',
    });
    expect(tokens.verifyAccess(token)).toEqual(claims);
  });

  it('rejects an ES256 token presented with an RSA kid, and the reverse', () => {
    const asRsaKid = jwt.sign(claimsBody, e1.privateKey, {
      ...base,
      algorithm: 'ES256',
      header: { alg: 'ES256', typ: 'at+jwt', kid: 'k1' },
    });
    const asEcKid = jwt.sign(claimsBody, k1.privateKey, {
      ...base,
      algorithm: 'RS256',
      header: { alg: 'RS256', typ: 'at+jwt', kid: 'e1' },
    });
    const tokens = service('k1', [k1, e1]);
    for (const t of [asRsaKid, asEcKid]) {
      expect(authError(() => tokens.verifyAccess(t))).toMatchObject({ code: 'invalid_token' });
    }
  });

  it('rejects HS256 signed with the EC public PEM and alg=none', () => {
    const tokens = service('e1', [k1, e1]);
    const pem = e1.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const body = enc({ ...claimsBody, sub: 'admin', iss: settings.issuer, aud: settings.audience });
    const hsHead = `${enc({ alg: 'HS256', typ: 'at+jwt', kid: 'e1' })}.${body}`;
    const hs = `${hsHead}.${createHmac('sha256', pem).update(hsHead).digest('base64url')}`;
    const none = `${enc({ alg: 'none', typ: 'at+jwt', kid: 'e1' })}.${body}.`;
    for (const t of [hs, none]) {
      expect(authError(() => tokens.verifyAccess(t))).toMatchObject({ code: 'invalid_token' });
    }
  });

  it('puts kid in the header exactly once', () => {
    const token = service('k1').signAccess(claims);
    const header = Buffer.from(token.split('.')[0] as string, 'base64url').toString();
    expect(header.match(/"kid"/g)).toHaveLength(1);
  });
});

describe('TokenService: typ and clock tolerance', () => {
  const body = { sid: 's', roles: [], token_use: 'access' };
  const base = { issuer: settings.issuer, audience: settings.audience, subject: 'user-1' };
  const withTyp = (typ: string | undefined, payload: object = body) =>
    jwt.sign(payload, k1.privateKey, {
      ...base,
      algorithm: 'RS256',
      header: { alg: 'RS256', kid: 'k1', ...(typ ? { typ } : {}) } as jwt.JwtHeader,
    });

  it('sets typ per token kind and rejects the wrong one', () => {
    const tokens = service('k1');
    const challenge = tokens.signMfaChallenge('user-1');
    expect(jwt.decode(challenge.token, { complete: true })?.header.typ).toBe('mfa-challenge+jwt');
    expect(authError(() => tokens.verifyAccess(withTyp('mfa-challenge+jwt')))).toMatchObject({
      code: 'invalid_token',
    });
  });

  it('compares typ case-insensitively and accepts the application/ prefix', () => {
    const tokens = service('k1');
    expect(tokens.verifyAccess(withTyp('AT+JWT'))).toMatchObject({ userId: 'user-1' });
    expect(tokens.verifyAccess(withTyp('application/at+jwt'))).toMatchObject({ userId: 'user-1' });
  });

  it('rejects missing or legacy typ by default', () => {
    const tokens = service('k1');
    for (const t of [withTyp(undefined), withTyp('JWT')]) {
      expect(authError(() => tokens.verifyAccess(t))).toMatchObject({ code: 'invalid_token' });
    }
  });

  it('requireTyp=false accepts legacy access tokens but never legacy MFA tokens', () => {
    const tokens = new TokenService(new KeyStore([k1], 'k1'), settings, { requireTyp: false });
    expect(tokens.verifyAccess(withTyp('JWT'))).toMatchObject({ userId: 'user-1' });
    expect(tokens.verifyAccess(withTyp(undefined))).toMatchObject({ userId: 'user-1' });
    expect(authError(() => tokens.verifyAccess(withTyp('foo')))).toMatchObject({
      code: 'invalid_token',
    });
    const mfa = jwt.sign({ token_use: 'mfa', jti: 'j' }, k1.privateKey, {
      issuer: settings.issuer,
      audience: `${settings.audience}:mfa`,
      subject: 'user-1',
      algorithm: 'RS256',
      header: { alg: 'RS256', kid: 'k1', typ: 'JWT' },
    });
    expect(authError(() => tokens.verifyMfaChallenge(mfa))).toMatchObject({
      code: 'invalid_mfa_token',
    });
  });

  it('tolerates a few seconds of clock skew but not more', () => {
    const tokens = service('k1');
    const now = Math.floor(Date.now() / 1000);
    expect(tokens.verifyAccess(withTyp('at+jwt', { ...body, exp: now - 2 }))).toBeDefined();
    const stale = withTyp('at+jwt', { ...body, exp: now - 30 });
    expect(authError(() => tokens.verifyAccess(stale))).toMatchObject({ code: 'token_expired' });
  });
});
