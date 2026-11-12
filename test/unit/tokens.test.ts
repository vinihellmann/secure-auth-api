import { createHmac, generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { KeyStore, keyFromPem, type JwtKey } from '../../src/infra/crypto/jwt-keys';
import { TokenService } from '../../src/modules/auth/tokens';
import { AppError } from '../../src/shared/errors';

function rsaKey(kid: string): JwtKey {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return keyFromPem(kid, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
}

const k1 = rsaKey('k1');
const k2 = rsaKey('k2');
const settings = { issuer: 'test-issuer', audience: 'test-aud', accessTtlSeconds: 900, mfaTtlSeconds: 300 };
const claims = { userId: 'user-1', sessionId: 'session-1', roles: ['user'] };

const service = (active: string, keys: JwtKey[] = [k1, k2]) =>
  new TokenService(new KeyStore(keys, active), settings);

function expectAuthError(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(AppError);
    expect((err as AppError).status).toBe(401);
    expect((err as AppError).code).toBe(code);
    return;
  }
  throw new Error('expected an authentication error');
}

describe('TokenService', () => {
  it('signs RS256 access tokens with the active kid and verifies them', () => {
    const tokens = service('k1');
    const token = tokens.signAccess(claims);
    const decoded = jwt.decode(token, { complete: true });

    expect(decoded?.header).toMatchObject({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
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
    expectAuthError(() => service('k2', [k2]).verifyAccess(token), 'invalid_token');
  });

  it('rejects a token whose signature does not match the kid', () => {
    const signedWithK2 = jwt.sign({ sid: 's', roles: [], token_use: 'access' }, k2.privateKey, {
      algorithm: 'RS256',
      keyid: 'k1', // lies about the key
      issuer: settings.issuer,
      audience: settings.audience,
      subject: 'user-1',
    });
    expectAuthError(() => service('k1').verifyAccess(signedWithK2), 'invalid_token');
  });

  it('rejects alg confusion (HS256 signed with the public key)', () => {
    const publicPem = k1.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const forged = [
      Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'k1' })).toString('base64url'),
      Buffer.from(
        JSON.stringify({ sub: 'admin', sid: 's', roles: ['admin'], token_use: 'access' }),
      ).toString('base64url'),
    ].join('.');
    const signature = createHmac('sha256', publicPem).update(forged).digest('base64url');
    expectAuthError(() => service('k1').verifyAccess(`${forged}.${signature}`), 'invalid_token');
  });

  it('rejects tampered payloads and expired tokens', () => {
    const tokens = service('k1');
    const [h, , s] = tokens.signAccess(claims).split('.');
    const evil = Buffer.from(JSON.stringify({ ...claims, roles: ['admin'] })).toString('base64url');
    expectAuthError(() => tokens.verifyAccess(`${h}.${evil}.${s}`), 'invalid_token');

    const expired = jwt.sign(
      { sid: 's', roles: [], token_use: 'access', exp: Math.floor(Date.now() / 1000) - 10 },
      k1.privateKey,
      { algorithm: 'RS256', keyid: 'k1', issuer: settings.issuer, audience: settings.audience, subject: 'u' },
    );
    expectAuthError(() => tokens.verifyAccess(expired), 'token_expired');
  });

  it('keeps MFA challenge tokens and access tokens apart', () => {
    const tokens = service('k1');
    const challenge = tokens.signMfaChallenge('user-1');
    expect(tokens.verifyMfaChallenge(challenge.token)).toEqual({ userId: 'user-1', jti: challenge.jti });
    expectAuthError(() => tokens.verifyAccess(challenge.token), 'invalid_token');
    expectAuthError(() => tokens.verifyMfaChallenge(tokens.signAccess(claims)), 'invalid_mfa_token');
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
