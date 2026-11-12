import { randomUUID } from 'node:crypto';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import type { KeyStore } from '../../infra/crypto/jwt-keys';
import { unauthorized } from '../../shared/errors';

export interface AccessClaims {
  userId: string;
  sessionId: string;
  roles: string[];
}

export interface TokenSettings {
  issuer: string;
  audience: string;
  accessTtlSeconds: number;
  mfaTtlSeconds: number;
}

type TokenUse = 'access' | 'mfa';

/**
 * RS256 tokens with a `kid` header. Verification looks the key up by `kid`, so tokens signed
 * with a key that was rotated out of "active" keep working until they expire, as long as the
 * key is still loaded (and therefore published in the JWKS).
 *
 * Access and MFA-challenge tokens share the key material but differ in `token_use` and
 * audience, so one can never be replayed as the other.
 */
export class TokenService {
  constructor(
    private readonly keys: KeyStore,
    private readonly settings: TokenSettings,
  ) {}

  get accessTtlSeconds(): number {
    return this.settings.accessTtlSeconds;
  }

  signAccess(claims: AccessClaims): string {
    return this.sign('access', claims.userId, this.settings.accessTtlSeconds, {
      sid: claims.sessionId,
      roles: claims.roles,
    });
  }

  verifyAccess(token: string): AccessClaims {
    const payload = this.verify('access', token);
    const sid = payload.sid;
    const roles = payload.roles;
    if (
      typeof sid !== 'string' ||
      !Array.isArray(roles) ||
      !roles.every((r) => typeof r === 'string')
    ) {
      throw unauthorized('Invalid access token', 'invalid_token');
    }
    return { userId: payload.sub as string, sessionId: sid, roles };
  }

  /** Short-lived proof that the password step succeeded; exchanged at /v1/auth/login/mfa. */
  signMfaChallenge(userId: string): { token: string; jti: string; expiresIn: number } {
    const jti = randomUUID();
    const token = this.sign('mfa', userId, this.settings.mfaTtlSeconds, {}, jti);
    return { token, jti, expiresIn: this.settings.mfaTtlSeconds };
  }

  verifyMfaChallenge(token: string): { userId: string; jti: string } {
    const payload = this.verify('mfa', token);
    if (typeof payload.jti !== 'string')
      throw unauthorized('Invalid MFA token', 'invalid_mfa_token');
    return { userId: payload.sub as string, jti: payload.jti };
  }

  private audienceFor(use: TokenUse): string {
    return use === 'access' ? this.settings.audience : `${this.settings.audience}:mfa`;
  }

  private sign(
    use: TokenUse,
    subject: string,
    ttlSeconds: number,
    extra: Record<string, unknown>,
    jwtid: string = randomUUID(),
  ): string {
    const key = this.keys.active;
    return jwt.sign({ ...extra, token_use: use }, key.privateKey, {
      algorithm: 'RS256',
      keyid: key.kid,
      issuer: this.settings.issuer,
      audience: this.audienceFor(use),
      subject,
      expiresIn: ttlSeconds,
      jwtid,
    });
  }

  private verify(use: TokenUse, token: string): JwtPayload {
    const code = use === 'access' ? 'invalid_token' : 'invalid_mfa_token';
    const decoded = jwt.decode(token, { complete: true });
    const kid = decoded?.header.kid;
    const key = typeof kid === 'string' ? this.keys.get(kid) : undefined;
    if (!decoded || decoded.header.alg !== 'RS256' || !key) {
      throw unauthorized('Invalid token', code);
    }

    let payload: string | JwtPayload;
    try {
      payload = jwt.verify(token, key.publicKey, {
        algorithms: ['RS256'], // never trust the header's alg (alg=none / HS256 confusion)
        issuer: this.settings.issuer,
        audience: this.audienceFor(use),
      });
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError)
        throw unauthorized('Token expired', 'token_expired');
      throw unauthorized('Invalid token', code);
    }

    if (
      typeof payload === 'string' ||
      payload.token_use !== use ||
      typeof payload.sub !== 'string'
    ) {
      throw unauthorized('Invalid token', code);
    }
    return payload;
  }
}
