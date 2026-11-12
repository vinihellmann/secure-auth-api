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

export interface TokenServiceOptions {
  /**
   * Require the JOSE `typ` header on access tokens (default true). Set to false only during
   * the deploy that introduces `typ`: access tokens issued before it carry `typ: JWT` (or none)
   * and are accepted while the flag is off. Access TTLs are short, so turn it back on after
   * one access TTL. MFA challenge tokens always require their `typ` (they live minutes).
   */
  requireTyp?: boolean;
}

type TokenUse = 'access' | 'mfa';

/** JOSE `typ` per token kind (RFC 9068 for access tokens), so one kind can never pass as another. */
const TOKEN_TYP: Record<TokenUse, string> = {
  access: 'at+jwt',
  mfa: 'mfa-challenge+jwt',
};

/**
 * Leeway for clock drift between replicas / gateways. Kept small on purpose: it extends the
 * effective lifetime of every token (and shifts `nbf`/`iat` checks) by this much.
 */
const CLOCK_TOLERANCE_SECONDS = 5;

/** Media-type compare per RFC 8725 §3.11 / RFC 7515 §4.1.9: case-insensitive, `application/` optional. */
function normalizeTyp(typ: string): string {
  const lower = typ.toLowerCase();
  return lower.includes('/') ? lower : `application/${lower}`;
}

/**
 * Signed JWTs (RS256 or ES256 depending on the key) with a `kid` header. Verification looks
 * the key up by `kid`, so tokens signed with a key that was rotated out of "active" keep
 * working until they expire, as long as the key is still loaded (and therefore published in
 * the JWKS). The algorithm is a property of the key, never of the token: the header's `alg`
 * must equal the key's `alg`, which blocks RS256<->ES256 swaps, HS256 and `none`.
 *
 * Access and MFA-challenge tokens share the key material but differ in `typ`, `token_use`
 * and audience, so one can never be replayed as the other.
 */
export class TokenService {
  private readonly requireTyp: boolean;

  constructor(
    private readonly keys: KeyStore,
    private readonly settings: TokenSettings,
    options: TokenServiceOptions = {},
  ) {
    this.requireTyp = options.requireTyp ?? true;
  }

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

  private typAccepted(use: TokenUse, typ: unknown): boolean {
    if (typeof typ === 'string' && normalizeTyp(typ) === normalizeTyp(TOKEN_TYP[use])) return true;
    // Transition only: pre-typ access tokens have no typ or the jsonwebtoken default "JWT".
    if (use === 'access' && !this.requireTyp) {
      return typ === undefined || (typeof typ === 'string' && typ.toUpperCase() === 'JWT');
    }
    return false;
  }

  private sign(
    use: TokenUse,
    subject: string,
    ttlSeconds: number,
    extra: Record<string, unknown>,
    jwtid: string = randomUUID(),
  ): string {
    const key = this.keys.active;
    // kid goes through `header` only (not the `keyid` option) so it appears exactly once.
    return jwt.sign({ ...extra, token_use: use }, key.privateKey, {
      algorithm: key.alg,
      header: { alg: key.alg, typ: TOKEN_TYP[use], kid: key.kid },
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
    if (!decoded || !key || decoded.header.alg !== key.alg) {
      throw unauthorized('Invalid token', code);
    }
    if (!this.typAccepted(use, decoded.header.typ)) {
      throw unauthorized('Invalid token', code);
    }

    let payload: string | JwtPayload;
    try {
      payload = jwt.verify(token, key.publicKey, {
        algorithms: [key.alg], // never trust the header's alg (alg=none / HS256 confusion)
        issuer: this.settings.issuer,
        audience: this.audienceFor(use),
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
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
