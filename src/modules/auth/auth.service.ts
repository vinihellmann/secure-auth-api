import type { RequestContext } from '../../shared/context';
import { forbidden, tooManyRequests, unauthorized } from '../../shared/errors';
import type { AuditRecorder } from '../audit/audit.service';
import type { MfaService } from '../mfa/mfa.service';
import type { SessionService } from '../sessions/sessions.service';
import type { PasswordHasher } from '../users/password-hasher';
import type { UserRecord, UsersRepository } from '../users/users.repository';
import type { LoginLockout } from './lockout';
import type { TokenService } from './tokens';

/** One-time use of MFA challenge tokens (jti), Redis in production. */
export interface MfaChallengeStore {
  isConsumed(jti: string): Promise<boolean>;
  /** Returns true the first time a jti is consumed, false afterwards. */
  consume(jti: string, ttlSeconds: number): Promise<boolean>;
}

export interface AuthServiceDeps {
  users: UsersRepository;
  hasher: PasswordHasher;
  tokens: TokenService;
  sessions: SessionService;
  mfa: MfaService;
  lockout: LoginLockout;
  challenges: MfaChallengeStore;
  audit: AuditRecorder;
  mfaTtlSeconds: number;
}

export interface TokenPair {
  tokenType: 'Bearer';
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export type LoginResult =
  | ({ mfaRequired: false } & TokenPair)
  | { mfaRequired: true; mfaToken: string; mfaTokenExpiresIn: number };

const INVALID_CREDENTIALS = (): Error =>
  unauthorized('Invalid email or password', 'invalid_credentials');

export class AuthService {
  constructor(private readonly d: AuthServiceDeps) {}

  /**
   * Password step. Every failure path costs one bcrypt comparison (a dummy hash is used for
   * unknown emails) and returns the same error, so neither the response nor its timing tells
   * whether the account exists.
   */
  async login(email: string, password: string, ctx: RequestContext): Promise<LoginResult> {
    const lockKey = `login:${email}`;
    const lockedForMs = await this.d.lockout.remainingLockMs(lockKey);
    if (lockedForMs > 0) {
      throw tooManyRequests(
        lockedForMs / 1000,
        'too_many_failed_attempts',
        'Too many failed attempts, try again later',
      );
    }

    const user = await this.d.users.findByEmail(email);
    const passwordOk = await this.d.hasher.verify(password, user?.passwordHash);

    if (!user || !passwordOk) {
      const lockMs = await this.d.lockout.registerFailure(lockKey);
      await this.d.audit.record({
        eventType: 'login_failed',
        actorUserId: user?.id ?? null,
        metadata: { reason: 'invalid_credentials', lockApplied: lockMs > 0 },
        ...ctx,
      });
      throw INVALID_CREDENTIALS();
    }

    if (user.lockedAt) {
      await this.d.audit.record({
        eventType: 'login_blocked_account_locked',
        actorUserId: user.id,
        ...ctx,
      });
      throw forbidden('Account is locked; contact an administrator', 'account_locked');
    }

    await this.d.lockout.reset(lockKey);

    if (await this.d.mfa.isEnabled(user.id)) {
      const challenge = this.d.tokens.signMfaChallenge(user.id);
      await this.d.audit.record({
        eventType: 'login_mfa_challenge_issued',
        actorUserId: user.id,
        ...ctx,
      });
      return {
        mfaRequired: true,
        mfaToken: challenge.token,
        mfaTokenExpiresIn: challenge.expiresIn,
      };
    }

    return { mfaRequired: false, ...(await this.startSession(user, ctx, 'password')) };
  }

  /** Second step: exchanges the MFA challenge plus a TOTP or recovery code for tokens. */
  async loginWithMfa(
    input: { mfaToken: string; code?: string; recoveryCode?: string },
    ctx: RequestContext,
  ): Promise<TokenPair> {
    const { userId, jti } = this.d.tokens.verifyMfaChallenge(input.mfaToken);
    // Checked before the factor so a replayed challenge cannot burn a recovery code.
    if (await this.d.challenges.isConsumed(jti)) {
      throw unauthorized('MFA token already used', 'invalid_mfa_token');
    }
    const lockKey = `mfa:${userId}`;
    const lockedForMs = await this.d.lockout.remainingLockMs(lockKey);
    if (lockedForMs > 0) {
      throw tooManyRequests(
        lockedForMs / 1000,
        'too_many_failed_attempts',
        'Too many failed attempts, try again later',
      );
    }

    const result = await this.d.mfa.verifySecondFactor(userId, input);
    if (!result.ok) {
      await this.d.lockout.registerFailure(lockKey);
      await this.d.audit.record({
        eventType: 'login_mfa_failed',
        actorUserId: userId,
        metadata: { method: result.method },
        ...ctx,
      });
      throw unauthorized('Invalid or already used code', 'invalid_mfa_code');
    }

    // The challenge is single use: a stolen mfaToken cannot be replayed with a later code.
    if (!(await this.d.challenges.consume(jti, this.d.mfaTtlSeconds))) {
      throw unauthorized('MFA token already used', 'invalid_mfa_token');
    }

    const user = await this.d.users.findById(userId);
    if (!user) throw INVALID_CREDENTIALS();
    if (user.lockedAt)
      throw forbidden('Account is locked; contact an administrator', 'account_locked');

    await this.d.lockout.reset(lockKey);
    return this.startSession(user, ctx, result.method);
  }

  async refresh(refreshToken: string, ctx: RequestContext): Promise<TokenPair> {
    const rotated = await this.d.sessions.rotate(refreshToken, ctx);
    return {
      tokenType: 'Bearer',
      accessToken: this.d.tokens.signAccess({
        userId: rotated.userId,
        sessionId: rotated.sessionId,
        roles: rotated.roles,
      }),
      expiresIn: this.d.tokens.accessTtlSeconds,
      refreshToken: rotated.refreshToken,
      refreshTokenExpiresAt: rotated.refreshTokenExpiresAt.toISOString(),
    };
  }

  async logout(userId: string, sessionId: string, ctx: RequestContext): Promise<void> {
    await this.d.sessions.revoke(userId, sessionId);
    await this.d.audit.record({
      eventType: 'logout',
      actorUserId: userId,
      metadata: { sessionId },
      ...ctx,
    });
  }

  private async startSession(
    user: UserRecord,
    ctx: RequestContext,
    method: 'password' | 'totp' | 'recovery_code',
  ): Promise<TokenPair> {
    const session = await this.d.sessions.create(user.id, ctx);
    await this.d.audit.record({
      eventType: 'login_succeeded',
      actorUserId: user.id,
      metadata: { sessionId: session.sessionId, method },
      ...ctx,
    });
    return {
      tokenType: 'Bearer',
      accessToken: this.d.tokens.signAccess({
        userId: user.id,
        sessionId: session.sessionId,
        roles: user.roles,
      }),
      expiresIn: this.d.tokens.accessTtlSeconds,
      refreshToken: session.refreshToken,
      refreshTokenExpiresAt: session.refreshTokenExpiresAt.toISOString(),
    };
  }
}
