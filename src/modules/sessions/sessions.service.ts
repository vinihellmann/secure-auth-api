import { randomToken, sha256Hex } from '../../infra/crypto/hash';
import type { RequestContext } from '../../shared/context';
import { notFound, unauthorized } from '../../shared/errors';
import type { AuditRecorder } from '../audit/audit.service';
import type { SessionRecord, SessionsRepository } from './sessions.repository';

/**
 * Revoked session ids, checked on every authenticated request so that revocation takes effect
 * immediately instead of when the access token expires. Entries live as long as an access
 * token can, after which the token itself is dead anyway.
 */
export interface RevokedSessionCache {
  markRevoked(sessionIds: string[]): Promise<void>;
  isRevoked(sessionId: string): Promise<boolean>;
}

export interface IssuedRefreshToken {
  sessionId: string;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

export interface RotatedRefreshToken extends IssuedRefreshToken {
  userId: string;
  roles: string[];
}

export interface SessionServiceDeps {
  repo: SessionsRepository;
  revoked: RevokedSessionCache;
  audit: AuditRecorder;
  refreshTtlDays: number;
  now?: () => Date;
}

/**
 * Sessions and opaque refresh tokens. The raw token is returned to the client once; only its
 * SHA-256 is stored, so a database leak does not yield usable tokens (they are 256-bit random,
 * so a fast hash is sufficient).
 */
export class SessionService {
  private readonly now: () => Date;

  constructor(private readonly d: SessionServiceDeps) {
    this.now = d.now ?? (() => new Date());
  }

  private newToken(): { raw: string; hash: string; expiresAt: Date } {
    const raw = randomToken(32);
    const expiresAt = new Date(this.now().getTime() + this.d.refreshTtlDays * 86_400_000);
    return { raw, hash: sha256Hex(raw), expiresAt };
  }

  async create(userId: string, ctx: RequestContext): Promise<IssuedRefreshToken> {
    const token = this.newToken();
    const { sessionId } = await this.d.repo.create({
      userId,
      userAgent: ctx.userAgent,
      ip: ctx.ip,
      tokenHash: token.hash,
      expiresAt: token.expiresAt,
    });
    return { sessionId, refreshToken: token.raw, refreshTokenExpiresAt: token.expiresAt };
  }

  async rotate(rawToken: string, ctx: RequestContext): Promise<RotatedRefreshToken> {
    const next = this.newToken();
    const outcome = await this.d.repo.rotate(sha256Hex(rawToken), next.hash, next.expiresAt, this.now());

    switch (outcome.kind) {
      case 'rotated':
        return {
          userId: outcome.userId,
          roles: outcome.roles,
          sessionId: outcome.sessionId,
          refreshToken: next.raw,
          refreshTokenExpiresAt: next.expiresAt,
        };
      case 'reuse':
        // The revocation is already committed; now cut off live access tokens too.
        await this.d.revoked.markRevoked([outcome.sessionId]);
        await this.d.audit.record({
          eventType: 'refresh_token_reuse_detected',
          actorUserId: outcome.userId,
          metadata: { sessionId: outcome.sessionId, familyId: outcome.familyId },
          ...ctx,
        });
        throw unauthorized('Refresh token reuse detected; session revoked', 'refresh_token_reused');
      case 'expired':
        throw unauthorized('Refresh token expired', 'refresh_token_expired');
      case 'invalid':
        throw unauthorized('Invalid refresh token', 'invalid_refresh_token');
    }
  }

  list(userId: string): Promise<SessionRecord[]> {
    return this.d.repo.listActive(userId);
  }

  async revoke(userId: string, sessionId: string): Promise<void> {
    const ids = await this.d.repo.revoke(userId, { sessionId });
    if (ids.length === 0) throw notFound('Session not found');
    await this.d.revoked.markRevoked(ids);
  }

  async revokeOthers(userId: string, keepSessionId: string): Promise<string[]> {
    const ids = await this.d.repo.revoke(userId, { exceptSessionId: keepSessionId });
    await this.d.revoked.markRevoked(ids);
    return ids;
  }

  async revokeAll(userId: string): Promise<string[]> {
    const ids = await this.d.repo.revoke(userId, {});
    await this.d.revoked.markRevoked(ids);
    return ids;
  }

  isRevoked(sessionId: string): Promise<boolean> {
    return this.d.revoked.isRevoked(sessionId);
  }
}
