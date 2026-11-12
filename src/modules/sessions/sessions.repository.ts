import { randomUUID } from 'node:crypto';
import {
  Op,
  type InferAttributes,
  type Sequelize,
  type Transaction,
  type WhereOptions,
} from 'sequelize';
import { RefreshTokenModel, SessionModel, UserModel } from '../../infra/db/models';

export interface SessionRecord {
  id: string;
  userId: string;
  userAgent: string | null;
  ip: string | null;
  createdAt: Date;
  lastUsedAt: Date;
}

export interface NewSession {
  userId: string;
  userAgent: string | null;
  ip: string | null;
  tokenHash: string;
  expiresAt: Date;
}

export type RotationOutcome =
  | { kind: 'rotated'; userId: string; sessionId: string; roles: string[] }
  | { kind: 'invalid' }
  | { kind: 'expired' }
  | { kind: 'reuse'; userId: string; sessionId: string; familyId: string };

export interface SessionsRepository {
  create(input: NewSession): Promise<{ sessionId: string }>;
  /**
   * Swaps a refresh token for a new one inside one transaction with a row lock, so two
   * concurrent refreshes with the same token are serialized and the second is seen as reuse.
   */
  rotate(oldHash: string, newHash: string, newExpiresAt: Date, now: Date): Promise<RotationOutcome>;
  listActive(userId: string): Promise<SessionRecord[]>;
  /** Revokes sessions (and their tokens); returns the ids that were actually active. */
  revoke(userId: string, filter: { sessionId?: string; exceptSessionId?: string }): Promise<string[]>;
}

const toSession = (m: SessionModel): SessionRecord => ({
  id: m.id,
  userId: m.userId,
  userAgent: m.userAgent,
  ip: m.ip,
  createdAt: m.createdAt,
  lastUsedAt: m.lastUsedAt,
});

export class SequelizeSessionsRepository implements SessionsRepository {
  constructor(private readonly sequelize: Sequelize) {}

  async create(input: NewSession): Promise<{ sessionId: string }> {
    const sessionId = randomUUID();
    await this.sequelize.transaction(async (transaction) => {
      await SessionModel.create(
        { id: sessionId, userId: input.userId, userAgent: input.userAgent, ip: input.ip },
        { transaction },
      );
      await RefreshTokenModel.create(
        {
          id: randomUUID(),
          sessionId,
          familyId: sessionId, // one rotation family per session
          userId: input.userId,
          tokenHash: input.tokenHash,
          expiresAt: input.expiresAt,
        },
        { transaction },
      );
    });
    return { sessionId };
  }

  async rotate(oldHash: string, newHash: string, newExpiresAt: Date, now: Date): Promise<RotationOutcome> {
    return this.sequelize.transaction(async (transaction) => {
      const token = await RefreshTokenModel.findOne({
        where: { tokenHash: oldHash },
        transaction,
        lock: true, // SELECT ... FOR UPDATE
      });
      if (!token) return { kind: 'invalid' } as const;

      if (token.revokedAt !== null) {
        // Revoked by logout, admin action or an earlier reuse detection: just refuse.
        return { kind: 'invalid' } as const;
      }
      if (token.replacedBy !== null) {
        // An already rotated token was presented again: it leaked. Kill the whole family.
        await this.revokeFamily(token.familyId, token.sessionId, now, transaction);
        return {
          kind: 'reuse',
          userId: token.userId,
          sessionId: token.sessionId,
          familyId: token.familyId,
        } as const;
      }
      if (token.expiresAt.getTime() <= now.getTime()) return { kind: 'expired' } as const;

      const session = await SessionModel.findByPk(token.sessionId, { transaction, lock: true });
      const user = await UserModel.findByPk(token.userId, { transaction });
      if (!session || session.revokedAt !== null || !user || user.lockedAt !== null) {
        return { kind: 'invalid' } as const;
      }

      const next = await RefreshTokenModel.create(
        {
          id: randomUUID(),
          sessionId: token.sessionId,
          familyId: token.familyId,
          userId: token.userId,
          tokenHash: newHash,
          expiresAt: newExpiresAt,
        },
        { transaction },
      );
      await token.update({ replacedBy: next.id }, { transaction });
      await session.update({ lastUsedAt: now }, { transaction });

      return {
        kind: 'rotated',
        userId: token.userId,
        sessionId: token.sessionId,
        roles: user.roles,
      } as const;
    });
  }

  async listActive(userId: string): Promise<SessionRecord[]> {
    const rows = await SessionModel.findAll({
      where: { userId, revokedAt: null },
      order: [['lastUsedAt', 'DESC']],
    });
    return rows.map(toSession);
  }

  async revoke(
    userId: string,
    filter: { sessionId?: string; exceptSessionId?: string },
  ): Promise<string[]> {
    const now = new Date();
    return this.sequelize.transaction(async (transaction) => {
      const where: WhereOptions<InferAttributes<SessionModel>> = {
        userId,
        revokedAt: null,
        ...(filter.sessionId ? { id: filter.sessionId } : {}),
        ...(filter.exceptSessionId ? { id: { [Op.ne]: filter.exceptSessionId } } : {}),
      };

      const sessions = await SessionModel.findAll({ where, transaction, lock: true });
      const ids = sessions.map((s) => s.id);
      if (ids.length === 0) return [];

      await SessionModel.update({ revokedAt: now }, { where: { id: ids }, transaction });
      await RefreshTokenModel.update(
        { revokedAt: now },
        { where: { sessionId: ids, revokedAt: null }, transaction },
      );
      return ids;
    });
  }

  private async revokeFamily(
    familyId: string,
    sessionId: string,
    now: Date,
    transaction: Transaction,
  ): Promise<void> {
    await RefreshTokenModel.update(
      { revokedAt: now },
      { where: { familyId, revokedAt: null }, transaction },
    );
    await SessionModel.update(
      { revokedAt: now },
      { where: { id: sessionId, revokedAt: null }, transaction },
    );
  }
}
