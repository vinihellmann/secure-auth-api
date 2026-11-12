import { randomUUID } from 'node:crypto';
import { Op, type Sequelize } from 'sequelize';
import { MfaCredentialModel, RecoveryCodeModel } from '../../infra/db/models';

export interface MfaCredential {
  userId: string;
  secretEnc: string;
  status: 'pending' | 'enabled';
}

export interface MfaRepository {
  find(userId: string): Promise<MfaCredential | null>;
  /** Creates or replaces a pending credential. */
  savePending(userId: string, secretEnc: string): Promise<void>;
  /** Enables the credential and atomically replaces the recovery codes. */
  enable(userId: string, recoveryCodeHashes: string[]): Promise<void>;
  remove(userId: string): Promise<void>;
  /** Marks the code matching any candidate hash used; returns false when it does not exist or was already used. */
  consumeRecoveryCode(userId: string, codeHashes: string[]): Promise<boolean>;
  countUnusedRecoveryCodes(userId: string): Promise<number>;
  /** Paginates all credentials (for the re-encryption script). */
  listAfter(afterUserId: string | null, limit: number): Promise<MfaCredential[]>;
  updateSecret(userId: string, secretEnc: string): Promise<void>;
}

const toCredential = (m: MfaCredentialModel): MfaCredential => ({
  userId: m.userId,
  secretEnc: m.secretEnc,
  status: m.status,
});

export class SequelizeMfaRepository implements MfaRepository {
  constructor(private readonly sequelize: Sequelize) {}

  async find(userId: string): Promise<MfaCredential | null> {
    const m = await MfaCredentialModel.findByPk(userId);
    return m ? toCredential(m) : null;
  }

  async savePending(userId: string, secretEnc: string): Promise<void> {
    await MfaCredentialModel.upsert({
      userId,
      secretEnc,
      status: 'pending',
      enabledAt: null,
      createdAt: new Date(),
    });
  }

  async enable(userId: string, recoveryCodeHashes: string[]): Promise<void> {
    await this.sequelize.transaction(async (transaction) => {
      await MfaCredentialModel.update(
        { status: 'enabled', enabledAt: new Date() },
        { where: { userId, status: 'pending' }, transaction },
      );
      await RecoveryCodeModel.destroy({ where: { userId }, transaction });
      await RecoveryCodeModel.bulkCreate(
        recoveryCodeHashes.map((codeHash) => ({ id: randomUUID(), userId, codeHash })),
        { transaction },
      );
    });
  }

  async remove(userId: string): Promise<void> {
    await this.sequelize.transaction(async (transaction) => {
      await RecoveryCodeModel.destroy({ where: { userId }, transaction });
      await MfaCredentialModel.destroy({ where: { userId }, transaction });
    });
  }

  async consumeRecoveryCode(userId: string, codeHashes: string[]): Promise<boolean> {
    if (codeHashes.length === 0) return false;
    // Single conditional UPDATE: two concurrent attempts cannot both succeed. The candidates are
    // encodings of ONE code, unique per user, so at most one row can match.
    const [count] = await RecoveryCodeModel.update(
      { usedAt: new Date() },
      { where: { userId, codeHash: { [Op.in]: codeHashes }, usedAt: null } },
    );
    return count === 1;
  }

  countUnusedRecoveryCodes(userId: string): Promise<number> {
    return RecoveryCodeModel.count({ where: { userId, usedAt: null } });
  }

  async listAfter(afterUserId: string | null, limit: number): Promise<MfaCredential[]> {
    const rows = await MfaCredentialModel.findAll({
      where: afterUserId ? { userId: { [Op.gt]: afterUserId } } : {},
      order: [['userId', 'ASC']],
      limit,
    });
    return rows.map(toCredential);
  }

  async updateSecret(userId: string, secretEnc: string): Promise<void> {
    await MfaCredentialModel.update({ secretEnc }, { where: { userId } });
  }
}
