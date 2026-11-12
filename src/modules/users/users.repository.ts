import { randomUUID } from 'node:crypto';
import { UniqueConstraintError } from 'sequelize';
import { UserModel } from '../../infra/db/models';

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  roles: string[];
  lockedAt: Date | null;
  createdAt: Date;
}

export class EmailTakenError extends Error {
  constructor() {
    super('Email already registered');
    this.name = 'EmailTakenError';
  }
}

export interface UsersRepository {
  findById(id: string): Promise<UserRecord | null>;
  findByEmail(email: string): Promise<UserRecord | null>;
  create(input: { email: string; passwordHash: string; roles: string[] }): Promise<UserRecord>;
  updatePasswordHash(id: string, passwordHash: string): Promise<void>;
  setRoles(id: string, roles: string[]): Promise<void>;
  /** Returns false when the user does not exist. */
  setLockedAt(id: string, lockedAt: Date | null): Promise<boolean>;
}

const toRecord = (m: UserModel): UserRecord => ({
  id: m.id,
  email: m.email,
  passwordHash: m.passwordHash,
  roles: m.roles,
  lockedAt: m.lockedAt,
  createdAt: m.createdAt,
});

export class SequelizeUsersRepository implements UsersRepository {
  async findById(id: string): Promise<UserRecord | null> {
    const m = await UserModel.findByPk(id);
    return m ? toRecord(m) : null;
  }

  async findByEmail(email: string): Promise<UserRecord | null> {
    const m = await UserModel.findOne({ where: { email } });
    return m ? toRecord(m) : null;
  }

  async create(input: {
    email: string;
    passwordHash: string;
    roles: string[];
  }): Promise<UserRecord> {
    try {
      const m = await UserModel.create({ id: randomUUID(), ...input });
      return toRecord(m);
    } catch (err) {
      if (err instanceof UniqueConstraintError) throw new EmailTakenError();
      throw err;
    }
  }

  async updatePasswordHash(id: string, passwordHash: string): Promise<void> {
    await UserModel.update({ passwordHash }, { where: { id } });
  }

  async setRoles(id: string, roles: string[]): Promise<void> {
    await UserModel.update({ roles }, { where: { id } });
  }

  async setLockedAt(id: string, lockedAt: Date | null): Promise<boolean> {
    const [count] = await UserModel.update({ lockedAt }, { where: { id } });
    return count > 0;
  }
}
