import {
  DataTypes,
  Model,
  type CreationOptional,
  type InferAttributes,
  type InferCreationAttributes,
  type Sequelize,
} from 'sequelize';

export class UserModel extends Model<
  InferAttributes<UserModel>,
  InferCreationAttributes<UserModel>
> {
  declare id: string;
  declare email: string;
  declare passwordHash: string;
  declare roles: CreationOptional<string[]>;
  declare lockedAt: CreationOptional<Date | null>;
  declare createdAt: CreationOptional<Date>;
  declare updatedAt: CreationOptional<Date>;
}

export class SessionModel extends Model<
  InferAttributes<SessionModel>,
  InferCreationAttributes<SessionModel>
> {
  declare id: string;
  declare userId: string;
  declare userAgent: string | null;
  declare ip: string | null;
  declare createdAt: CreationOptional<Date>;
  declare lastUsedAt: CreationOptional<Date>;
  declare revokedAt: CreationOptional<Date | null>;
}

export class RefreshTokenModel extends Model<
  InferAttributes<RefreshTokenModel>,
  InferCreationAttributes<RefreshTokenModel>
> {
  declare id: string;
  declare sessionId: string;
  declare familyId: string;
  declare userId: string;
  declare tokenHash: string;
  declare replacedBy: CreationOptional<string | null>;
  declare revokedAt: CreationOptional<Date | null>;
  declare expiresAt: Date;
  declare createdAt: CreationOptional<Date>;
}

export class MfaCredentialModel extends Model<
  InferAttributes<MfaCredentialModel>,
  InferCreationAttributes<MfaCredentialModel>
> {
  declare userId: string;
  declare secretEnc: string;
  declare status: 'pending' | 'enabled';
  declare createdAt: CreationOptional<Date>;
  declare enabledAt: CreationOptional<Date | null>;
}

export class RecoveryCodeModel extends Model<
  InferAttributes<RecoveryCodeModel>,
  InferCreationAttributes<RecoveryCodeModel>
> {
  declare id: string;
  declare userId: string;
  declare codeHash: string;
  declare usedAt: CreationOptional<Date | null>;
  declare createdAt: CreationOptional<Date>;
}

const createdAt = { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW };

/**
 * Binds the model classes to a Sequelize instance. Column names are snake_case
 * (underscored: true); the audit_events table is accessed with raw SQL on purpose
 * (append-only, hash-chained, see modules/audit).
 */
export function initModels(sequelize: Sequelize) {
  UserModel.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true },
      email: { type: DataTypes.TEXT, allowNull: false, unique: true },
      passwordHash: { type: DataTypes.TEXT, allowNull: false },
      roles: {
        type: DataTypes.ARRAY(DataTypes.TEXT),
        allowNull: false,
        defaultValue: ['user'],
      },
      lockedAt: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
      createdAt: DataTypes.DATE,
      updatedAt: DataTypes.DATE,
    },
    { sequelize, tableName: 'users', underscored: true, timestamps: true },
  );

  SessionModel.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      userAgent: { type: DataTypes.TEXT, allowNull: true },
      ip: { type: DataTypes.TEXT, allowNull: true },
      createdAt,
      lastUsedAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
      revokedAt: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
    },
    { sequelize, tableName: 'sessions', underscored: true, timestamps: false },
  );

  RefreshTokenModel.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true },
      sessionId: { type: DataTypes.UUID, allowNull: false },
      familyId: { type: DataTypes.UUID, allowNull: false },
      userId: { type: DataTypes.UUID, allowNull: false },
      tokenHash: { type: DataTypes.TEXT, allowNull: false, unique: true },
      replacedBy: { type: DataTypes.UUID, allowNull: true, defaultValue: null },
      revokedAt: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      createdAt,
    },
    { sequelize, tableName: 'refresh_tokens', underscored: true, timestamps: false },
  );

  MfaCredentialModel.init(
    {
      userId: { type: DataTypes.UUID, primaryKey: true },
      secretEnc: { type: DataTypes.TEXT, allowNull: false },
      status: { type: DataTypes.TEXT, allowNull: false },
      createdAt,
      enabledAt: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
    },
    { sequelize, tableName: 'mfa_credentials', underscored: true, timestamps: false },
  );

  RecoveryCodeModel.init(
    {
      id: { type: DataTypes.UUID, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      codeHash: { type: DataTypes.TEXT, allowNull: false },
      usedAt: { type: DataTypes.DATE, allowNull: true, defaultValue: null },
      createdAt,
    },
    { sequelize, tableName: 'recovery_codes', underscored: true, timestamps: false },
  );
}
