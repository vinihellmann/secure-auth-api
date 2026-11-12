import type { Express } from 'express';
import type { AppConfig } from './config/env';
import { createApp } from './http/app';
import { createEnvelopeCrypto } from './infra/crypto/envelope';
import { loadKeyStore } from './infra/crypto/jwt-keys';
import { loadMacKeyring } from './infra/crypto/mac';
import { initModels } from './infra/db/models';
import { createSequelize } from './infra/db/sequelize';
import type { Logger } from './infra/logger';
import { SlidingWindowLimiter } from './infra/rate-limit/sliding-window';
import { createRedis } from './infra/redis/client';
import {
  RedisLockoutStore,
  RedisMfaChallengeStore,
  RedisRevokedSessionCache,
  RedisTotpStepStore,
} from './infra/redis/stores';
import { createSecretsProvider, type SecretsProvider } from './infra/secrets';
import { SequelizeAuditRepository } from './modules/audit/audit.repository';
import { AuditService } from './modules/audit/audit.service';
import { AuthService } from './modules/auth/auth.service';
import { LoginLockout } from './modules/auth/lockout';
import { TokenService } from './modules/auth/tokens';
import { SequelizeMfaRepository } from './modules/mfa/mfa.repository';
import { RecoveryCodeHasher } from './modules/mfa/recovery-codes';
import { MfaService } from './modules/mfa/mfa.service';
import { TotpVerifier } from './modules/mfa/totp';
import { SequelizeSessionsRepository } from './modules/sessions/sessions.repository';
import { SessionService } from './modules/sessions/sessions.service';
import { PasswordConfirmer } from './modules/users/password-confirmation';
import { createPasswordHasher } from './modules/users/password-hasher';
import { SequelizeUsersRepository } from './modules/users/users.repository';
import { UsersService } from './modules/users/users.service';

export interface ContainerOptions {
  secrets?: SecretsProvider;
  configurePublicRoutes?: (app: Express) => void;
}

/** Composition root: the only place that knows concrete implementations. */
export async function createContainer(
  config: AppConfig,
  logger: Logger,
  opts: ContainerOptions = {},
) {
  const secrets = opts.secrets ?? createSecretsProvider(config);
  const [keys, envelope, mac] = await Promise.all([
    loadKeyStore(secrets, config.jwt.activeKid),
    createEnvelopeCrypto(secrets, config.kekActiveVersion),
    loadMacKeyring(secrets, config.macActiveVersion),
  ]);

  const sequelize = createSequelize(config.databaseUrl);
  initModels(sequelize);
  const redis = createRedis(config.redisUrl, logger);

  const audit = new AuditService(new SequelizeAuditRepository(sequelize, mac), mac);
  const hasher = createPasswordHasher({ scrypt: config.scrypt });
  const lockoutStore = new RedisLockoutStore(redis);
  // Re-authentication (change password, disable 2FA) has its own lockout key per user, so a
  // stolen access token cannot brute-force the current password.
  const passwordConfirmation = new PasswordConfirmer(hasher, new LoginLockout(lockoutStore));
  const usersRepo = new SequelizeUsersRepository();
  const tokens = new TokenService(
    keys,
    {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      accessTtlSeconds: config.jwt.accessTtlSeconds,
      mfaTtlSeconds: config.jwt.mfaTtlSeconds,
    },
    { requireTyp: config.jwt.requireTyp },
  );
  const sessions = new SessionService({
    repo: new SequelizeSessionsRepository(sequelize),
    // Revocation markers only need to outlive the longest-lived access token.
    revoked: new RedisRevokedSessionCache(redis, config.jwt.accessTtlSeconds + 60),
    audit,
    refreshTtlDays: config.refreshTtlDays,
  });
  const mfa = new MfaService({
    repo: new SequelizeMfaRepository(sequelize),
    users: usersRepo,
    passwordConfirmation,
    recoveryCodes: new RecoveryCodeHasher(mac),
    envelope,
    totp: new TotpVerifier(new RedisTotpStepStore(redis)),
    audit,
    issuer: config.totpIssuer,
  });
  const users = new UsersService({
    users: usersRepo,
    hasher,
    passwordConfirmation,
    sessions,
    audit,
    isMfaEnabled: (userId) => mfa.isEnabled(userId),
  });
  const auth = new AuthService({
    users: usersRepo,
    hasher,
    tokens,
    sessions,
    mfa,
    lockout: new LoginLockout(lockoutStore),
    challenges: new RedisMfaChallengeStore(redis),
    audit,
    mfaTtlSeconds: config.jwt.mfaTtlSeconds,
  });

  const readiness = async (): Promise<Record<string, boolean>> => {
    const [postgres, redisOk] = await Promise.all([
      sequelize.authenticate().then(
        () => true,
        () => false,
      ),
      redis.ping().then(
        (r) => r === 'PONG',
        () => false,
      ),
    ]);
    return { postgres, redis: redisOk };
  };

  const app = createApp({
    config,
    logger,
    keys,
    tokens,
    limiter: new SlidingWindowLimiter(redis),
    auth,
    users,
    sessions,
    mfa,
    audit,
    readiness,
    configurePublicRoutes: opts.configurePublicRoutes,
  });

  return {
    app,
    sequelize,
    redis,
    keys,
    envelope,
    mac,
    tokens,
    async close(): Promise<void> {
      await Promise.allSettled([sequelize.close(), redis.quit()]);
    },
  };
}

export type Container = Awaited<ReturnType<typeof createContainer>>;
