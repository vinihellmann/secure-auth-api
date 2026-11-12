/**
 * One-shot: applies pending migrations, then seeds the admin account from ADMIN_EMAIL /
 * ADMIN_PASSWORD when set. Safe to run on every deploy.
 */
import { loadConfig } from '../src/config/env';
import { runMigrations } from '../src/infra/db/migrator';
import { initModels } from '../src/infra/db/models';
import { createSequelize } from '../src/infra/db/sequelize';
import { createLogger } from '../src/infra/logger';
import { BcryptPasswordHasher } from '../src/modules/users/password-hasher';
import { seedAdmin } from '../src/modules/users/seed-admin';
import { SequelizeUsersRepository } from '../src/modules/users/users.repository';

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ level: config.logLevel });
  const sequelize = createSequelize(config.databaseUrl);
  try {
    const applied = await runMigrations(sequelize);
    logger.info('migrations_applied', { applied });

    if (config.admin) {
      initModels(sequelize);
      const result = await seedAdmin(
        new SequelizeUsersRepository(),
        new BcryptPasswordHasher(config.bcryptCost),
        config.admin,
      );
      logger.info('admin_seed', { email: config.admin.email, result });
    }
  } finally {
    await sequelize.close();
  }
}

main().catch((err: unknown) => {
  createLogger({ level: 'error' }).error('migrate_failed', {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
