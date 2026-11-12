import { SequelizeStorage, Umzug } from 'umzug';
import type { Sequelize } from 'sequelize';
import type { MacKeyring } from '../crypto/mac';
import { migration as init } from './migrations/001-init';
import { migration as auditEvents } from './migrations/002-audit-events';
import { migration as auditImmutability } from './migrations/003-audit-immutability';
import { migration as auditMac } from './migrations/004-audit-mac';

/** Passed to every migration. `mac` is only needed by migrations that sign existing data. */
export interface MigrationContext {
  sequelize: Sequelize;
  mac?: MacKeyring;
}

export interface Migration {
  name: string;
  up: (context: MigrationContext) => Promise<void>;
  down: (context: MigrationContext) => Promise<void>;
}

const MIGRATIONS: Migration[] = [init, auditEvents, auditImmutability, auditMac];

export type MigrationLog = (message: Record<string, unknown>) => void;

/**
 * Programmatic migrations (umzug). Applied migrations are tracked in the
 * "SequelizeMeta" table, so running this on every deploy is idempotent.
 */
export function createMigrator(
  sequelize: Sequelize,
  log?: MigrationLog,
  context?: { mac?: MacKeyring },
) {
  const noop: MigrationLog = () => undefined;
  const logger = { info: log ?? noop, warn: log ?? noop, error: log ?? noop, debug: noop };
  const migrationContext: MigrationContext = {
    sequelize,
    ...(context?.mac ? { mac: context.mac } : {}),
  };
  return new Umzug<MigrationContext>({
    migrations: MIGRATIONS.map((m) => ({
      name: m.name,
      up: async ({ context: c }) => m.up(c),
      down: async ({ context: c }) => m.down(c),
    })),
    context: migrationContext,
    storage: new SequelizeStorage({ sequelize }),
    logger,
  });
}

export async function runMigrations(
  sequelize: Sequelize,
  log?: MigrationLog,
  context?: { mac?: MacKeyring },
): Promise<string[]> {
  const applied = await createMigrator(sequelize, log, context).up();
  return applied.map((m) => m.name);
}
