import { SequelizeStorage, Umzug } from 'umzug';
import type { Sequelize } from 'sequelize';
import { migration as init } from './migrations/001-init';
import { migration as auditEvents } from './migrations/002-audit-events';
import { migration as auditImmutability } from './migrations/003-audit-immutability';

export interface Migration {
  name: string;
  up: (sequelize: Sequelize) => Promise<void>;
  down: (sequelize: Sequelize) => Promise<void>;
}

const MIGRATIONS: Migration[] = [init, auditEvents, auditImmutability];

export type MigrationLog = (message: Record<string, unknown>) => void;

/**
 * Programmatic migrations (umzug). Applied migrations are tracked in the
 * "SequelizeMeta" table, so running this on every deploy is idempotent.
 */
export function createMigrator(sequelize: Sequelize, log?: MigrationLog) {
  const noop: MigrationLog = () => undefined;
  const logger = { info: log ?? noop, warn: log ?? noop, error: log ?? noop, debug: noop };
  return new Umzug<Sequelize>({
    migrations: MIGRATIONS.map((m) => ({
      name: m.name,
      up: async ({ context }) => m.up(context),
      down: async ({ context }) => m.down(context),
    })),
    context: sequelize,
    storage: new SequelizeStorage({ sequelize }),
    logger,
  });
}

export async function runMigrations(sequelize: Sequelize, log?: MigrationLog): Promise<string[]> {
  const applied = await createMigrator(sequelize, log).up();
  return applied.map((m) => m.name);
}
