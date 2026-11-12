import type { Migration } from '../migrator';

/**
 * Defense in depth for the hash chain: the database itself refuses UPDATE, DELETE
 * and TRUNCATE on audit_events. A superuser or table owner can still disable the
 * trigger, which is exactly what the hash chain is there to detect.
 */
export const migration: Migration = {
  name: '003-audit-immutability',
  up: async ({ sequelize }) => {
    await sequelize.query(`
      CREATE FUNCTION audit_events_block_mutation() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP
          USING ERRCODE = 'integrity_constraint_violation';
      END;
      $$ LANGUAGE plpgsql;

      CREATE TRIGGER audit_events_immutable
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();

      CREATE TRIGGER audit_events_no_truncate
        BEFORE TRUNCATE ON audit_events
        FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_mutation();
    `);
  },
  down: async ({ sequelize }) => {
    await sequelize.query(`
      DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
      DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
      DROP FUNCTION IF EXISTS audit_events_block_mutation();
    `);
  },
};
