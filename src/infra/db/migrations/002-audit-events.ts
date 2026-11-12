import type { Migration } from '../migrator';

export const migration: Migration = {
  name: '002-audit-events',
  up: async (sequelize) => {
    // actor_user_id intentionally has no foreign key: audit rows must outlive users.
    await sequelize.query(`
      CREATE TABLE audit_events (
        id bigserial PRIMARY KEY,
        occurred_at timestamptz NOT NULL,
        actor_user_id uuid,
        event_type text NOT NULL,
        ip text,
        user_agent text,
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        prev_hash text NOT NULL,
        hash text NOT NULL UNIQUE
      );
      CREATE INDEX audit_events_type_idx ON audit_events (event_type, id DESC);
      CREATE INDEX audit_events_actor_idx ON audit_events (actor_user_id, id DESC);
      CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at);
    `);
  },
  down: async (sequelize) => {
    await sequelize.query(`DROP TABLE IF EXISTS audit_events;`);
  },
};
