import type { Migration } from '../migrator';

export const migration: Migration = {
  name: '001-init',
  up: async ({ sequelize }) => {
    await sequelize.query(`
      CREATE TABLE users (
        id uuid PRIMARY KEY,
        email text NOT NULL UNIQUE,
        password_hash text NOT NULL,
        roles text[] NOT NULL DEFAULT ARRAY['user']::text[],
        locked_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE sessions (
        id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user_agent text,
        ip text,
        created_at timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz NOT NULL DEFAULT now(),
        revoked_at timestamptz
      );
      CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;

      CREATE TABLE refresh_tokens (
        id uuid PRIMARY KEY,
        session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        family_id uuid NOT NULL,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash text NOT NULL UNIQUE,
        replaced_by uuid,
        revoked_at timestamptz,
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
      CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

      CREATE TABLE mfa_credentials (
        user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        secret_enc text NOT NULL,
        status text NOT NULL CHECK (status IN ('pending', 'enabled')),
        created_at timestamptz NOT NULL DEFAULT now(),
        enabled_at timestamptz
      );

      CREATE TABLE recovery_codes (
        id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash text NOT NULL,
        used_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (user_id, code_hash)
      );
    `);
  },
  down: async ({ sequelize }) => {
    await sequelize.query(`
      DROP TABLE IF EXISTS recovery_codes;
      DROP TABLE IF EXISTS mfa_credentials;
      DROP TABLE IF EXISTS refresh_tokens;
      DROP TABLE IF EXISTS sessions;
      DROP TABLE IF EXISTS users;
    `);
  },
};
