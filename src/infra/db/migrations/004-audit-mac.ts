import { QueryTypes } from 'sequelize';
import { anchorMessage } from '../../../modules/audit/chain';
import type { Migration } from '../migrator';

/**
 * Keyed audit chain (HMAC) with a downgrade-proof cut-over.
 *
 * - audit_events.mac_key_id: NULL = legacy row (unkeyed SHA-256), otherwise the MAC key version.
 * - audit_chain_anchor: single row recording the last legacy row id (legacy_until_id), itself
 *   authenticated with HMAC (purpose "audit-anchor") over `legacy_until_id=<id>`. Rows after that
 *   id must be keyed, so an attacker cannot relabel MAC rows as legacy rows; forging or moving
 *   the anchor requires the MAC key.
 *
 * When audit_events already holds rows the anchor is created here, which needs the MAC keyring.
 * An empty table gets no anchor (every row is keyed from the start).
 */
export const migration: Migration = {
  name: '004-audit-mac',
  up: async ({ sequelize, mac }) => {
    await sequelize.transaction(async (transaction) => {
      await sequelize.query('ALTER TABLE audit_events ADD COLUMN mac_key_id text;', {
        transaction,
      });
      await sequelize.query(
        `CREATE TABLE audit_chain_anchor (
           id smallint PRIMARY KEY CHECK (id = 1),
           legacy_until_id bigint NOT NULL,
           mac_key_id text NOT NULL,
           mac text NOT NULL,
           created_at timestamptz NOT NULL DEFAULT now()
         );`,
        { transaction },
      );
      const [row] = await sequelize.query<{ max_id: string | null }>(
        'SELECT max(id)::text AS max_id FROM audit_events',
        { type: QueryTypes.SELECT, transaction },
      );
      const maxId = row?.max_id ?? null;
      if (maxId === null) return;
      if (!mac) {
        throw new Error(
          'Migration 004-audit-mac: audit_events already has rows and no MAC keyring was provided. ' +
            'Run the migrate script with the secrets mounted (mac_key_<version>) so the legacy ' +
            'cut-over anchor can be signed.',
        );
      }
      await sequelize.query(
        `INSERT INTO audit_chain_anchor (id, legacy_until_id, mac_key_id, mac)
         VALUES (1, CAST(:id AS bigint), :keyId, :mac)`,
        {
          transaction,
          replacements: {
            id: maxId,
            keyId: mac.activeVersion,
            mac: mac.mac('audit-anchor', anchorMessage(maxId)),
          },
        },
      );
    });
  },
  down: async ({ sequelize }) => {
    await sequelize.query(`
      DROP TABLE IF EXISTS audit_chain_anchor;
      ALTER TABLE audit_events DROP COLUMN IF EXISTS mac_key_id;
    `);
  },
};
