import { QueryTypes } from 'sequelize';
import { computeEventHash } from '../../src/modules/audit/chain';
import { client, loginAdmin, registerAndLogin, startApp, type TestContext } from './helpers';

let ctx: TestContext;
let adminToken: string;

beforeAll(async () => {
  ctx = await startApp();
  adminToken = await loginAdmin(ctx);
});

afterAll(async () => {
  await ctx?.container.close();
});

const verify = () => client(ctx).get('/v1/admin/audit-events/verify', adminToken);

describe('tamper-evident audit log', () => {
  it('records security events and lists them with cursor pagination', async () => {
    const user = await registerAndLogin(ctx);
    const res = await client(ctx).get(
      `/v1/admin/audit-events?actorUserId=${user.id}&limit=1`,
      adminToken,
    );
    expect(res.status).toBe(200);
    expect(res.body.items).toHaveLength(1);
    expect(res.body.items[0]).toMatchObject({ eventType: 'login_succeeded', actorUserId: user.id });
    expect(res.body.items[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(res.body.nextCursor).toEqual(expect.any(String));

    const next = await client(ctx).get(
      `/v1/admin/audit-events?actorUserId=${user.id}&limit=1&cursor=${res.body.nextCursor}`,
      adminToken,
    );
    expect(next.body.items[0].eventType).toBe('user_registered');
  });

  it('refuses UPDATE and DELETE at the database level', async () => {
    await expect(
      ctx.container.sequelize.query(
        `UPDATE audit_events SET event_type = 'x' WHERE id = (SELECT min(id) FROM audit_events)`,
      ),
    ).rejects.toThrow(/append-only/);
    await expect(ctx.container.sequelize.query('DELETE FROM audit_events')).rejects.toThrow(
      /append-only/,
    );
  });

  it('verifies the chain and pinpoints a tampered row', async () => {
    await registerAndLogin(ctx); // make sure there are fresh events
    const before = await verify();
    expect(before.status).toBe(200);
    if (!before.body.ok) {
      // Surface the offending rows so a broken chain is diagnosable from CI logs alone.
      const rows = await ctx.container.sequelize.query(
        `SELECT id::text AS id, occurred_at, actor_user_id, event_type, ip, user_agent, metadata,
                prev_hash, hash
           FROM audit_events WHERE id BETWEEN CAST(:id AS bigint) - 1 AND CAST(:id AS bigint)
           ORDER BY id`,
        { type: QueryTypes.SELECT, replacements: { id: before.body.firstBroken?.id ?? '0' } },
      );
      throw new Error(`chain broken: ${JSON.stringify({ verify: before.body, rows }, null, 2)}`);
    }
    expect(before.body.checked).toBeGreaterThan(1);

    const db = ctx.container.sequelize;
    const [target] = await db.query<{ id: string; metadata: unknown }>(
      `SELECT id::text AS id, metadata FROM audit_events ORDER BY id DESC OFFSET 1 LIMIT 1`,
      { type: QueryTypes.SELECT },
    );
    if (!target) throw new Error('no audit events');

    // Simulate an attacker with table-owner rights: disable the trigger and rewrite history.
    const rewrite = async (metadata: unknown): Promise<void> => {
      await db.transaction(async (transaction) => {
        await db.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable', {
          transaction,
        });
        await db.query(
          'UPDATE audit_events SET metadata = CAST(:m AS jsonb) WHERE id = CAST(:id AS bigint)',
          {
            replacements: { m: JSON.stringify(metadata), id: target.id },
            transaction,
          },
        );
        await db.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable', {
          transaction,
        });
      });
    };

    await rewrite({ tampered: true });
    try {
      const after = await verify();
      expect(after.body.ok).toBe(false);
      expect(after.body.firstBroken).toEqual({ id: target.id, reason: 'hash_mismatch' });
    } finally {
      await rewrite(target.metadata); // restore so the chain is valid for later runs
    }

    expect((await verify()).body.ok).toBe(true);
  });
  it('detects the old attack: row rewritten and plain SHA-256 recomputed for it and every later row', async () => {
    await registerAndLogin(ctx);
    await registerAndLogin(ctx);
    expect((await verify()).body.ok).toBe(true);

    const db = ctx.container.sequelize;
    type Row = {
      id: string;
      occurred_at: Date;
      actor_user_id: string | null;
      event_type: string;
      ip: string | null;
      user_agent: string | null;
      metadata: Record<string, unknown>;
      prev_hash: string;
      hash: string;
      mac_key_id: string | null;
    };
    const original = await db.query<Row>(
      `SELECT id::text AS id, occurred_at, actor_user_id, event_type, ip, user_agent, metadata,
              prev_hash, hash, mac_key_id
         FROM audit_events ORDER BY audit_events.id DESC LIMIT 3`,
      { type: QueryTypes.SELECT },
    );
    const rows = [...original].reverse(); // ascending
    const [first] = rows;
    if (!first) throw new Error('no audit events');

    // Attacker: rewrite the oldest of these rows, then recompute unkeyed SHA-256 links for all of them.
    let prev = first.prev_hash;
    const forged = rows.map((r, i) => {
      const metadata = i === 0 ? { tampered: true } : r.metadata;
      const core = {
        occurredAt: r.occurred_at,
        actorUserId: r.actor_user_id,
        eventType: r.event_type,
        ip: r.ip,
        userAgent: r.user_agent,
        metadata,
      };
      const hash = computeEventHash(core, prev);
      const out = { id: r.id, metadata, prevHash: prev, hash };
      prev = hash;
      return out;
    });

    const apply = async (
      values: {
        id: string;
        metadata: unknown;
        prevHash: string;
        hash: string;
        macKeyId: string | null;
      }[],
    ): Promise<void> => {
      await db.transaction(async (transaction) => {
        await db.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable', {
          transaction,
        });
        for (const v of values) {
          await db.query(
            `UPDATE audit_events
                SET metadata = CAST(:m AS jsonb), prev_hash = :prevHash, hash = :hash,
                    mac_key_id = :macKeyId
              WHERE id = CAST(:id AS bigint)`,
            {
              replacements: {
                m: JSON.stringify(v.metadata),
                prevHash: v.prevHash,
                hash: v.hash,
                macKeyId: v.macKeyId,
                id: v.id,
              },
              transaction,
            },
          );
        }
        await db.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable', {
          transaction,
        });
      });
    };

    await apply(forged.map((f) => ({ ...f, macKeyId: null })));
    try {
      const after = await verify();
      expect(after.body.ok).toBe(false);
      expect(after.body.firstBroken?.id).toBe(first.id);
    } finally {
      await apply(
        rows.map((r) => ({
          id: r.id,
          metadata: r.metadata,
          prevHash: r.prev_hash,
          hash: r.hash,
          macKeyId: r.mac_key_id,
        })),
      );
    }

    expect((await verify()).body.ok).toBe(true);
  });
});
