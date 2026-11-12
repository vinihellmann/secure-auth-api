import { QueryTypes } from 'sequelize';
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
    expect(before.body.ok).toBe(true);
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
        await db.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable', { transaction });
        await db.query('UPDATE audit_events SET metadata = CAST(:m AS jsonb) WHERE id = CAST(:id AS bigint)', {
          replacements: { m: JSON.stringify(metadata), id: target.id },
          transaction,
        });
        await db.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable', { transaction });
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
});
