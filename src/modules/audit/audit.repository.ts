import { QueryTypes, type Sequelize } from 'sequelize';
import {
  GENESIS_HASH,
  computeEventHash,
  type AuditEventCore,
  type StoredAuditEvent,
} from './chain';

/**
 * Arbitrary constant used as the advisory lock key that serialises appends.
 * Every writer takes the same transaction-scoped lock, so "read last hash, insert next"
 * is a critical section and the chain cannot fork under concurrency.
 */
export const AUDIT_ADVISORY_LOCK_KEY = 7263910001;

export interface AuditFilters {
  limit: number;
  cursor?: string;
  eventType?: string;
  actorUserId?: string;
  from?: Date;
  to?: Date;
}

export interface AuditRepository {
  append(event: AuditEventCore): Promise<StoredAuditEvent>;
  list(filters: AuditFilters): Promise<StoredAuditEvent[]>;
  fetchBatchAfter(afterId: string | null, limit: number): Promise<StoredAuditEvent[]>;
}

interface AuditRow {
  id: string;
  occurred_at: Date;
  actor_user_id: string | null;
  event_type: string;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

const SELECT_COLUMNS = `id::text AS id, occurred_at, actor_user_id, event_type, ip, user_agent, metadata, prev_hash, hash`;

const toEvent = (r: AuditRow): StoredAuditEvent => ({
  id: r.id,
  occurredAt: r.occurred_at,
  actorUserId: r.actor_user_id,
  eventType: r.event_type,
  ip: r.ip,
  userAgent: r.user_agent,
  metadata: r.metadata,
  prevHash: r.prev_hash,
  hash: r.hash,
});

export class SequelizeAuditRepository implements AuditRepository {
  constructor(private readonly sequelize: Sequelize) {}

  async append(event: AuditEventCore): Promise<StoredAuditEvent> {
    return this.sequelize.transaction(async (t) => {
      await this.sequelize.query(`SELECT pg_advisory_xact_lock(${AUDIT_ADVISORY_LOCK_KEY})`, {
        transaction: t,
      });
      const last = await this.sequelize.query<{ hash: string }>(
        'SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1',
        { type: QueryTypes.SELECT, transaction: t },
      );
      const prevHash = last[0]?.hash ?? GENESIS_HASH;
      const hash = computeEventHash(event, prevHash);
      const inserted = await this.sequelize.query<{ id: string }>(
        `INSERT INTO audit_events
           (occurred_at, actor_user_id, event_type, ip, user_agent, metadata, prev_hash, hash)
         VALUES
           (CAST(:occurredAt AS timestamptz), :actorUserId, :eventType, :ip, :userAgent,
            CAST(:metadata AS jsonb), :prevHash, :hash)
         RETURNING id::text AS id`,
        {
          type: QueryTypes.SELECT,
          transaction: t,
          replacements: {
            occurredAt: event.occurredAt.toISOString(),
            actorUserId: event.actorUserId,
            eventType: event.eventType,
            ip: event.ip,
            userAgent: event.userAgent,
            metadata: JSON.stringify(event.metadata),
            prevHash,
            hash,
          },
        },
      );
      return { ...event, id: (inserted[0] as { id: string }).id, prevHash, hash };
    });
  }

  async list(f: AuditFilters): Promise<StoredAuditEvent[]> {
    const where: string[] = [];
    const replacements: Record<string, unknown> = { limit: f.limit };
    if (f.cursor) {
      where.push('id < CAST(:cursor AS bigint)');
      replacements.cursor = f.cursor;
    }
    if (f.eventType) {
      where.push('event_type = :eventType');
      replacements.eventType = f.eventType;
    }
    if (f.actorUserId) {
      where.push('actor_user_id = :actorUserId');
      replacements.actorUserId = f.actorUserId;
    }
    if (f.from) {
      where.push('occurred_at >= CAST(:from AS timestamptz)');
      replacements.from = f.from.toISOString();
    }
    if (f.to) {
      where.push('occurred_at <= CAST(:to AS timestamptz)');
      replacements.to = f.to.toISOString();
    }
    const rows = await this.sequelize.query<AuditRow>(
      `SELECT ${SELECT_COLUMNS} FROM audit_events
       ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
       ORDER BY id DESC LIMIT :limit`,
      { type: QueryTypes.SELECT, replacements },
    );
    return rows.map(toEvent);
  }

  async fetchBatchAfter(afterId: string | null, limit: number): Promise<StoredAuditEvent[]> {
    const rows = await this.sequelize.query<AuditRow>(
      `SELECT ${SELECT_COLUMNS} FROM audit_events
       WHERE id > CAST(:after AS bigint) ORDER BY id ASC LIMIT :limit`,
      { type: QueryTypes.SELECT, replacements: { after: afterId ?? '0', limit } },
    );
    return rows.map(toEvent);
  }
}
