import { ChainVerifier, type StoredAuditEvent, type VerifyResult } from './chain';
import type { AuditFilters, AuditRepository } from './audit.repository';

export interface AuditInput {
  eventType: string;
  actorUserId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

/** Narrow port used by the other services, trivial to fake in unit tests. */
export interface AuditRecorder {
  record(input: AuditInput): Promise<void>;
}

const VERIFY_BATCH_SIZE = 500;

export class AuditService implements AuditRecorder {
  constructor(private readonly repo: AuditRepository) {}

  async record(input: AuditInput): Promise<void> {
    await this.repo.append({
      occurredAt: new Date(),
      actorUserId: input.actorUserId ?? null,
      eventType: input.eventType,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
      metadata: input.metadata ?? {},
    });
  }

  async list(
    filters: AuditFilters,
  ): Promise<{ items: StoredAuditEvent[]; nextCursor: string | null }> {
    // Fetch one extra row to know whether another page exists.
    const rows = await this.repo.list({ ...filters, limit: filters.limit + 1 });
    const hasMore = rows.length > filters.limit;
    const items = hasMore ? rows.slice(0, filters.limit) : rows;
    const last = items[items.length - 1];
    return { items, nextCursor: hasMore && last ? last.id : null };
  }

  /** Walks the whole chain in id order and reports the first broken link. */
  async verify(): Promise<VerifyResult> {
    const verifier = new ChainVerifier();
    let after: string | null = null;
    for (;;) {
      const batch: StoredAuditEvent[] = await this.repo.fetchBatchAfter(after, VERIFY_BATCH_SIZE);
      if (batch.length === 0) break;
      for (const event of batch) {
        const broken = verifier.push(event);
        if (broken) {
          return {
            ok: false,
            checked: verifier.checked,
            headHash: verifier.head,
            firstBroken: broken,
          };
        }
      }
      after = (batch[batch.length - 1] as StoredAuditEvent).id;
    }
    return { ok: true, checked: verifier.checked, headHash: verifier.head };
  }
}
