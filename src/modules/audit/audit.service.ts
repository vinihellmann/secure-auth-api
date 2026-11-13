import type { MacKeyring } from '../../infra/crypto/mac';
import {
  ChainVerifier,
  GENESIS_HASH,
  resolveAnchor,
  type StoredAuditEvent,
  type VerifyResult,
} from './chain';
import type { AuditFilters, AuditRepository } from './audit.repository';

export type AuditEventType =
  | 'admin_user_locked'
  | 'admin_user_unlocked'
  | 'login_blocked_account_locked'
  | 'login_failed'
  | 'login_mfa_challenge_issued'
  | 'login_mfa_failed'
  | 'login_succeeded'
  | 'logout'
  | 'mfa_disable_failed'
  | 'mfa_disabled'
  | 'mfa_enable_failed'
  | 'mfa_enabled'
  | 'mfa_setup_failed'
  | 'mfa_setup_started'
  | 'password_change_failed'
  | 'password_changed'
  | 'password_rehashed'
  | 'reauth_failed'
  | 'refresh_token_reuse_detected'
  | 'session_revoked'
  | 'user_registered';

export interface AuditInput {
  eventType: AuditEventType;
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
  constructor(
    private readonly repo: AuditRepository,
    private readonly keyring: MacKeyring,
  ) {}

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

  /**
   * Walks the whole chain in id order and reports the first broken link. Legacy (unkeyed) rows
   * are only accepted up to the id signed in the cut-over anchor; a missing anchor accepts none
   * and an invalid one fails verification outright.
   */
  async verify(): Promise<VerifyResult> {
    const { state, legacyUntil } = resolveAnchor(await this.repo.getAnchor(), this.keyring);
    if (state === 'invalid') {
      return { ok: false, checked: 0, headHash: GENESIS_HASH, legacyRows: 0, anchor: state };
    }
    const verifier = new ChainVerifier({ keyring: this.keyring, legacyUntil });
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
            legacyRows: verifier.legacyRows,
            anchor: state,
          };
        }
      }
      after = (batch[batch.length - 1] as StoredAuditEvent).id;
    }
    return {
      ok: true,
      checked: verifier.checked,
      headHash: verifier.head,
      legacyRows: verifier.legacyRows,
      anchor: state,
    };
  }
}
