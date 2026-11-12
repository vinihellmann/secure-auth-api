import { sha256Hex } from '../../infra/crypto/hash';

/** prev_hash of the very first event in the chain. */
export const GENESIS_HASH = '0'.repeat(64);

export interface AuditEventCore {
  occurredAt: Date;
  actorUserId: string | null;
  eventType: string;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
}

export interface StoredAuditEvent extends AuditEventCore {
  id: string;
  prevHash: string;
  hash: string;
}

/**
 * Deterministic JSON: object keys sorted recursively, undefined dropped, Dates as ISO strings.
 * Needed because Postgres jsonb does not preserve key order, so the hash input must not
 * depend on it. Metadata must therefore avoid floats (jsonb may normalise their text form).
 */
export function canonicalize(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const entries = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
  return `{${entries.join(',')}}`;
}

/** hash = SHA-256( canonical JSON of the event fields plus prevHash ). */
export function computeEventHash(core: AuditEventCore, prevHash: string): string {
  return sha256Hex(
    canonicalize({
      occurredAt: core.occurredAt.toISOString(),
      actorUserId: core.actorUserId,
      eventType: core.eventType,
      ip: core.ip,
      userAgent: core.userAgent,
      metadata: core.metadata,
      prevHash,
    }),
  );
}

export interface ChainBreak {
  id: string;
  reason: 'prev_hash_mismatch' | 'hash_mismatch';
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  headHash: string;
  firstBroken?: ChainBreak;
}

/**
 * Incremental verifier so very long chains can be walked in batches.
 * Feed events in ascending id order; push() returns the first break it finds.
 */
export class ChainVerifier {
  private expectedPrev: string;
  private count = 0;

  constructor(startPrevHash: string = GENESIS_HASH) {
    this.expectedPrev = startPrevHash;
  }

  push(event: StoredAuditEvent): ChainBreak | null {
    if (event.prevHash !== this.expectedPrev) {
      return { id: event.id, reason: 'prev_hash_mismatch' };
    }
    if (computeEventHash(event, event.prevHash) !== event.hash) {
      return { id: event.id, reason: 'hash_mismatch' };
    }
    this.expectedPrev = event.hash;
    this.count += 1;
    return null;
  }

  get checked(): number {
    return this.count;
  }

  get head(): string {
    return this.expectedPrev;
  }
}

export function verifyChain(events: Iterable<StoredAuditEvent>): VerifyResult {
  const verifier = new ChainVerifier();
  for (const event of events) {
    const broken = verifier.push(event);
    if (broken) {
      return { ok: false, checked: verifier.checked, headHash: verifier.head, firstBroken: broken };
    }
  }
  return { ok: true, checked: verifier.checked, headHash: verifier.head };
}
