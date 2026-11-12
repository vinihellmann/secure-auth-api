import { safeEqual, sha256Hex } from '../../infra/crypto/hash';
import type { MacKeyring } from '../../infra/crypto/mac';

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
  /** MAC key version; null = legacy row written before keyed chaining (unkeyed SHA-256). */
  macKeyId: string | null;
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

function chainFields(core: AuditEventCore, prevHash: string) {
  return {
    occurredAt: core.occurredAt.toISOString(),
    actorUserId: core.actorUserId,
    eventType: core.eventType,
    ip: core.ip,
    userAgent: core.userAgent,
    metadata: core.metadata,
    prevHash,
  };
}

/** Legacy (unkeyed) hash = SHA-256( canonical JSON of the event fields plus prevHash ). */
export function computeEventHash(core: AuditEventCore, prevHash: string): string {
  return sha256Hex(canonicalize(chainFields(core, prevHash)));
}

/**
 * Keyed hash = HMAC-SHA256 (purpose "audit-chain") over the same fields plus macKeyId, so the
 * key version cannot be swapped without invalidating the row.
 */
export function computeEventMac(
  core: AuditEventCore,
  prevHash: string,
  keyring: MacKeyring,
  macKeyId: string,
): string {
  return keyring.mac(
    'audit-chain',
    canonicalize({ ...chainFields(core, prevHash), macKeyId }),
    macKeyId,
  );
}

/**
 * Canonical message authenticated by the cut-over anchor: `legacy_until_id=<decimal id>`.
 * Rows with id <= legacy_until_id are legacy (unkeyed); every later row must be keyed.
 */
export const anchorMessage = (legacyUntilId: string | bigint | number): string =>
  `legacy_until_id=${legacyUntilId.toString()}`;

export interface StoredAnchor {
  legacyUntilId: string;
  macKeyId: string;
  mac: string;
}

export type AnchorState = 'absent' | 'valid' | 'invalid';

/** An absent or invalid anchor accepts no legacy rows (legacyUntil = 0). */
export function resolveAnchor(
  anchor: StoredAnchor | null,
  keyring: MacKeyring,
): { state: AnchorState; legacyUntil: bigint } {
  if (!anchor) return { state: 'absent', legacyUntil: 0n };
  let id: bigint;
  try {
    id = BigInt(anchor.legacyUntilId);
  } catch {
    return { state: 'invalid', legacyUntil: 0n };
  }
  const valid =
    id >= 0n && keyring.verify('audit-anchor', anchorMessage(id), anchor.mac, anchor.macKeyId);
  return valid ? { state: 'valid', legacyUntil: id } : { state: 'invalid', legacyUntil: 0n };
}

export interface ChainBreak {
  id: string;
  reason: 'prev_hash_mismatch' | 'hash_mismatch' | 'unkeyed_after_cutover' | 'unknown_mac_key';
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  headHash: string;
  firstBroken?: ChainBreak;
  /** Number of legacy (unkeyed) rows verified. */
  legacyRows: number;
  anchor: AnchorState;
}

export interface ChainVerifierOptions {
  keyring: MacKeyring;
  /** Highest id accepted as a legacy row (from a VALID anchor); 0 when none. */
  legacyUntil?: bigint;
  startPrevHash?: string;
}

/**
 * Incremental verifier so very long chains can be walked in batches.
 * Feed events in ascending id order; push() returns the first break it finds.
 */
export class ChainVerifier {
  private expectedPrev: string;
  private count = 0;
  private legacy = 0;
  private readonly keyring: MacKeyring;
  private readonly legacyUntil: bigint;

  constructor(options: ChainVerifierOptions) {
    this.keyring = options.keyring;
    this.legacyUntil = options.legacyUntil ?? 0n;
    this.expectedPrev = options.startPrevHash ?? GENESIS_HASH;
  }

  push(event: StoredAuditEvent): ChainBreak | null {
    if (event.prevHash !== this.expectedPrev) {
      return { id: event.id, reason: 'prev_hash_mismatch' };
    }
    if (BigInt(event.id) <= this.legacyUntil) {
      if (event.macKeyId !== null || computeEventHash(event, event.prevHash) !== event.hash) {
        return { id: event.id, reason: 'hash_mismatch' };
      }
      this.legacy += 1;
    } else {
      if (event.macKeyId === null) return { id: event.id, reason: 'unkeyed_after_cutover' };
      if (!this.keyring.has(event.macKeyId)) return { id: event.id, reason: 'unknown_mac_key' };
      const expected = computeEventMac(event, event.prevHash, this.keyring, event.macKeyId);
      if (!safeEqual(expected, event.hash)) return { id: event.id, reason: 'hash_mismatch' };
    }
    this.expectedPrev = event.hash;
    this.count += 1;
    return null;
  }

  get checked(): number {
    return this.count;
  }

  get legacyRows(): number {
    return this.legacy;
  }

  get head(): string {
    return this.expectedPrev;
  }
}

export function verifyChain(
  events: Iterable<StoredAuditEvent>,
  options: ChainVerifierOptions & { anchor?: AnchorState },
): VerifyResult {
  const verifier = new ChainVerifier(options);
  const anchor = options.anchor ?? ((options.legacyUntil ?? 0n) > 0n ? 'valid' : 'absent');
  for (const event of events) {
    const broken = verifier.push(event);
    if (broken) {
      return {
        ok: false,
        checked: verifier.checked,
        headHash: verifier.head,
        firstBroken: broken,
        legacyRows: verifier.legacyRows,
        anchor,
      };
    }
  }
  return {
    ok: anchor !== 'invalid',
    checked: verifier.checked,
    headHash: verifier.head,
    legacyRows: verifier.legacyRows,
    anchor,
  };
}
