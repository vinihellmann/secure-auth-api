import { randomBytes } from 'node:crypto';
import { MacKeyring } from '../../src/infra/crypto/mac';
import {
  GENESIS_HASH,
  anchorMessage,
  canonicalize,
  computeEventHash,
  computeEventMac,
  resolveAnchor,
  verifyChain,
  type AuditEventCore,
  type StoredAnchor,
  type StoredAuditEvent,
} from '../../src/modules/audit/chain';

const keyring = new MacKeyring(new Map([['1', randomBytes(32)]]), '1');
const otherKeyring = new MacKeyring(new Map([['1', randomBytes(32)]]), '1');

const coreFor = (i: number): AuditEventCore => ({
  occurredAt: new Date(Date.UTC(2025, 0, 1, 0, 0, i)),
  actorUserId: null,
  eventType: i % 2 ? 'login_succeeded' : 'logout',
  ip: '203.0.113.7',
  userAgent: 'jest',
  metadata: { n: i, nested: { b: 2, a: 1 } },
});

/** First `legacy` rows are unkeyed SHA-256 (pre-migration), the rest are keyed with `ring`. */
function buildChain(n: number, legacy = 0, ring: MacKeyring = keyring): StoredAuditEvent[] {
  const events: StoredAuditEvent[] = [];
  let prevHash = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const core = coreFor(i);
    const macKeyId = i <= legacy ? null : '1';
    const hash =
      macKeyId === null
        ? computeEventHash(core, prevHash)
        : computeEventMac(core, prevHash, ring, macKeyId);
    events.push({ ...core, id: String(i), prevHash, hash, macKeyId });
    prevHash = hash;
  }
  return events;
}

/** Attacker without the key: recompute plain SHA-256 for rows `from..` and relabel them legacy. */
function rewriteAsLegacy(chain: StoredAuditEvent[], from: number): StoredAuditEvent[] {
  const out = chain.slice();
  for (let i = from; i < out.length; i++) {
    const prev = i === 0 ? GENESIS_HASH : (out[i - 1] as StoredAuditEvent).hash;
    const e = out[i] as StoredAuditEvent;
    out[i] = { ...e, prevHash: prev, macKeyId: null, hash: computeEventHash(e, prev) };
  }
  return out;
}

const anchorFor = (legacyUntil: number): StoredAnchor => ({
  legacyUntilId: String(legacyUntil),
  macKeyId: '1',
  mac: keyring.mac('audit-anchor', anchorMessage(legacyUntil)),
});

describe('canonicalize', () => {
  it('is independent of key order (jsonb does not preserve it)', () => {
    expect(canonicalize({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: null } })).toBe(
      canonicalize({ a: { c: null, d: [1, { x: 1, y: 2 }] }, b: 1 }),
    );
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
  });
});

describe('keyed audit chain', () => {
  it('verifies an untouched chain', () => {
    const chain = buildChain(5);
    expect(verifyChain(chain, { keyring })).toEqual({
      ok: true,
      checked: 5,
      headHash: chain[4]?.hash,
      legacyRows: 0,
      anchor: 'absent',
    });
  });

  it('starts from the genesis hash and uses a 64 hex MAC', () => {
    const [first] = buildChain(1);
    expect(first?.prevHash).toBe(GENESIS_HASH);
    expect(first?.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('commits to the key id in the MAC', () => {
    const core = coreFor(1);
    const k2 = new MacKeyring(
      new Map([
        ['1', randomBytes(32)],
        ['2', randomBytes(32)],
      ]),
      '1',
    );
    expect(computeEventMac(core, GENESIS_HASH, k2, '1')).not.toBe(
      computeEventMac(core, GENESIS_HASH, k2, '2'),
    );
  });

  it('detects a modified field', () => {
    const chain = buildChain(5);
    chain[2] = { ...(chain[2] as StoredAuditEvent), metadata: { n: 999 } };
    expect(verifyChain(chain, { keyring })).toMatchObject({
      ok: false,
      checked: 2,
      firstBroken: { id: '3', reason: 'hash_mismatch' },
    });
  });

  it('detects a deleted event', () => {
    const chain = buildChain(5);
    chain.splice(1, 1);
    expect(verifyChain(chain, { keyring }).firstBroken).toEqual({
      id: '3',
      reason: 'prev_hash_mismatch',
    });
  });

  it('detects a row whose MAC was recomputed with a different key', () => {
    const chain = buildChain(4);
    const forged = { ...(chain[2] as StoredAuditEvent), eventType: 'admin_user_unlocked' };
    chain[2] = { ...forged, hash: computeEventMac(forged, forged.prevHash, otherKeyring, '1') };
    expect(verifyChain(chain, { keyring }).firstBroken).toEqual({
      id: '3',
      reason: 'hash_mismatch',
    });
  });

  it('detects a full rewrite of the chain with a different key', () => {
    const forgedChain = buildChain(5, 0, otherKeyring);
    expect(verifyChain(forgedChain, { keyring }).firstBroken).toEqual({
      id: '1',
      reason: 'hash_mismatch',
    });
  });

  it('detects the old attack: rewrite a row and recompute plain SHA-256 for it and all later rows', () => {
    const chain = buildChain(6);
    chain[2] = { ...(chain[2] as StoredAuditEvent), metadata: { tampered: true } };
    const forged = rewriteAsLegacy(chain, 2);
    // Without an anchor, no legacy row is acceptable.
    expect(verifyChain(forged, { keyring }).firstBroken).toEqual({
      id: '3',
      reason: 'unkeyed_after_cutover',
    });
    // Keeping the key id but swapping the algorithm fails too.
    const keepId = forged.map((e) => ({ ...e, macKeyId: '1' }));
    expect(verifyChain(keepId, { keyring }).ok).toBe(false);
  });

  it('detects an unknown MAC key id', () => {
    const chain = buildChain(3);
    chain[1] = { ...(chain[1] as StoredAuditEvent), macKeyId: '7' };
    expect(verifyChain(chain, { keyring }).firstBroken).toEqual({
      id: '2',
      reason: 'unknown_mac_key',
    });
  });

  it('detects a downgrade (macKeyId -> null) after the cut-over, even with a valid anchor', () => {
    const chain = buildChain(6, 2);
    const forged = rewriteAsLegacy(chain, 3); // rows 4..6 relabelled legacy
    expect(verifyChain(forged, { keyring, legacyUntil: 2n }).firstBroken).toEqual({
      id: '4',
      reason: 'unkeyed_after_cutover',
    });
  });

  it('verifies a legacy prefix under a valid anchor', () => {
    const chain = buildChain(6, 3);
    const resolved = resolveAnchor(anchorFor(3), keyring);
    expect(resolved).toEqual({ state: 'valid', legacyUntil: 3n });
    expect(verifyChain(chain, { keyring, legacyUntil: resolved.legacyUntil })).toMatchObject({
      ok: true,
      checked: 6,
      legacyRows: 3,
      anchor: 'valid',
    });
  });

  it('compares ids numerically, not as text', () => {
    const chain = buildChain(12, 9);
    expect(verifyChain(chain, { keyring, legacyUntil: 9n })).toMatchObject({
      ok: true,
      legacyRows: 9,
    });
  });

  it('fails a chain with legacy rows when the anchor is missing', () => {
    const chain = buildChain(4, 2);
    const resolved = resolveAnchor(null, keyring);
    expect(resolved).toEqual({ state: 'absent', legacyUntil: 0n });
    expect(verifyChain(chain, { keyring, legacyUntil: resolved.legacyUntil })).toMatchObject({
      ok: false,
      firstBroken: { id: '1', reason: 'unkeyed_after_cutover' },
    });
  });

  it('treats a tampered anchor as invalid and fails verification', () => {
    const chain = buildChain(6, 3);
    for (const bad of [
      { ...anchorFor(3), legacyUntilId: '6' },
      { ...anchorFor(3), mac: 'f'.repeat(64) },
      { ...anchorFor(3), macKeyId: '9' },
      { ...anchorFor(3), legacyUntilId: 'abc' },
    ]) {
      const resolved = resolveAnchor(bad, keyring);
      expect(resolved).toEqual({ state: 'invalid', legacyUntil: 0n });
      expect(
        verifyChain(chain, { keyring, legacyUntil: resolved.legacyUntil, anchor: resolved.state }),
      ).toMatchObject({ ok: false, anchor: 'invalid' });
    }
  });

  it('rejects an anchor signed for another purpose', () => {
    const forged: StoredAnchor = {
      legacyUntilId: '6',
      macKeyId: '1',
      mac: keyring.mac('audit-chain', anchorMessage(6)),
    };
    expect(resolveAnchor(forged, keyring).state).toBe('invalid');
  });

  it('detects legacy row modification under a valid anchor via the first MAC row prev_hash', () => {
    const chain = buildChain(6, 3);
    // Attacker rewrites legacy row 2 and recomputes plain SHA-256 for legacy rows 2..3.
    chain[1] = { ...(chain[1] as StoredAuditEvent), metadata: { tampered: true } };
    for (let i = 1; i < 3; i++) {
      const prev = (chain[i - 1] as StoredAuditEvent).hash;
      const e = chain[i] as StoredAuditEvent;
      chain[i] = { ...e, prevHash: prev, hash: computeEventHash(e, prev) };
    }
    expect(verifyChain(chain, { keyring, legacyUntil: 3n }).firstBroken).toEqual({
      id: '4',
      reason: 'prev_hash_mismatch',
    });
  });

  it('detects a modified legacy row without recomputation', () => {
    const chain = buildChain(6, 3);
    chain[0] = { ...(chain[0] as StoredAuditEvent), metadata: { x: 1 } };
    expect(verifyChain(chain, { keyring, legacyUntil: 3n }).firstBroken).toEqual({
      id: '1',
      reason: 'hash_mismatch',
    });
  });
});
