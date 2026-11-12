import {
  GENESIS_HASH,
  canonicalize,
  computeEventHash,
  verifyChain,
  type AuditEventCore,
  type StoredAuditEvent,
} from '../../src/modules/audit/chain';

function buildChain(n: number): StoredAuditEvent[] {
  const events: StoredAuditEvent[] = [];
  let prevHash = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const core: AuditEventCore = {
      occurredAt: new Date(Date.UTC(2025, 0, 1, 0, 0, i)),
      actorUserId: null,
      eventType: i % 2 ? 'login_succeeded' : 'logout',
      ip: '203.0.113.7',
      userAgent: 'jest',
      metadata: { n: i, nested: { b: 2, a: 1 } },
    };
    const hash = computeEventHash(core, prevHash);
    events.push({ ...core, id: String(i), prevHash, hash });
    prevHash = hash;
  }
  return events;
}

describe('canonicalize', () => {
  it('is independent of key order (jsonb does not preserve it)', () => {
    expect(canonicalize({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: null } })).toBe(
      canonicalize({ a: { c: null, d: [1, { x: 1, y: 2 }] }, b: 1 }),
    );
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
  });
});

describe('audit hash chain', () => {
  it('verifies an untouched chain', () => {
    const chain = buildChain(5);
    expect(verifyChain(chain)).toEqual({ ok: true, checked: 5, headHash: chain[4]?.hash });
  });

  it('starts from the genesis hash', () => {
    expect(buildChain(1)[0]?.prevHash).toBe(GENESIS_HASH);
  });

  it('detects a modified field', () => {
    const chain = buildChain(5);
    chain[2] = { ...(chain[2] as StoredAuditEvent), metadata: { n: 999 } };
    expect(verifyChain(chain)).toMatchObject({
      ok: false,
      checked: 2,
      firstBroken: { id: '3', reason: 'hash_mismatch' },
    });
  });

  it('detects a deleted event', () => {
    const chain = buildChain(5);
    chain.splice(1, 1);
    expect(verifyChain(chain).firstBroken).toEqual({ id: '3', reason: 'prev_hash_mismatch' });
  });

  it('detects a recomputed hash that does not link to its predecessor', () => {
    const chain = buildChain(4);
    const forged = { ...(chain[2] as StoredAuditEvent), eventType: 'admin_user_unlocked' };
    forged.hash = computeEventHash(forged, forged.prevHash); // attacker fixes this row's hash
    chain[2] = forged;
    expect(verifyChain(chain).firstBroken).toEqual({ id: '4', reason: 'prev_hash_mismatch' });
  });
});
