import { randomBytes } from 'node:crypto';
import { MacKeyError, MacKeyring, loadMacKeyring } from '../../src/infra/crypto/mac';
import { EnvSecretsProvider } from '../../src/infra/secrets/env-provider';

const key = () => randomBytes(32);
const ring = () =>
  new MacKeyring(
    new Map([
      ['1', key()],
      ['2', key()],
    ]),
    '2',
  );

describe('MacKeyring', () => {
  it('derives different subkeys per purpose and per version', () => {
    const r = ring();
    const macs = [
      r.mac('audit-chain', 'data', '1'),
      r.mac('audit-anchor', 'data', '1'),
      r.mac('recovery-code', 'data', '1'),
      r.mac('audit-chain', 'data', '2'),
    ];
    expect(new Set(macs).size).toBe(4);
    for (const m of macs) expect(m).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic and defaults to the active version', () => {
    const r = ring();
    expect(r.mac('audit-chain', 'x')).toBe(r.mac('audit-chain', 'x', '2'));
    expect(r.mac('audit-chain', Buffer.from('x'))).toBe(r.mac('audit-chain', 'x'));
    expect(r.activeVersion).toBe('2');
    expect(r.versions).toEqual(['1', '2']);
    expect(r.has('1')).toBe(true);
    expect(r.has('3')).toBe(false);
  });

  it('verifies good MACs and rejects wrong data, purpose, version and length', () => {
    const r = ring();
    const m = r.mac('audit-chain', 'data', '1');
    expect(r.verify('audit-chain', 'data', m, '1')).toBe(true);
    expect(r.verify('audit-chain', 'other', m, '1')).toBe(false);
    expect(r.verify('audit-anchor', 'data', m, '1')).toBe(false);
    expect(r.verify('audit-chain', 'data', m, '2')).toBe(false);
    expect(r.verify('audit-chain', 'data', m.slice(0, 60), '1')).toBe(false);
    expect(r.verify('audit-chain', 'data', `${m}00`, '1')).toBe(false);
    expect(r.verify('audit-chain', 'data', '', '1')).toBe(false);
  });

  it('returns false for an unknown version on verify but throws on mac', () => {
    const r = ring();
    expect(r.verify('audit-chain', 'd', 'a'.repeat(64), '9')).toBe(false);
    expect(() => r.mac('audit-chain', 'd', '9')).toThrow(MacKeyError);
  });

  it('different root keys give different MACs', () => {
    const a = new MacKeyring(new Map([['1', key()]]), '1');
    const b = new MacKeyring(new Map([['1', key()]]), '1');
    expect(a.mac('audit-chain', 'd')).not.toBe(b.mac('audit-chain', 'd'));
  });

  it('validates its constructor arguments', () => {
    expect(() => new MacKeyring(new Map([['1', randomBytes(16)]]), '1')).toThrow(MacKeyError);
    expect(() => new MacKeyring(new Map([['a.b', key()]]), 'a.b')).toThrow(MacKeyError);
    expect(() => new MacKeyring(new Map([['', key()]]), '')).toThrow(MacKeyError);
    expect(() => new MacKeyring(new Map([['1', key()]]), '2')).toThrow(MacKeyError);
  });
});

describe('loadMacKeyring', () => {
  it('loads mac_key_<version> secrets from the provider', async () => {
    const k1 = key();
    const k2 = key();
    const secrets = new EnvSecretsProvider({
      SECRET_MAC_KEY_1: k1.toString('base64'),
      SECRET_MAC_KEY_2: k2.toString('base64'),
      SECRET_KEK_1: key().toString('base64'),
    });
    const r = await loadMacKeyring(secrets, '2');
    expect(r.versions).toEqual(['1', '2']);
    expect(r.activeVersion).toBe('2');
    expect(r.mac('audit-chain', 'd', '1')).toBe(
      new MacKeyring(new Map([['1', k1]]), '1').mac('audit-chain', 'd'),
    );
  });

  it('rejects missing, short and unloaded-active keys', async () => {
    await expect(loadMacKeyring(new EnvSecretsProvider({}), '1')).rejects.toThrow(MacKeyError);
    const short = new EnvSecretsProvider({ SECRET_MAC_KEY_1: randomBytes(8).toString('base64') });
    await expect(loadMacKeyring(short, '1')).rejects.toThrow(/32 bytes/);
    const ok = new EnvSecretsProvider({ SECRET_MAC_KEY_1: key().toString('base64') });
    await expect(loadMacKeyring(ok, '2')).rejects.toThrow(/not loaded/);
  });
});
