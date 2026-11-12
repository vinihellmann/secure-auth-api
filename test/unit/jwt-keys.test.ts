import { generateKeyPairSync } from 'node:crypto';
import { KeyStore, keyFromPem } from '../../src/infra/crypto/jwt-keys';

type Priv = ReturnType<typeof generateKeyPairSync>['privateKey'];
const pem = (priv: Priv) => priv.export({ type: 'pkcs8', format: 'pem' }) as string;

describe('keyFromPem', () => {
  it('derives RS256 from RSA and ES256 from P-256', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    expect(keyFromPem('r', pem(rsa)).alg).toBe('RS256');
    expect(keyFromPem('e', pem(ec)).alg).toBe('ES256');
  });

  it('rejects weak RSA, other curves and other key types', () => {
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    expect(() => keyFromPem('w', pem(weak))).toThrow(/2048/);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    expect(() => keyFromPem('c', pem(p384))).toThrow(/curve/);
    const ed = generateKeyPairSync('ed25519').privateKey;
    expect(() => keyFromPem('o', pem(ed))).toThrow(/unsupported/);
    const pss = generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).privateKey;
    expect(() => keyFromPem('p', pem(pss))).toThrow(/unsupported/);
    const dsa = generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }).privateKey;
    expect(() => keyFromPem('d', pem(dsa))).toThrow(/unsupported/);
  });
});

describe('KeyStore.jwks', () => {
  it('publishes per-key alg and public members only', () => {
    const r = keyFromPem('r', pem(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey));
    const e = keyFromPem('e', pem(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey));
    const { keys } = new KeyStore([r, e], 'r').jwks();
    expect(keys.map((k) => k.kid)).toEqual(['r', 'e']);
    expect(keys[0]).toMatchObject({ kty: 'RSA', use: 'sig', alg: 'RS256', e: 'AQAB' });
    expect(keys[1]).toMatchObject({ kty: 'EC', use: 'sig', alg: 'ES256', crv: 'P-256' });
    for (const key of keys) {
      for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(key).not.toHaveProperty(priv);
    }
    expect(Object.keys(keys[1] as object).sort()).toEqual([
      'alg',
      'crv',
      'kid',
      'kty',
      'use',
      'x',
      'y',
    ]);
  });
});
