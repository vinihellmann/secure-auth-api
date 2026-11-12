import { randomBytes } from 'node:crypto';
import { EnvelopeCrypto, EnvelopeError, parseEnvelope } from '../../src/infra/crypto/envelope';

const kek1 = randomBytes(32);
const kek2 = randomBytes(32);
const v1Only = new EnvelopeCrypto(new Map([['1', kek1]]), '1');
const both = new EnvelopeCrypto(
  new Map([
    ['1', kek1],
    ['2', kek2],
  ]),
  '2',
);

/** Flips one bit inside the base64url segment `index` of the envelope. */
function tamper(payload: string, index: number): string {
  const parts = payload.split('.');
  const bytes = Buffer.from(parts[index] as string, 'base64url');
  bytes[0] = (bytes[0] as number) ^ 0x01;
  parts[index] = bytes.toString('base64url');
  return parts.join('.');
}

describe('EnvelopeCrypto', () => {
  it('round-trips and documents its format', () => {
    const payload = v1Only.encrypt('JBSWY3DPEHPK3PXP', 'mfa:user-1');
    expect(payload).toMatch(/^v1\.1\.[\w-]+\.[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(payload).not.toContain('JBSWY3DPEHPK3PXP');
    expect(v1Only.decrypt(payload, 'mfa:user-1')).toBe('JBSWY3DPEHPK3PXP');

    const parsed = parseEnvelope(payload);
    expect(parsed.wrappedDek).toHaveLength(60);
    expect(parsed.iv).toHaveLength(12);
    expect(parsed.tag).toHaveLength(16);
  });

  it('uses a fresh DEK and IV per value', () => {
    const a = parseEnvelope(v1Only.encrypt('same', 'ctx'));
    const b = parseEnvelope(v1Only.encrypt('same', 'ctx'));
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it.each([
    [2, 'wrapped DEK'],
    [3, 'IV'],
    [4, 'auth tag'],
    [5, 'ciphertext'],
  ])('detects tampering with the %s segment (%s)', (index) => {
    const payload = v1Only.encrypt('secret value', 'ctx');
    expect(() => v1Only.decrypt(tamper(payload, index), 'ctx')).toThrow(EnvelopeError);
  });

  it('binds the ciphertext to its context (a value copied to another row fails)', () => {
    const payload = v1Only.encrypt('secret value', 'mfa:alice');
    expect(() => v1Only.decrypt(payload, 'mfa:mallory')).toThrow('Decryption failed');
  });

  it('binds the wrapped DEK to the KEK version in the header', () => {
    const payload = both.encrypt('secret value', 'ctx'); // wrapped with KEK 2
    const relabeled = payload.replace(/^v1\.2\./, 'v1.1.');
    expect(() => both.decrypt(relabeled, 'ctx')).toThrow(EnvelopeError);
  });

  it('rejects malformed envelopes and unknown versions', () => {
    expect(() => v1Only.decrypt('not-an-envelope', 'ctx')).toThrow('Malformed envelope');
    const payload = v1Only.encrypt('x', 'ctx');
    expect(() => v1Only.decrypt(payload.replace(/^v1/, 'v9'), 'ctx')).toThrow(
      'Unsupported envelope version',
    );
    expect(() => v1Only.decrypt(both.encrypt('x', 'ctx'), 'ctx')).toThrow(
      'Unknown KEK version "2"',
    );
  });

  it('re-wraps to the active KEK without touching the data encryption', () => {
    const old = v1Only.encrypt('rotate me', 'ctx');
    expect(both.isCurrent(old)).toBe(false);

    const rewrapped = both.rewrap(old);
    expect(rewrapped.startsWith('v1.2.')).toBe(true);
    expect(both.isCurrent(rewrapped)).toBe(true);
    expect(both.decrypt(rewrapped, 'ctx')).toBe('rotate me');

    const [a, b] = [parseEnvelope(old), parseEnvelope(rewrapped)];
    expect(b.iv.equals(a.iv) && b.tag.equals(a.tag) && b.ciphertext.equals(a.ciphertext)).toBe(
      true,
    );
    expect(both.rewrap(rewrapped)).toBe(rewrapped); // already current: no-op
  });

  it('refuses invalid key material', () => {
    expect(() => new EnvelopeCrypto(new Map([['1', randomBytes(16)]]), '1')).toThrow('32 bytes');
    expect(() => new EnvelopeCrypto(new Map([['1', kek1]]), '2')).toThrow('not loaded');
  });
});
