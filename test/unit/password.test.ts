import * as bcrypt from 'bcryptjs';
import {
  AgilePasswordHasher,
  BcryptPasswordHasher,
  DEFAULT_SCRYPT_PARAMS,
  ScryptPasswordHasher,
  createPasswordHasher,
} from '../../src/modules/users/password-hasher';
import { passwordSchema } from '../../src/modules/users/users.schemas';

const PW = 'Correct-Horse-9-Battery';
const FAST = { logN: 10, r: 8, p: 1 };

describe('password policy', () => {
  it('accepts a strong password', () => {
    expect(passwordSchema.safeParse(PW).success).toBe(true);
  });

  it.each([
    ['Sh0rt!pass', 'at least 12 characters'],
    ['alllowercase-123', 'uppercase letter'],
    ['ALLUPPERCASE-123', 'lowercase letter'],
    ['No-Digits-Here!', 'digit'],
    ['NoSymbols12345', 'symbol'],
    ['MyPassword-2025!', 'must not contain the word "password"'],
  ])('rejects %p (%s)', (password, message) => {
    const result = passwordSchema.safeParse(password);
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((i) => i.message).join(' | ')).toContain(message);
  });

  it('no longer rejects passwords over 72 bytes', () => {
    expect(passwordSchema.safeParse(`Aa1!${'é'.repeat(40)}`).success).toBe(true);
  });

  it('still caps at 128 characters', () => {
    const result = passwordSchema.safeParse(`Aa1!${'x'.repeat(125)}`);
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('Password must be at most 128 characters');
  });
});

describe('ScryptPasswordHasher', () => {
  const hasher = new ScryptPasswordHasher(FAST);

  it('uses the documented default parameters', () => {
    expect(DEFAULT_SCRYPT_PARAMS).toEqual({ logN: 15, r: 8, p: 3 });
  });

  it('round-trips in PHC format', async () => {
    const hash = await hasher.hash(PW);
    expect(hash).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
    await expect(hasher.verify(PW, hash)).resolves.toBe(true);
    await expect(hasher.verify('wrong', hash)).resolves.toBe(false);
  });

  it('salts each hash', async () => {
    expect(await hasher.hash(PW)).not.toBe(await hasher.hash(PW));
  });

  it('treats NFKC-equivalent passwords as equal', async () => {
    const hash = await hasher.hash('Café-Pass-123!');
    await expect(hasher.verify('Café-Pass-123!', hash)).resolves.toBe(true);
  });

  it.each([
    '',
    'garbage',
    '$scrypt$',
    '$scrypt$ln=10,r=8,p=1$abc$def',
    '$scrypt$ln=99,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$scrypt$ln=10,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$2b$04$short',
  ])('returns false for malformed hash %p', async (bad) => {
    await expect(hasher.verify(PW, bad)).resolves.toBe(false);
  });

  it('returns false for unknown users via the cached dummy path', async () => {
    const h = new ScryptPasswordHasher(FAST);
    const spy = jest.spyOn(h, 'hash');
    await expect(h.verify(PW, null)).resolves.toBe(false);
    await expect(h.verify(PW, undefined)).resolves.toBe(false);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('flags only weaker parameters for rehash', async () => {
    const weak = await new ScryptPasswordHasher(FAST).hash(PW);
    expect(new ScryptPasswordHasher({ logN: 11, r: 8, p: 1 }).needsRehash(weak)).toBe(true);
    expect(new ScryptPasswordHasher({ logN: 10, r: 8, p: 2 }).needsRehash(weak)).toBe(true);
    expect(new ScryptPasswordHasher(FAST).needsRehash(weak)).toBe(false);
  });

  it.each([
    { logN: 9, r: 8, p: 1 },
    { logN: 21, r: 8, p: 1 },
    { logN: 10, r: 0, p: 1 },
    { logN: 10, r: 33, p: 1 },
    { logN: 10, r: 8, p: 0 },
    { logN: 10, r: 8, p: 17 },
    { logN: 10.5, r: 8, p: 1 },
  ])('rejects invalid params %p', (params) => {
    expect(() => new ScryptPasswordHasher(params)).toThrow(RangeError);
  });
});

describe('legacy bcrypt and agile hasher', () => {
  const hasher = createPasswordHasher({ scrypt: FAST });

  it('verifies a legacy bcrypt hash and asks for rehash', async () => {
    const legacy = await bcrypt.hash(PW, 4);
    await expect(hasher.verify(PW, legacy)).resolves.toBe(true);
    await expect(hasher.verify('wrong', legacy)).resolves.toBe(false);
    expect(hasher.needsRehash(legacy)).toBe(true);
  });

  it('hashes new passwords with scrypt, which need no rehash', async () => {
    const hash = await hasher.hash(PW);
    expect(hash.startsWith('$scrypt$')).toBe(true);
    expect(hasher.needsRehash(hash)).toBe(false);
  });

  it('returns false for unknown users and unknown formats', async () => {
    await expect(hasher.verify(PW, null)).resolves.toBe(false);
    await expect(hasher.verify(PW, '$argon2id$whatever')).resolves.toBe(false);
    expect(hasher.needsRehash('$argon2id$whatever')).toBe(true);
  });

  it('BcryptPasswordHasher handles malformed hashes and unknown users', async () => {
    const b = new BcryptPasswordHasher(4);
    await expect(b.verify(PW, '$2b$04$bad')).resolves.toBe(false);
    await expect(b.verify(PW, null)).resolves.toBe(false);
  });

  it('AgilePasswordHasher dispatches by prefix', async () => {
    const agile = new AgilePasswordHasher(new ScryptPasswordHasher(FAST), [
      new BcryptPasswordHasher(4),
    ]);
    const legacy = await new BcryptPasswordHasher(4).hash(PW);
    await expect(agile.verify(PW, legacy)).resolves.toBe(true);
  });
});
