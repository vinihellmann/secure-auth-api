import { BcryptPasswordHasher } from '../../src/modules/users/password-hasher';
import { passwordSchema } from '../../src/modules/users/users.schemas';

describe('password policy', () => {
  it('accepts a strong password', () => {
    expect(passwordSchema.safeParse('Correct-Horse-9-Battery').success).toBe(true);
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

  it('rejects passwords over 72 bytes instead of letting bcrypt truncate them', () => {
    const multiByte = `Aa1!${'é'.repeat(40)}`; // 44 chars, 84 bytes
    const result = passwordSchema.safeParse(multiByte);
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('Password must be at most 72 bytes');
  });
});

describe('BcryptPasswordHasher', () => {
  it('hashes with the configured cost (12 in production)', async () => {
    const hash = await new BcryptPasswordHasher(12).hash('Correct-Horse-9-Battery');
    expect(hash).toMatch(/^\$2[aby]\$12\$/);
  });

  it('verifies correct and wrong passwords', async () => {
    const hasher = new BcryptPasswordHasher(4);
    const hash = await hasher.hash('Correct-Horse-9-Battery');
    await expect(hasher.verify('Correct-Horse-9-Battery', hash)).resolves.toBe(true);
    await expect(hasher.verify('wrong', hash)).resolves.toBe(false);
  });

  it('returns false for unknown users after a dummy comparison', async () => {
    const hasher = new BcryptPasswordHasher(4);
    await expect(hasher.verify('anything', null)).resolves.toBe(false);
    await expect(hasher.verify('anything', undefined)).resolves.toBe(false);
  });
});
