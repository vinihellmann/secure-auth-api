import * as bcrypt from 'bcryptjs';

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /**
   * Verifies a password. When `hash` is null/undefined (unknown user) a comparison against a
   * dummy hash of the same cost is still performed, so response time does not reveal whether
   * an account exists.
   */
  verify(password: string, hash: string | null | undefined): Promise<boolean>;
}

export class BcryptPasswordHasher implements PasswordHasher {
  private readonly dummyHash: Promise<string>;

  constructor(private readonly cost: number) {
    this.dummyHash = bcrypt.hash('dummy-password-for-constant-time-compare', cost);
    // Avoid an unhandled rejection if hashing fails before first use.
    this.dummyHash.catch(() => undefined);
  }

  hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.cost);
  }

  async verify(password: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash) {
      await bcrypt.compare(password, await this.dummyHash);
      return false;
    }
    return bcrypt.compare(password, hash);
  }
}
