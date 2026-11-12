import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import * as bcrypt from 'bcryptjs';

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /**
   * Verifies a password. When `hash` is null/undefined (unknown user) a comparison against a
   * dummy hash of the primary algorithm is still performed, so response time does not reveal
   * whether an account exists. Malformed stored hashes yield false, never an exception.
   */
  verify(password: string, hash: string | null | undefined): Promise<boolean>;
  /** True when the stored hash uses a non-primary algorithm or weaker parameters than configured. */
  needsRehash(hash: string): boolean;
}

/** A hasher that handles one algorithm and can recognise its own hashes. */
export interface AlgorithmHasher extends PasswordHasher {
  readonly id: string;
  owns(hash: string): boolean;
}

export interface ScryptParams {
  logN: number;
  r: number;
  p: number;
  /** Derived key length in bytes (default 32). */
  keyLength?: number;
  /** Salt length in bytes (default 16). */
  saltLength?: number;
}

/** OWASP-listed equivalent of N=2^17,r=8,p=1, using 32 MiB per hash instead of 128 MiB. */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = { logN: 15, r: 8, p: 3 };

const DEFAULT_KEY_LENGTH = 32;
const DEFAULT_SALT_LENGTH = 16;
const DUMMY_PASSWORD = 'dummy-password-for-constant-time-compare';

function scryptAsync(
  password: Buffer,
  salt: Buffer,
  keyLength: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

function assertInt(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`scrypt ${name} must be an integer between ${min} and ${max}`);
  }
}

interface ParsedScrypt {
  logN: number;
  r: number;
  p: number;
  salt: Buffer;
  key: Buffer;
}

const SCRYPT_RE =
  /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

function decodeB64(value: string): Buffer | null {
  const buf = Buffer.from(value, 'base64');
  // Strict: reject non-canonical encodings (re-encoding must round-trip exactly).
  return buf.toString('base64').replace(/=+$/, '') === value ? buf : null;
}

function parseScrypt(hash: string): ParsedScrypt | null {
  const m = SCRYPT_RE.exec(hash);
  if (!m) return null;
  const logN = Number(m[1]);
  const r = Number(m[2]);
  const p = Number(m[3]);
  if (logN < 10 || logN > 20 || r < 1 || r > 32 || p < 1 || p > 16) return null;
  const salt = decodeB64(m[4] as string);
  const key = decodeB64(m[5] as string);
  if (!salt || !key || salt.length < 8 || key.length < 16 || key.length > 64) return null;
  return { logN, r, p, salt, key };
}

/**
 * Primary algorithm: scrypt (memory-hard, runs on the libuv threadpool, built into Node).
 * Stored as PHC string: `$scrypt$ln=<logN>,r=<r>,p=<p>$<salt b64>$<hash b64>` (no padding).
 */
export class ScryptPasswordHasher implements AlgorithmHasher {
  readonly id = 'scrypt';
  private readonly keyLength: number;
  private readonly saltLength: number;
  private dummyHash: Promise<string> | undefined;

  constructor(private readonly params: ScryptParams = DEFAULT_SCRYPT_PARAMS) {
    assertInt('logN', params.logN, 10, 20);
    assertInt('r', params.r, 1, 32);
    assertInt('p', params.p, 1, 16);
    this.keyLength = params.keyLength ?? DEFAULT_KEY_LENGTH;
    this.saltLength = params.saltLength ?? DEFAULT_SALT_LENGTH;
    assertInt('keyLength', this.keyLength, 16, 64);
    assertInt('saltLength', this.saltLength, 8, 64);
  }

  owns(hash: string): boolean {
    return hash.startsWith('$scrypt$');
  }

  private derive(
    password: string,
    salt: Buffer,
    logN: number,
    r: number,
    p: number,
    len: number,
  ): Promise<Buffer> {
    const N = 2 ** logN;
    // Node's default maxmem (32 MiB) would reject our parameters; allow 128*N*r*p plus margin.
    const maxmem = 128 * N * r * p + 1024 * 1024;
    // NFKC: visually identical strings (composed vs decomposed accents, full-width forms) must
    // hash identically, otherwise a password typed on another OS/keyboard would fail.
    return scryptAsync(Buffer.from(password.normalize('NFKC'), 'utf8'), salt, len, {
      N,
      r,
      p,
      maxmem,
    });
  }

  async hash(password: string): Promise<string> {
    const { logN, r, p } = this.params;
    const salt = randomBytes(this.saltLength);
    const key = await this.derive(password, salt, logN, r, p, this.keyLength);
    const enc = (b: Buffer): string => b.toString('base64').replace(/=+$/, '');
    return `$scrypt$ln=${logN},r=${r},p=${p}$${enc(salt)}$${enc(key)}`;
  }

  async verify(password: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash) {
      await this.verify(password, await this.getDummyHash());
      return false;
    }
    const parsed = parseScrypt(hash);
    if (!parsed) return false;
    try {
      const key = await this.derive(
        password,
        parsed.salt,
        parsed.logN,
        parsed.r,
        parsed.p,
        parsed.key.length,
      );
      return timingSafeEqual(key, parsed.key);
    } catch {
      return false;
    }
  }

  needsRehash(hash: string): boolean {
    const parsed = parseScrypt(hash);
    if (!parsed) return true;
    const { logN, r, p } = this.params;
    return (
      parsed.logN < logN ||
      parsed.r < r ||
      parsed.p < p ||
      parsed.key.length < this.keyLength ||
      parsed.salt.length < this.saltLength
    );
  }

  private getDummyHash(): Promise<string> {
    if (!this.dummyHash) {
      this.dummyHash = this.hash(DUMMY_PASSWORD);
      // Avoid an unhandled rejection if hashing fails before first use.
      this.dummyHash.catch(() => undefined);
    }
    return this.dummyHash;
  }
}

/** Legacy: verifies existing bcrypt hashes. Passwords are NOT normalized (as when hashed). */
export class BcryptPasswordHasher implements AlgorithmHasher {
  readonly id = 'bcrypt';
  private dummyHash: Promise<string> | undefined;

  constructor(private readonly cost: number) {}

  owns(hash: string): boolean {
    return /^\$2[aby]\$/.test(hash);
  }

  hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.cost);
  }

  async verify(password: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash) {
      this.dummyHash ??= bcrypt.hash(DUMMY_PASSWORD, this.cost);
      this.dummyHash.catch(() => undefined);
      await bcrypt.compare(password, await this.dummyHash);
      return false;
    }
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  needsRehash(): boolean {
    return true;
  }
}

/** Dispatches on the hash prefix (Strategy); new hashes use the primary algorithm. */
export class AgilePasswordHasher implements PasswordHasher {
  constructor(
    private readonly primary: AlgorithmHasher,
    private readonly legacy: AlgorithmHasher[],
  ) {}

  hash(password: string): Promise<string> {
    return this.primary.hash(password);
  }

  verify(password: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash) return this.primary.verify(password, null);
    const hasher = [this.primary, ...this.legacy].find((h) => h.owns(hash));
    // Unknown format: burn a primary comparison so timing stays uniform, then fail.
    return hasher ? hasher.verify(password, hash) : this.primary.verify(password, null);
  }

  needsRehash(hash: string): boolean {
    return this.primary.owns(hash) ? this.primary.needsRehash(hash) : true;
  }
}

export function createPasswordHasher(opts: { scrypt: ScryptParams }): PasswordHasher {
  return new AgilePasswordHasher(new ScryptPasswordHasher(opts.scrypt), [
    new BcryptPasswordHasher(12),
  ]);
}
