import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import type { SecretsProvider } from '../secrets/provider';

/**
 * Keyed integrity (HMAC-SHA256) with versioned keys.
 *
 * Root keys are 32 random bytes stored as `mac_key_<version>` secrets (base64), the same
 * convention as `kek_<version>`. A root key is never used directly: one subkey per
 * (version, purpose) is derived with HKDF-SHA256, so a MAC computed for one purpose can
 * never be replayed as a MAC for another.
 */
export type MacPurpose = 'audit-chain' | 'audit-anchor' | 'recovery-code';

const KEY_LENGTH = 32;
const VERSION_PATTERN = /^[A-Za-z0-9_-]+$/;
const HKDF_SALT = Buffer.from('secure-auth-api/mac/v1');
const MAC_SECRET_PREFIX = 'mac_key_';

export class MacKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MacKeyError';
  }
}

export class MacKeyring {
  private readonly keys = new Map<string, Buffer>();
  private readonly subkeys = new Map<string, Buffer>();

  /**
   * @param keys          map of version -> 32 byte root key (every version that may appear in storage)
   * @param activeVersion version used for new MACs
   */
  constructor(
    keys: ReadonlyMap<string, Buffer>,
    private readonly active: string,
  ) {
    for (const [version, key] of keys) {
      if (!VERSION_PATTERN.test(version))
        throw new MacKeyError(`Invalid MAC key version "${version}"`);
      if (key.length !== KEY_LENGTH) throw new MacKeyError(`MAC key "${version}" must be 32 bytes`);
      this.keys.set(version, Buffer.from(key));
    }
    if (!this.keys.has(active)) {
      throw new MacKeyError(`Active MAC key version "${active}" is not loaded`);
    }
  }

  get activeVersion(): string {
    return this.active;
  }

  get versions(): string[] {
    return [...this.keys.keys()].sort();
  }

  has(version: string): boolean {
    return this.keys.has(version);
  }

  /** HMAC-SHA256 (hex) of `data` under the purpose-specific subkey of `version` (default: active). */
  mac(purpose: MacPurpose, data: string | Buffer, version: string = this.active): string {
    return createHmac('sha256', this.subkey(purpose, version)).update(data).digest('hex');
  }

  /** Timing-safe check against an expected hex MAC. Unknown version yields false, never a throw. */
  verify(
    purpose: MacPurpose,
    data: string | Buffer,
    expectedHex: string,
    version: string,
  ): boolean {
    if (!this.keys.has(version)) return false;
    const actual = Buffer.from(this.mac(purpose, data, version), 'utf8');
    const expected = Buffer.from(expectedHex, 'utf8');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  private subkey(purpose: MacPurpose, version: string): Buffer {
    const cacheKey = `${version}\u0000${purpose}`;
    const cached = this.subkeys.get(cacheKey);
    if (cached) return cached;
    const root = this.keys.get(version);
    if (!root) throw new MacKeyError(`Unknown MAC key version "${version}"`);
    const derived = Buffer.from(
      hkdfSync('sha256', root, HKDF_SALT, Buffer.from(purpose), KEY_LENGTH),
    );
    this.subkeys.set(cacheKey, derived);
    return derived;
  }
}

/** Loads every `mac_key_<version>` secret (base64 encoded 32 bytes). */
export async function loadMacKeyring(
  secrets: SecretsProvider,
  activeVersion: string,
): Promise<MacKeyring> {
  const names = await secrets.list(MAC_SECRET_PREFIX);
  const keys = new Map<string, Buffer>();
  for (const name of names) {
    const version = name.slice(MAC_SECRET_PREFIX.length);
    const key = Buffer.from(await secrets.get(name), 'base64');
    if (key.length !== KEY_LENGTH) {
      throw new MacKeyError(`Secret "${name}" must be base64 of exactly 32 bytes`);
    }
    keys.set(version, key);
  }
  if (keys.size === 0)
    throw new MacKeyError('No MAC key secrets found (expected mac_key_<version>)');
  return new MacKeyring(keys, activeVersion);
}
