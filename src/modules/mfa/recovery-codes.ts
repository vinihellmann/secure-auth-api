import { randomInt } from 'node:crypto';
import { sha256Hex } from '../../infra/crypto/hash';
import type { MacKeyring } from '../../infra/crypto/mac';

// No 0/O/1/I/L: codes are read from paper and typed by hand.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const RECOVERY_CODE_COUNT = 10;

/** XXXXX-XXXXX, 10 symbols from a 31-char alphabet (~49.5 bits). */
export function generateRecoveryCode(): string {
  let raw = '';
  for (let i = 0; i < 10; i++) raw += ALPHABET[randomInt(ALPHABET.length)];
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

export const normalizeRecoveryCode = (code: string): string =>
  code.toUpperCase().replace(/[^A-Z0-9]/g, '');

/**
 * Recovery codes are stored as `m1.<macKeyVersion>.<hex>` where hex is HMAC-SHA256 (purpose
 * "recovery-code") over `<userId>|<normalized code>` with a server-side key. A database leak
 * alone therefore allows no offline guessing, and a hash cannot be moved to another user.
 */
export class RecoveryCodeHasher {
  constructor(private readonly keyring: MacKeyring) {}

  hash(userId: string, code: string): string {
    return this.hashWith(userId, code, this.keyring.activeVersion);
  }

  /**
   * Every stored form a code may have: the hash under each loaded key version, plus the legacy
   * unsalted SHA-256 so codes issued before keyed hashing keep working until consumed.
   */
  candidates(userId: string, code: string): string[] {
    return [
      ...this.keyring.versions.map((v) => this.hashWith(userId, code, v)),
      sha256Hex(normalizeRecoveryCode(code)),
    ];
  }

  private hashWith(userId: string, code: string, version: string): string {
    const mac = this.keyring.mac(
      'recovery-code',
      `${userId}|${normalizeRecoveryCode(code)}`,
      version,
    );
    return `m1.${version}.${mac}`;
  }
}
