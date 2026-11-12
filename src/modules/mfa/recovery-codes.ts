import { randomInt } from 'node:crypto';
import { sha256Hex } from '../../infra/crypto/hash';

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
 * Codes are random and high-entropy, so a fast hash is enough (no dictionary to attack) and
 * keeps verification cheap. Combined with per-user scoping and single use.
 */
export const hashRecoveryCode = (code: string): string => sha256Hex(normalizeRecoveryCode(code));
