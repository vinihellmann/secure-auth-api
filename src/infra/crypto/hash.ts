import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const sha256Hex = (input: string | Buffer): string =>
  createHash('sha256').update(input).digest('hex');

/** Opaque URL-safe random token (default 32 bytes = 256 bits of entropy). */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
