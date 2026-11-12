import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretsProvider } from '../secrets/provider';

/**
 * Field-level envelope encryption (AES-256-GCM, two layers).
 *
 *   plaintext --(DEK, AES-256-GCM)--> ciphertext
 *   DEK       --(KEK, AES-256-GCM)--> wrapped DEK
 *
 * A fresh random 32-byte DEK is generated for every value. The DEK is wrapped by a
 * key-encryption key (KEK) identified by a version string, so KEKs can be rotated
 * by re-wrapping DEKs only; the (potentially large) ciphertext is never re-encrypted.
 *
 * Serialized format (single ASCII string, safe for text columns):
 *
 *   v1.<kekVersion>.<wrappedDek>.<iv>.<tag>.<ciphertext>
 *
 *   v1            format version, lets us change the layout later
 *   kekVersion    [A-Za-z0-9_-]+, selects the KEK used to wrap the DEK
 *   wrappedDek    base64url( wrapIv[12] | wrapTag[16] | encryptedDek[32] ) = 60 bytes
 *   iv            base64url, 12 byte GCM nonce for the data encryption
 *   tag           base64url, 16 byte GCM tag for the data encryption
 *   ciphertext    base64url of the encrypted UTF-8 plaintext
 *
 * base64url never contains '.', so the string splits unambiguously into 6 parts.
 *
 * Authenticated data (AAD):
 *   data:  "v1|ctx|<context>"      binds the ciphertext to a logical owner (e.g. "mfa:<userId>")
 *                                  so a value copied to another row fails to decrypt.
 *                                  It deliberately excludes the KEK version, so re-wrapping
 *                                  does not invalidate the data tag.
 *   wrap:  "v1|kek|<kekVersion>"   binds the wrapped DEK to the KEK version named in the header.
 *
 * Tampering with any part (including the version header) makes GCM authentication fail.
 */

const FORMAT_VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm' as const;
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const WRAPPED_DEK_LENGTH = IV_LENGTH + TAG_LENGTH + KEY_LENGTH;
const KEK_VERSION_PATTERN = /^[A-Za-z0-9_-]+$/;

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

export interface ParsedEnvelope {
  version: string;
  kekVersion: string;
  wrappedDek: Buffer;
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

const b64 = (buf: Buffer): string => buf.toString('base64url');

export function serializeEnvelope(p: ParsedEnvelope): string {
  return [p.version, p.kekVersion, b64(p.wrappedDek), b64(p.iv), b64(p.tag), b64(p.ciphertext)].join(
    '.',
  );
}

export function parseEnvelope(payload: string): ParsedEnvelope {
  const parts = payload.split('.');
  if (parts.length !== 6) throw new EnvelopeError('Malformed envelope');
  const [version, kekVersion, wrapped, iv, tag, ciphertext] = parts as [
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  if (version !== FORMAT_VERSION) throw new EnvelopeError('Unsupported envelope version');
  if (!KEK_VERSION_PATTERN.test(kekVersion)) throw new EnvelopeError('Malformed KEK version');
  const parsed: ParsedEnvelope = {
    version,
    kekVersion,
    wrappedDek: Buffer.from(wrapped, 'base64url'),
    iv: Buffer.from(iv, 'base64url'),
    tag: Buffer.from(tag, 'base64url'),
    ciphertext: Buffer.from(ciphertext, 'base64url'),
  };
  if (
    parsed.wrappedDek.length !== WRAPPED_DEK_LENGTH ||
    parsed.iv.length !== IV_LENGTH ||
    parsed.tag.length !== TAG_LENGTH
  ) {
    throw new EnvelopeError('Malformed envelope');
  }
  return parsed;
}

const wrapAad = (kekVersion: string) => Buffer.from(`${FORMAT_VERSION}|kek|${kekVersion}`, 'utf8');
const dataAad = (context: string) => Buffer.from(`${FORMAT_VERSION}|ctx|${context}`, 'utf8');

function wrapDek(kek: Buffer, kekVersion: string, dek: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, kek, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(wrapAad(kekVersion));
  const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

function unwrapDek(kek: Buffer, kekVersion: string, wrapped: Buffer): Buffer {
  const iv = wrapped.subarray(0, IV_LENGTH);
  const tag = wrapped.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = wrapped.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, kek, iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(wrapAad(kekVersion));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

export class EnvelopeCrypto {
  /**
   * @param keks          map of KEK version -> 32 byte key (all versions that may still appear in storage)
   * @param activeVersion version used for new encryptions and re-wrapping
   */
  constructor(
    private readonly keks: ReadonlyMap<string, Buffer>,
    private readonly activeVersion: string,
  ) {
    for (const [version, key] of keks) {
      if (!KEK_VERSION_PATTERN.test(version)) throw new EnvelopeError(`Invalid KEK version "${version}"`);
      if (key.length !== KEY_LENGTH) throw new EnvelopeError(`KEK "${version}" must be 32 bytes`);
    }
    if (!keks.has(activeVersion)) {
      throw new EnvelopeError(`Active KEK version "${activeVersion}" is not loaded`);
    }
  }

  get activeKekVersion(): string {
    return this.activeVersion;
  }

  encrypt(plaintext: string, context = ''): string {
    const kek = this.keks.get(this.activeVersion) as Buffer;
    const dek = randomBytes(KEY_LENGTH);
    try {
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv(ALGORITHM, dek, iv, { authTagLength: TAG_LENGTH });
      cipher.setAAD(dataAad(context));
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      return serializeEnvelope({
        version: FORMAT_VERSION,
        kekVersion: this.activeVersion,
        wrappedDek: wrapDek(kek, this.activeVersion, dek),
        iv,
        tag: cipher.getAuthTag(),
        ciphertext,
      });
    } finally {
      dek.fill(0);
    }
  }

  decrypt(payload: string, context = ''): string {
    const parsed = parseEnvelope(payload);
    const dek = this.unwrap(parsed);
    try {
      const decipher = createDecipheriv(ALGORITHM, dek, parsed.iv, { authTagLength: TAG_LENGTH });
      decipher.setAAD(dataAad(context));
      decipher.setAuthTag(parsed.tag);
      return Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]).toString('utf8');
    } catch {
      throw new EnvelopeError('Decryption failed');
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Re-wraps the DEK with the active KEK without touching iv/tag/ciphertext.
   * No-op (returns the input) when already wrapped with the active version.
   */
  rewrap(payload: string): string {
    const parsed = parseEnvelope(payload);
    if (parsed.kekVersion === this.activeVersion) return payload;
    const dek = this.unwrap(parsed);
    try {
      const kek = this.keks.get(this.activeVersion) as Buffer;
      return serializeEnvelope({
        ...parsed,
        kekVersion: this.activeVersion,
        wrappedDek: wrapDek(kek, this.activeVersion, dek),
      });
    } finally {
      dek.fill(0);
    }
  }

  isCurrent(payload: string): boolean {
    return parseEnvelope(payload).kekVersion === this.activeVersion;
  }

  private unwrap(parsed: ParsedEnvelope): Buffer {
    const kek = this.keks.get(parsed.kekVersion);
    if (!kek) throw new EnvelopeError(`Unknown KEK version "${parsed.kekVersion}"`);
    try {
      return unwrapDek(kek, parsed.kekVersion, parsed.wrappedDek);
    } catch {
      throw new EnvelopeError('Decryption failed');
    }
  }
}

const KEK_SECRET_PREFIX = 'kek_';

/**
 * Loads every `kek_<version>` secret (base64 encoded 32 bytes).
 */
export async function loadKeks(secrets: SecretsProvider): Promise<Map<string, Buffer>> {
  const names = await secrets.list(KEK_SECRET_PREFIX);
  const keks = new Map<string, Buffer>();
  for (const name of names) {
    const version = name.slice(KEK_SECRET_PREFIX.length);
    const key = Buffer.from(await secrets.get(name), 'base64');
    if (key.length !== KEY_LENGTH) {
      throw new EnvelopeError(`Secret "${name}" must be base64 of exactly 32 bytes`);
    }
    keks.set(version, key);
  }
  if (keks.size === 0) throw new EnvelopeError('No KEK secrets found (expected kek_<version>)');
  return keks;
}

export async function createEnvelopeCrypto(
  secrets: SecretsProvider,
  activeVersion: string,
): Promise<EnvelopeCrypto> {
  return new EnvelopeCrypto(await loadKeks(secrets), activeVersion);
}
