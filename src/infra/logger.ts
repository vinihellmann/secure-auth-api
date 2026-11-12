import winston from 'winston';

export type Logger = winston.Logger;

export interface LoggerOptions {
  level: string;
  silent?: boolean;
}

export const REDACTED = '[REDACTED]';
const MAX_DEPTH = 8;

/**
 * Keys redacted by exact (case-insensitive) match. Deliberately an explicit list rather than a
 * substring match: `token` as a substring would also hit `tokenType`, and `statusCode` /
 * `errorCode` are harmless diagnostics we need to keep. A bare `code` is handled by value, see
 * isSensitiveEntry.
 */
const SENSITIVE_KEYS = new Set([
  'password',
  'passwd',
  'secret',
  'token',
  'authorization',
  'cookie',
  'setcookie',
  'recoverycode',
  'recoverycodes',
  'otp',
]);

/** Suffixes that mark compound names: accessToken, refreshToken, mfaToken, newPassword, clientSecret. */
const SENSITIVE_SUFFIXES = ['token', 'password', 'passwd', 'secret'];

export function isSensitiveKey(key: string): boolean {
  const k = key.toLowerCase();
  return SENSITIVE_KEYS.has(k) || SENSITIVE_SUFFIXES.some((s) => k.endsWith(s));
}

// TOTP codes (6-8 digits) and recovery codes (XXXXX-XXXXX from the recovery-code alphabet).
const OTP_LIKE = /^(\d{6,8}|[A-HJKMNP-Z2-9]{5}-?[A-HJKMNP-Z2-9]{5})$/i;

/**
 * `code` is ambiguous: in a request body it is a one-time password, on an error it is a
 * diagnostic we need (`ECONNREFUSED`, Postgres SQLSTATE `23505`, an HTTP status). So it is
 * redacted only when its value looks like an OTP or recovery code.
 */
export function isSensitiveEntry(key: string, value: unknown): boolean {
  if (isSensitiveKey(key)) return true;
  return key.toLowerCase() === 'code' && typeof value === 'string' && OTP_LIKE.test(value.trim());
}

function isPlainObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function redactValue(value: unknown, depth: number, ancestors: object[]): unknown {
  if (typeof value !== 'object' || value === null) return value;
  if (ancestors.includes(value)) return '[Circular]';
  if (depth >= MAX_DEPTH) return '[Truncated]';

  const path = [...ancestors, value];
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1, path));

  if (value instanceof Error) {
    // name/message/stack are non-enumerable on Errors, so copy them explicitly.
    const out: Record<string, unknown> = {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
    copyEntries(value as unknown as Record<string, unknown>, out, depth, path);
    return out;
  }

  // Dates, Buffers, class instances etc. are left to the serializer untouched.
  if (!isPlainObject(value)) return value;

  const out: Record<string, unknown> = {};
  copyEntries(value as Record<string, unknown>, out, depth, path);
  return out;
}

function copyEntries(
  from: Record<string, unknown>,
  to: Record<string, unknown>,
  depth: number,
  path: object[],
): void {
  for (const key of Object.keys(from)) {
    to[key] = isSensitiveEntry(key, from[key]) ? REDACTED : redactValue(from[key], depth + 1, path);
  }
}

/**
 * Deep-redacts sensitive keys (see SENSITIVE_KEYS / SENSITIVE_SUFFIXES) and returns a copy;
 * the input is never mutated. Cycles become '[Circular]', nesting beyond 8 levels '[Truncated]'.
 */
export function redact<T>(value: T): T {
  return redactValue(value, 0, []) as T;
}

/**
 * Defense in depth: call sites are not supposed to log secrets, but a stray `logger.info({ body })`
 * must not leak them. Winston's info object carries Symbol keys (LEVEL, MESSAGE, SPLAT) that the
 * transports rely on, so the top level is copied with symbols preserved, not rebuilt.
 */
export const redactFormat = winston.format((info) => {
  const out = { ...info } as winston.Logform.TransformableInfo;
  for (const key of Object.keys(info)) {
    out[key] = isSensitiveEntry(key, info[key]) ? REDACTED : redactValue(info[key], 1, [info]);
  }
  return out;
});

/**
 * Structured JSON logger. Never log request bodies, passwords, tokens or secrets; the
 * redaction format is a safety net, not a licence.
 */
export function createLogger(options: LoggerOptions): Logger {
  return winston.createLogger({
    level: options.level,
    silent: options.silent ?? false,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      redactFormat(),
      winston.format.json(),
    ),
    transports: [new winston.transports.Console()],
  });
}
