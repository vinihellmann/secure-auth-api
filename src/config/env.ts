import { z } from 'zod';

const bool = (fallback: 'true' | 'false') =>
  z
    .enum(['true', 'false'])
    .default(fallback)
    .transform((v) => v === 'true');

/**
 * Express "trust proxy" accepts boolean | number | string (CSV of CIDRs / keywords).
 */
function parseTrustProxy(raw: string): boolean | number | string {
  const v = raw.trim();
  if (v === 'true') return true;
  if (v === 'false' || v === '') return false;
  if (/^\d+$/.test(v)) return Number(v);
  return v;
}

const rawSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),

  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),

  CORS_ORIGINS: z.string().default(''),
  TRUST_PROXY: z.string().default('false'),
  REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120_000).default(15_000),

  SECRETS_PROVIDER: z.enum(['file', 'env']).default('file'),
  SECRETS_DIR: z.string().min(1).default('/run/secrets'),

  JWT_ISSUER: z.string().min(1).default('secure-auth-api'),
  JWT_AUDIENCE: z.string().min(1).default('secure-auth-api-clients'),
  JWT_ACTIVE_KID: z
    .string()
    .regex(/^[a-z0-9_-]+$/)
    .default('k1'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  MFA_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(900).default(300),
  // Set to false for one access-token TTL when upgrading, so tokens issued before the JOSE
  // `typ` header was introduced keep working; then back to true.
  JWT_REQUIRE_TYP: bool('true'),

  KEK_ACTIVE_VERSION: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .default('1'),

  MAC_ACTIVE_VERSION: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .default('1'),

  // scrypt work factor: N = 2^SCRYPT_LOG_N, memory per hash = 128 * N * r bytes (32 MiB by
  // default). Defaults are an OWASP-listed equivalent of N=2^17,r=8,p=1 using a quarter of the
  // memory, which keeps concurrent logins from exhausting RAM.
  SCRYPT_LOG_N: z.coerce.number().int().min(10).max(20).default(15),
  SCRYPT_R: z.coerce.number().int().min(1).max(32).default(8),
  SCRYPT_P: z.coerce.number().int().min(1).max(16).default(3),
  TOTP_ISSUER: z.string().min(1).default('SecureAuthAPI'),
  RATE_LIMIT_ENABLED: bool('true'),

  ADMIN_EMAIL: z.string().email().optional(),
  ADMIN_PASSWORD: z.string().min(12).optional(),
});

export const envSchema = rawSchema
  .superRefine((env, ctx) => {
    if (Boolean(env.ADMIN_EMAIL) !== Boolean(env.ADMIN_PASSWORD)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_EMAIL'],
        message: 'ADMIN_EMAIL and ADMIN_PASSWORD must be set together',
      });
    }
    // Guard rails: settings that are fine for tests but unsafe in production fail the boot
    // instead of silently weakening the service.
    if (env.NODE_ENV === 'production') {
      const unsafe = (path: string, message: string) =>
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message });
      if (env.SECRETS_PROVIDER === 'env') {
        unsafe('SECRETS_PROVIDER', 'env secrets leak through process listings; use file');
      }
      if (env.RATE_LIMIT_ENABLED === false) {
        unsafe('RATE_LIMIT_ENABLED', 'rate limiting must stay enabled in production');
      }
      if (env.SCRYPT_LOG_N < 14) {
        unsafe('SCRYPT_LOG_N', 'must be at least 14 in production');
      }
    }
  })
  .transform((env) => ({
    env: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    port: env.PORT,
    logLevel: env.LOG_LEVEL,
    databaseUrl: env.DATABASE_URL,
    redisUrl: env.REDIS_URL,
    corsOrigins: env.CORS_ORIGINS.split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    requestTimeoutMs: env.REQUEST_TIMEOUT_MS,
    secrets: { provider: env.SECRETS_PROVIDER, dir: env.SECRETS_DIR },
    jwt: {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      activeKid: env.JWT_ACTIVE_KID,
      accessTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
      mfaTtlSeconds: env.MFA_TOKEN_TTL_SECONDS,
      requireTyp: env.JWT_REQUIRE_TYP,
    },
    refreshTtlDays: env.REFRESH_TOKEN_TTL_DAYS,
    kekActiveVersion: env.KEK_ACTIVE_VERSION,
    macActiveVersion: env.MAC_ACTIVE_VERSION,
    scrypt: { logN: env.SCRYPT_LOG_N, r: env.SCRYPT_R, p: env.SCRYPT_P },
    totpIssuer: env.TOTP_ISSUER,
    rateLimitEnabled: env.RATE_LIMIT_ENABLED,
    admin:
      env.ADMIN_EMAIL && env.ADMIN_PASSWORD
        ? { email: env.ADMIN_EMAIL.toLowerCase(), password: env.ADMIN_PASSWORD }
        : null,
  }));

export type AppConfig = z.output<typeof envSchema>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Parses and validates the environment. Throws ConfigError with a readable
 * list of problems so the process can fail fast at boot.
 */
export function loadConfig(source: Record<string, string | undefined> = process.env): AppConfig {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const lines = result.error.issues.map(
      (i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`,
    );
    throw new ConfigError(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  return result.data;
}
