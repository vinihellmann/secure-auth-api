import { authenticator } from 'otplib';
import { safeEqual } from '../../infra/crypto/hash';

export const TOTP_STEP_SECONDS = 30;
/** Accept the previous and next step to tolerate clock drift (RFC 6238 section 5.2). */
export const TOTP_WINDOW = 1;
const CODE_PATTERN = /^\d{6}$/;

/** Records the last accepted time-step per user (Redis in production). */
export interface TotpStepStore {
  /** Atomically accepts `step` only if it is greater than the last accepted one. */
  claimStep(userId: string, step: number, ttlSeconds: number): Promise<boolean>;
}

export const generateTotpSecret = (): string => authenticator.generateSecret(20); // 160 bits

export const buildOtpAuthUri = (secret: string, account: string, issuer: string): string =>
  authenticator.keyuri(account, issuer, secret);

export const timeStep = (nowMs: number): number => Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);

/** The code a correct authenticator shows during `step`. */
export function codeForStep(secret: string, step: number): string {
  return authenticator.clone({ epoch: step * TOTP_STEP_SECONDS * 1000 }).generate(secret);
}

/**
 * Returns the matching time-step, or null. Pure: replay protection is a separate concern
 * (see TotpVerifier) so this stays trivially testable.
 */
export function matchTotp(secret: string, code: string, nowMs: number): number | null {
  if (!CODE_PATTERN.test(code)) return null;
  const current = timeStep(nowMs);
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    const step = current + delta;
    if (safeEqual(codeForStep(secret, step), code)) return step;
  }
  return null;
}

/**
 * TOTP verification with anti-replay: a code is valid for ~90s (window of 1), so without
 * state it could be used several times. The accepted step is claimed atomically in Redis and
 * only strictly newer steps are accepted afterwards.
 */
export class TotpVerifier {
  constructor(
    private readonly steps: TotpStepStore,
    private readonly now: () => number = Date.now,
  ) {}

  async verify(userId: string, secret: string, code: string): Promise<boolean> {
    const step = matchTotp(secret, code, this.now());
    if (step === null) return false;
    const ttlSeconds = TOTP_STEP_SECONDS * (2 * TOTP_WINDOW + 2);
    return this.steps.claimStep(userId, step, ttlSeconds);
  }
}
