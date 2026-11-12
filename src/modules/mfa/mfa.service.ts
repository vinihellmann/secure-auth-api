import QRCode from 'qrcode';
import type { EnvelopeCrypto } from '../../infra/crypto/envelope';
import type { RequestContext } from '../../shared/context';
import { badRequest, conflict, forbidden, notFound } from '../../shared/errors';
import type { AuditRecorder } from '../audit/audit.service';
import type { UsersRepository } from '../users/users.repository';
import type { MfaRepository } from './mfa.repository';
import {
  RECOVERY_CODE_COUNT,
  generateRecoveryCode,
  type RecoveryCodeHasher,
} from './recovery-codes';
import { buildOtpAuthUri, generateTotpSecret, type TotpVerifier } from './totp';

/** Confirms the user's password; implementations apply their own brute-force lockout. */
export interface PasswordConfirmation {
  confirm(userId: string, password: string, passwordHash: string): Promise<boolean>;
}

export interface MfaServiceDeps {
  repo: MfaRepository;
  users: UsersRepository;
  passwordConfirmation: PasswordConfirmation;
  recoveryCodes: RecoveryCodeHasher;
  envelope: EnvelopeCrypto;
  totp: TotpVerifier;
  audit: AuditRecorder;
  issuer: string;
}

/** Encryption context: binds the ciphertext to its owner so it cannot be moved to another row. */
export const mfaSecretContext = (userId: string): string => `mfa:${userId}`;

export class MfaService {
  constructor(private readonly d: MfaServiceDeps) {}

  async isEnabled(userId: string): Promise<boolean> {
    return (await this.d.repo.find(userId))?.status === 'enabled';
  }

  /** Starts (or restarts) enrollment. The secret is stored encrypted and stays pending. */
  async setup(userId: string, ctx: RequestContext) {
    const user = await this.d.users.findById(userId);
    if (!user) throw notFound('User not found');
    if (await this.isEnabled(userId))
      throw conflict('Two-factor authentication is already enabled', 'mfa_already_enabled');

    const secret = generateTotpSecret();
    await this.d.repo.savePending(
      userId,
      this.d.envelope.encrypt(secret, mfaSecretContext(userId)),
    );
    const otpauthUri = buildOtpAuthUri(secret, user.email, this.d.issuer);
    await this.d.audit.record({ eventType: 'mfa_setup_started', actorUserId: userId, ...ctx });

    return {
      otpauthUri,
      qrCodeDataUrl: await QRCode.toDataURL(otpauthUri, { errorCorrectionLevel: 'M', margin: 1 }),
      // Shown once for manual entry; never returned again.
      secret,
    };
  }

  /** Confirms enrollment with a first valid code and returns single-use recovery codes. */
  async enable(
    userId: string,
    code: string,
    ctx: RequestContext,
  ): Promise<{ recoveryCodes: string[] }> {
    const cred = await this.d.repo.find(userId);
    if (!cred) throw badRequest('mfa_not_set_up', 'Call /v1/mfa/totp/setup first');
    if (cred.status === 'enabled')
      throw conflict('Two-factor authentication is already enabled', 'mfa_already_enabled');

    if (!(await this.d.totp.verify(userId, this.decryptSecret(cred.secretEnc, userId), code))) {
      await this.d.audit.record({ eventType: 'mfa_enable_failed', actorUserId: userId, ...ctx });
      throw badRequest('invalid_mfa_code', 'Invalid or already used code');
    }

    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await this.d.repo.enable(
      userId,
      recoveryCodes.map((c) => this.d.recoveryCodes.hash(userId, c)),
    );
    await this.d.audit.record({ eventType: 'mfa_enabled', actorUserId: userId, ...ctx });
    return { recoveryCodes };
  }

  /** Second login factor: a TOTP code (anti-replay) or a single-use recovery code. */
  async verifySecondFactor(
    userId: string,
    proof: { code?: string; recoveryCode?: string },
  ): Promise<{ ok: boolean; method: 'totp' | 'recovery_code' }> {
    const cred = await this.d.repo.find(userId);
    if (!cred || cred.status !== 'enabled') return { ok: false, method: 'totp' };

    if (proof.recoveryCode) {
      const ok = await this.d.repo.consumeRecoveryCode(
        userId,
        this.d.recoveryCodes.candidates(userId, proof.recoveryCode),
      );
      return { ok, method: 'recovery_code' };
    }
    const ok =
      proof.code !== undefined &&
      (await this.d.totp.verify(userId, this.decryptSecret(cred.secretEnc, userId), proof.code));
    return { ok, method: 'totp' };
  }

  /** Requires the password and a current second factor, so a stolen session alone cannot disable 2FA. */
  async disable(
    userId: string,
    input: { password: string; code?: string; recoveryCode?: string },
    ctx: RequestContext,
  ): Promise<void> {
    const user = await this.d.users.findById(userId);
    if (!user) throw notFound('User not found');
    if (!(await this.isEnabled(userId)))
      throw badRequest('mfa_not_enabled', 'Two-factor authentication is not enabled');

    const passwordOk = await this.d.passwordConfirmation.confirm(
      userId,
      input.password,
      user.passwordHash,
    );
    const factor = passwordOk ? await this.verifySecondFactor(userId, input) : { ok: false };
    if (!passwordOk || !factor.ok) {
      await this.d.audit.record({ eventType: 'mfa_disable_failed', actorUserId: userId, ...ctx });
      throw forbidden('Invalid password or code', 'invalid_credentials');
    }

    await this.d.repo.remove(userId);
    await this.d.audit.record({ eventType: 'mfa_disabled', actorUserId: userId, ...ctx });
  }

  private decryptSecret(secretEnc: string, userId: string): string {
    return this.d.envelope.decrypt(secretEnc, mfaSecretContext(userId));
  }
}
