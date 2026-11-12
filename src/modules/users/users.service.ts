import type { RequestContext } from '../../shared/context';
import { badRequest, conflict, forbidden, notFound } from '../../shared/errors';
import type { AuditRecorder } from '../audit/audit.service';
import type { SessionService } from '../sessions/sessions.service';
import type { PasswordHasher } from './password-hasher';
import { EmailTakenError, type UsersRepository } from './users.repository';

export interface UsersServiceDeps {
  users: UsersRepository;
  hasher: PasswordHasher;
  sessions: SessionService;
  audit: AuditRecorder;
  /** Whether the user has 2FA enabled (provided by the MFA module). */
  isMfaEnabled: (userId: string) => Promise<boolean>;
}

export interface PublicUser {
  id: string;
  email: string;
  roles: string[];
  createdAt: string;
}

export class UsersService {
  constructor(private readonly d: UsersServiceDeps) {}

  async register(input: { email: string; password: string }, ctx: RequestContext): Promise<PublicUser> {
    const passwordHash = await this.d.hasher.hash(input.password);
    try {
      const user = await this.d.users.create({ email: input.email, passwordHash, roles: ['user'] });
      await this.d.audit.record({ eventType: 'user_registered', actorUserId: user.id, ...ctx });
      return { id: user.id, email: user.email, roles: user.roles, createdAt: user.createdAt.toISOString() };
    } catch (err) {
      if (err instanceof EmailTakenError) throw conflict('Email already registered', 'email_taken');
      throw err;
    }
  }

  async getProfile(userId: string): Promise<PublicUser & { mfaEnabled: boolean }> {
    const user = await this.d.users.findById(userId);
    if (!user) throw notFound('User not found');
    return {
      id: user.id,
      email: user.email,
      roles: user.roles,
      createdAt: user.createdAt.toISOString(),
      mfaEnabled: await this.d.isMfaEnabled(user.id),
    };
  }

  /** Changes the password and revokes every other session of the user. */
  async changePassword(
    input: { userId: string; currentSessionId: string; currentPassword: string; newPassword: string },
    ctx: RequestContext,
  ): Promise<void> {
    const user = await this.d.users.findById(input.userId);
    if (!user) throw notFound('User not found');
    if (!(await this.d.hasher.verify(input.currentPassword, user.passwordHash))) {
      await this.d.audit.record({
        eventType: 'password_change_failed',
        actorUserId: user.id,
        ...ctx,
      });
      throw forbidden('Current password is incorrect', 'invalid_current_password');
    }
    if (input.currentPassword === input.newPassword) {
      throw badRequest('password_unchanged', 'New password must differ from the current one');
    }
    await this.d.users.updatePasswordHash(user.id, await this.d.hasher.hash(input.newPassword));
    const revoked = await this.d.sessions.revokeOthers(user.id, input.currentSessionId);
    await this.d.audit.record({
      eventType: 'password_changed',
      actorUserId: user.id,
      metadata: { revokedSessions: revoked.length },
      ...ctx,
    });
  }

  async lockUser(targetId: string, adminId: string, ctx: RequestContext): Promise<void> {
    if (targetId === adminId) throw badRequest('cannot_lock_self', 'Admins cannot lock themselves');
    if (!(await this.d.users.setLockedAt(targetId, new Date()))) throw notFound('User not found');
    const revoked = await this.d.sessions.revokeAll(targetId);
    await this.d.audit.record({
      eventType: 'admin_user_locked',
      actorUserId: adminId,
      metadata: { targetUserId: targetId, revokedSessions: revoked.length },
      ...ctx,
    });
  }

  async unlockUser(targetId: string, adminId: string, ctx: RequestContext): Promise<void> {
    if (!(await this.d.users.setLockedAt(targetId, null))) throw notFound('User not found');
    await this.d.audit.record({
      eventType: 'admin_user_unlocked',
      actorUserId: adminId,
      metadata: { targetUserId: targetId },
      ...ctx,
    });
  }
}
