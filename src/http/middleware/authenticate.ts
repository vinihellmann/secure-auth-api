import type { RequestHandler } from 'express';
import type { TokenService } from '../../modules/auth/tokens';
import type { RevokedSessionCache } from '../../modules/sessions/sessions.service';
import { forbidden, unauthorized } from '../../shared/errors';

/**
 * Verifies the RS256 access token and rejects tokens whose session was revoked (logout,
 * password change, refresh-token reuse, admin lock) even though the JWT itself is still valid.
 */
export function authenticate(
  tokens: TokenService,
  revoked: Pick<RevokedSessionCache, 'isRevoked'>,
): RequestHandler {
  return async (req, _res, next) => {
    const header = req.get('authorization') ?? '';
    // Tolerate repeated spaces between scheme and token, but accept nothing beyond exactly
    // "<scheme> <one token>".
    const parts = header.trim().split(/\s+/);
    const [scheme, token] = parts;
    if (parts.length !== 2 || scheme?.toLowerCase() !== 'bearer' || !token) {
      throw unauthorized();
    }
    const claims = tokens.verifyAccess(token);
    if (await revoked.isRevoked(claims.sessionId)) {
      throw unauthorized('Session has been revoked', 'session_revoked');
    }
    req.auth = claims;
    next();
  };
}

export function requireRole(role: string): RequestHandler {
  return (req, _res, next) => {
    if (!req.auth) throw unauthorized();
    if (!req.auth.roles.includes(role)) throw forbidden('Insufficient role', 'insufficient_role');
    next();
  };
}
