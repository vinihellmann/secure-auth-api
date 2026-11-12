import type { Request, Response } from 'express';
import { clientContext } from '../../http/client-context';
import { unauthorized } from '../../shared/errors';
import { loginMfaSchema, loginSchema, refreshSchema } from './auth.schemas';
import type { AuthService } from './auth.service';

// Token responses must never be cached by intermediaries (RFC 6749 section 5.1).
const noStore = (res: Response): Response => res.set('Cache-Control', 'no-store');

export function createAuthController(service: AuthService) {
  return {
    login: async (req: Request, res: Response) => {
      const { email, password } = loginSchema.parse(req.body);
      noStore(res).json(await service.login(email, password, clientContext(req)));
    },

    loginMfa: async (req: Request, res: Response) => {
      const input = loginMfaSchema.parse(req.body);
      noStore(res).json(await service.loginWithMfa(input, clientContext(req)));
    },

    refresh: async (req: Request, res: Response) => {
      const { refreshToken } = refreshSchema.parse(req.body);
      noStore(res).json(await service.refresh(refreshToken, clientContext(req)));
    },

    logout: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      await service.logout(req.auth.userId, req.auth.sessionId, clientContext(req));
      res.status(204).end();
    },
  };
}
