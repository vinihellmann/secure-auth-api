import type { Request, Response } from 'express';
import { clientContext } from '../../http/client-context';
import { authed, noStore } from '../../http/handler';
import { loginMfaSchema, loginSchema, refreshSchema } from './auth.schemas';
import type { AuthService } from './auth.service';

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

    logout: authed(async (req, res) => {
      await service.logout(req.auth.userId, req.auth.sessionId, clientContext(req));
      res.status(204).end();
    }),
  };
}
