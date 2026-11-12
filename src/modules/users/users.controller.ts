import type { Request, Response } from 'express';
import { clientContext } from '../../http/client-context';
import { authed } from '../../http/handler';
import { registerSchema } from '../auth/auth.schemas';
import { changePasswordSchema, userIdParamSchema } from './users.schemas';
import type { UsersService } from './users.service';

export function createUsersController(service: UsersService) {
  return {
    register: async (req: Request, res: Response) => {
      const input = registerSchema.parse(req.body);
      res.status(201).json(await service.register(input, clientContext(req)));
    },

    me: authed(async (req, res) => {
      res.json(await service.getProfile(req.auth.userId));
    }),

    changePassword: authed(async (req, res) => {
      const input = changePasswordSchema.parse(req.body);
      await service.changePassword(
        { userId: req.auth.userId, currentSessionId: req.auth.sessionId, ...input },
        clientContext(req),
      );
      res.status(204).end();
    }),

    lock: authed(async (req, res) => {
      const { id } = userIdParamSchema.parse(req.params);
      await service.lockUser(id, req.auth.userId, clientContext(req));
      res.status(204).end();
    }),

    unlock: authed(async (req, res) => {
      const { id } = userIdParamSchema.parse(req.params);
      await service.unlockUser(id, req.auth.userId, clientContext(req));
      res.status(204).end();
    }),
  };
}
