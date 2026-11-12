import type { Request, Response } from 'express';
import { clientContext } from '../../http/client-context';
import { unauthorized } from '../../shared/errors';
import { disableMfaSchema, enableMfaSchema } from './mfa.schemas';
import type { MfaService } from './mfa.service';

export function createMfaController(service: MfaService) {
  return {
    setup: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      res
        .set('Cache-Control', 'no-store')
        .json(await service.setup(req.auth.userId, clientContext(req)));
    },

    enable: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      const { code } = enableMfaSchema.parse(req.body);
      res
        .set('Cache-Control', 'no-store')
        .json(await service.enable(req.auth.userId, code, clientContext(req)));
    },

    disable: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      const input = disableMfaSchema.parse(req.body);
      await service.disable(req.auth.userId, input, clientContext(req));
      res.status(204).end();
    },
  };
}
