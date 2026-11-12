import { clientContext } from '../../http/client-context';
import { authed, noStore } from '../../http/handler';
import { disableMfaSchema, enableMfaSchema } from './mfa.schemas';
import type { MfaService } from './mfa.service';

export function createMfaController(service: MfaService) {
  return {
    setup: authed(async (req, res) => {
      noStore(res).json(await service.setup(req.auth.userId, clientContext(req)));
    }),

    enable: authed(async (req, res) => {
      const { code } = enableMfaSchema.parse(req.body);
      noStore(res).json(await service.enable(req.auth.userId, code, clientContext(req)));
    }),

    disable: authed(async (req, res) => {
      const input = disableMfaSchema.parse(req.body);
      await service.disable(req.auth.userId, input, clientContext(req));
      res.status(204).end();
    }),
  };
}
