import { Router } from 'express';
import { POLICIES } from '../../http/middleware/rate-limit';
import type { RouteKit } from '../../http/route-kit';
import { createMfaController } from './mfa.controller';
import type { MfaService } from './mfa.service';

export function mfaRoutes(service: MfaService, { requireAuth, limit }: RouteKit): Router {
  const c = createMfaController(service);
  const r = Router();
  r.post('/mfa/totp/setup', requireAuth, limit(POLICIES.sensitive), c.setup);
  r.post('/mfa/totp/enable', requireAuth, limit(POLICIES.sensitive), c.enable);
  r.post('/mfa/totp/disable', requireAuth, limit(POLICIES.sensitive), c.disable);
  return r;
}
