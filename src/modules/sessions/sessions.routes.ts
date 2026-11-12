import { Router } from 'express';
import type { RouteKit } from '../../http/route-kit';
import { createSessionsController } from './sessions.controller';
import type { SessionService } from './sessions.service';

export function sessionsRoutes(service: SessionService, { requireAuth }: RouteKit): Router {
  const c = createSessionsController(service);
  const r = Router();
  r.get('/sessions', requireAuth, c.list);
  r.delete('/sessions/:id', requireAuth, c.revoke);
  return r;
}
