import { Router } from 'express';
import { POLICIES } from '../../http/middleware/rate-limit';
import type { RouteKit } from '../../http/route-kit';
import { createAuthController } from './auth.controller';
import type { AuthService } from './auth.service';

export function authRoutes(service: AuthService, { requireAuth, limit }: RouteKit): Router {
  const c = createAuthController(service);
  const r = Router();
  r.post('/auth/login', limit(POLICIES.login), c.login);
  r.post('/auth/login/mfa', limit(POLICIES.loginMfa), c.loginMfa);
  r.post('/auth/refresh', limit(POLICIES.refresh), c.refresh);
  r.post('/auth/logout', requireAuth, c.logout);
  return r;
}
