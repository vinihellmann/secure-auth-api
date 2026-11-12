import { Router } from 'express';
import { POLICIES } from '../../http/middleware/rate-limit';
import type { RouteKit } from '../../http/route-kit';
import { createUsersController } from './users.controller';
import type { UsersService } from './users.service';

/**
 * Self-service routes. Registration lives here (not with auth) because it creates a user;
 * the `/auth/register` path is part of the public API and stays as is.
 */
export function usersRoutes(service: UsersService, { requireAuth, limit }: RouteKit): Router {
  const c = createUsersController(service);
  const r = Router();
  r.post('/auth/register', limit(POLICIES.register), c.register);
  r.get('/me', requireAuth, c.me);
  r.post('/me/password', requireAuth, limit(POLICIES.sensitive), c.changePassword);
  return r;
}

/** Admin-only user management; the caller mounts it behind requireAuth + requireRole('admin'). */
export function adminUsersRoutes(service: UsersService): Router {
  const c = createUsersController(service);
  const r = Router();
  r.post('/users/:id/lock', c.lock);
  r.post('/users/:id/unlock', c.unlock);
  return r;
}
