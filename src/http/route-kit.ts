import type { RequestHandler } from 'express';
import type { RatePolicy } from './middleware/rate-limit';

/**
 * The cross-cutting middleware factories a feature router needs. Routers receive them instead
 * of importing the container, so each `*.routes.ts` stays declarative and testable.
 */
export interface RouteKit {
  requireAuth: RequestHandler;
  requireRole: (role: string) => RequestHandler;
  limit: (policy: RatePolicy) => RequestHandler;
}
