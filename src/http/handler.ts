import type { Request, RequestHandler, Response } from 'express';
import { unauthorized } from '../shared/errors';
import type { AuthContext } from './client-context';

export type AuthedRequest = Request & { auth: AuthContext };

/**
 * Wraps a handler that needs an authenticated caller. The `authenticate` middleware is what
 * normally guarantees `req.auth`, but a route mounted without it would otherwise fail open
 * with a confusing TypeError; failing closed here keeps that mistake a 401 and gives the
 * handler a narrowed request type instead of a repeated null check.
 *
 * Express 5 forwards rejected promises to the error handler, so async handlers need no try/catch.
 */
export const authed =
  (fn: (req: AuthedRequest, res: Response) => Promise<void> | void): RequestHandler =>
  (req, res) => {
    if (!req.auth) throw unauthorized();
    return fn(req as AuthedRequest, res);
  };

/** Token and secret-bearing responses must never be cached by intermediaries (RFC 6749 5.1). */
export const noStore = (res: Response): Response => res.set('Cache-Control', 'no-store');
