import type { Request } from 'express';
import type { RequestContext } from '../shared/context';

export interface AuthContext {
  userId: string;
  sessionId: string;
  roles: string[];
}

declare module 'express-serve-static-core' {
  interface Request {
    /** Set by the authenticate middleware. */
    auth?: AuthContext;
    requestId: string;
  }
}

/** Client metadata recorded on sessions and audit events. `req.ip` honours TRUST_PROXY. */
export function clientContext(req: Request): RequestContext {
  return {
    ip: req.ip ?? null,
    userAgent: req.get('user-agent')?.slice(0, 512) ?? null,
  };
}
