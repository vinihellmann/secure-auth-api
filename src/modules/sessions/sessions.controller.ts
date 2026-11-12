import type { Request, Response } from 'express';
import { z } from 'zod';
import { clientContext } from '../../http/client-context';
import { unauthorized } from '../../shared/errors';
import type { AuditRecorder } from '../audit/audit.service';
import type { SessionService } from './sessions.service';

const sessionIdParam = z.object({ id: z.string().uuid() });

export function createSessionsController(sessions: SessionService, audit: AuditRecorder) {
  return {
    list: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      const current = req.auth.sessionId;
      const items = await sessions.list(req.auth.userId);
      res.json({
        items: items.map((s) => ({
          id: s.id,
          current: s.id === current,
          userAgent: s.userAgent,
          ip: s.ip,
          createdAt: s.createdAt.toISOString(),
          lastUsedAt: s.lastUsedAt.toISOString(),
        })),
      });
    },

    revoke: async (req: Request, res: Response) => {
      if (!req.auth) throw unauthorized();
      const { id } = sessionIdParam.parse(req.params);
      await sessions.revoke(req.auth.userId, id);
      await audit.record({
        eventType: 'session_revoked',
        actorUserId: req.auth.userId,
        metadata: { sessionId: id },
        ...clientContext(req),
      });
      res.status(204).end();
    },
  };
}
