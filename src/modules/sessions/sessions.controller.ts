import { z } from 'zod';
import { clientContext } from '../../http/client-context';
import { authed } from '../../http/handler';
import type { SessionService } from './sessions.service';

const sessionIdParam = z.object({ id: z.string().uuid() });

export function createSessionsController(sessions: SessionService) {
  return {
    list: authed(async (req, res) => {
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
    }),

    revoke: authed(async (req, res) => {
      const { id } = sessionIdParam.parse(req.params);
      await sessions.revoke(req.auth.userId, id, clientContext(req));
      res.status(204).end();
    }),
  };
}
