import type { Request, Response } from 'express';
import type { AuditService } from './audit.service';
import { listAuditEventsQuery } from './audit.schemas';

export function createAuditController(service: AuditService) {
  return {
    list: async (req: Request, res: Response) => {
      const query = listAuditEventsQuery.parse(req.query);
      const { items, nextCursor } = await service.list(query);
      res.json({
        items: items.map((e) => ({
          id: e.id,
          occurredAt: e.occurredAt.toISOString(),
          actorUserId: e.actorUserId,
          eventType: e.eventType,
          ip: e.ip,
          userAgent: e.userAgent,
          metadata: e.metadata,
          prevHash: e.prevHash,
          hash: e.hash,
        })),
        nextCursor,
      });
    },

    verify: async (_req: Request, res: Response) => {
      res.json(await service.verify());
    },
  };
}
