import { z } from 'zod';

export const listAuditEventsQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z
    .string()
    .regex(/^\d{1,18}$/)
    .optional(),
  eventType: z.string().min(1).max(100).optional(),
  actorUserId: z.string().uuid().optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
});
