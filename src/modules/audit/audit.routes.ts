import { Router } from 'express';
import { createAuditController } from './audit.controller';
import type { AuditService } from './audit.service';

/** Admin-only; the caller mounts it behind requireAuth + requireRole('admin'). */
export function auditRoutes(service: AuditService): Router {
  const c = createAuditController(service);
  const r = Router();
  r.get('/audit-events', c.list);
  r.get('/audit-events/verify', c.verify);
  return r;
}
