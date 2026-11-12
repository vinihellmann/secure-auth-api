import path from 'node:path';
import cors from 'cors';
import express, { Router, type Express } from 'express';
import helmet from 'helmet';
import type { AppConfig } from '../config/env';
import type { KeyStore } from '../infra/crypto/jwt-keys';
import type { Logger } from '../infra/logger';
import type { RateLimiter } from '../infra/rate-limit/sliding-window';
import { auditRoutes } from '../modules/audit/audit.routes';
import type { AuditService } from '../modules/audit/audit.service';
import { authRoutes } from '../modules/auth/auth.routes';
import type { AuthService } from '../modules/auth/auth.service';
import type { TokenService } from '../modules/auth/tokens';
import { mfaRoutes } from '../modules/mfa/mfa.routes';
import type { MfaService } from '../modules/mfa/mfa.service';
import { sessionsRoutes } from '../modules/sessions/sessions.routes';
import type { SessionService } from '../modules/sessions/sessions.service';
import { adminUsersRoutes, usersRoutes } from '../modules/users/users.routes';
import type { UsersService } from '../modules/users/users.service';
import { authenticate, requireRole } from './middleware/authenticate';
import { errorHandler, notFoundHandler } from './middleware/errors';
import { POLICIES, rateLimit } from './middleware/rate-limit';
import { requestLogging, requestTimeout } from './middleware/request';
import type { RouteKit } from './route-kit';

export interface AppDeps {
  config: AppConfig;
  logger: Logger;
  keys: KeyStore;
  tokens: TokenService;
  limiter: RateLimiter;
  auth: AuthService;
  users: UsersService;
  sessions: SessionService;
  mfa: MfaService;
  audit: AuditService;
  readiness: () => Promise<Record<string, boolean>>;
  /** Routes that need a relaxed CSP (interactive docs). Registered before helmet. */
  configurePublicRoutes?: (app: Express) => void;
}

export function createApp(d: AppDeps): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', d.config.trustProxy);

  const limit: RouteKit['limit'] = (policy) =>
    rateLimit(d.limiter, policy, d.config.rateLimitEnabled);
  const requireAuth = authenticate(d.tokens, d.sessions);

  app.use(requestLogging(d.logger));
  app.use(requestTimeout(d.config.requestTimeoutMs));

  app.get('/openapi.yaml', (_req, res) => {
    res.type('application/yaml').sendFile(path.resolve(process.cwd(), 'openapi.yaml'));
  });
  d.configurePublicRoutes?.(app);

  app.use(helmet());
  app.use(
    cors({
      origin: d.config.corsOrigins.length > 0 ? d.config.corsOrigins : false,
      credentials: false,
      maxAge: 600,
      exposedHeaders: [
        'X-Request-Id',
        'Retry-After',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
      ],
    }),
  );
  app.use(express.json({ limit: '10kb' }));

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/ready', async (_req, res) => {
    const checks = await d.readiness();
    const ready = Object.values(checks).every(Boolean);
    res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'not_ready', checks });
  });
  app.get('/.well-known/jwks.json', (_req, res) => {
    // Short cache: clients pick up a new key soon after rotation.
    res.set('Cache-Control', 'public, max-age=300').json(d.keys.jwks());
  });

  const kit: RouteKit = { requireAuth, requireRole, limit };

  const admin = Router();
  admin.use(requireAuth, requireRole('admin'));
  admin.use(auditRoutes(d.audit));
  admin.use(adminUsersRoutes(d.users));

  const v1 = Router();
  v1.use(limit(POLICIES.global));
  v1.use(usersRoutes(d.users, kit));
  v1.use(authRoutes(d.auth, kit));
  v1.use(sessionsRoutes(d.sessions, kit));
  v1.use(mfaRoutes(d.mfa, kit));
  v1.use('/admin', admin);

  app.use('/v1', v1);
  app.use(notFoundHandler());
  app.use(errorHandler(d.logger));
  return app;
}
