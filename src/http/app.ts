import path from 'node:path';
import cors from 'cors';
import express, { Router, type Express } from 'express';
import helmet from 'helmet';
import type { AppConfig } from '../config/env';
import type { KeyStore } from '../infra/crypto/jwt-keys';
import type { Logger } from '../infra/logger';
import type { RateLimiter } from '../infra/rate-limit/sliding-window';
import { createAuditController } from '../modules/audit/audit.controller';
import type { AuditService } from '../modules/audit/audit.service';
import { createAuthController } from '../modules/auth/auth.controller';
import type { AuthService } from '../modules/auth/auth.service';
import type { TokenService } from '../modules/auth/tokens';
import { createMfaController } from '../modules/mfa/mfa.controller';
import type { MfaService } from '../modules/mfa/mfa.service';
import { createSessionsController } from '../modules/sessions/sessions.controller';
import type { SessionService } from '../modules/sessions/sessions.service';
import { createUsersController } from '../modules/users/users.controller';
import type { UsersService } from '../modules/users/users.service';
import { authenticate, requireRole } from './middleware/authenticate';
import { errorHandler, notFoundHandler } from './middleware/errors';
import { POLICIES, rateLimit } from './middleware/rate-limit';
import { requestLogging, requestTimeout } from './middleware/request';

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

  const limit = (policy: (typeof POLICIES)[keyof typeof POLICIES]) =>
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

  const auth = createAuthController(d.auth);
  const users = createUsersController(d.users);
  const sessions = createSessionsController(d.sessions, d.audit);
  const mfa = createMfaController(d.mfa);
  const audit = createAuditController(d.audit);

  const v1 = Router();
  v1.use(limit(POLICIES.global));

  v1.post('/auth/register', limit(POLICIES.register), users.register);
  v1.post('/auth/login', limit(POLICIES.login), auth.login);
  v1.post('/auth/login/mfa', limit(POLICIES.loginMfa), auth.loginMfa);
  v1.post('/auth/refresh', limit(POLICIES.refresh), auth.refresh);
  v1.post('/auth/logout', requireAuth, auth.logout);

  v1.get('/me', requireAuth, users.me);
  v1.post('/me/password', requireAuth, limit(POLICIES.sensitive), users.changePassword);

  v1.get('/sessions', requireAuth, sessions.list);
  v1.delete('/sessions/:id', requireAuth, sessions.revoke);

  v1.post('/mfa/totp/setup', requireAuth, limit(POLICIES.sensitive), mfa.setup);
  v1.post('/mfa/totp/enable', requireAuth, limit(POLICIES.sensitive), mfa.enable);
  v1.post('/mfa/totp/disable', requireAuth, limit(POLICIES.sensitive), mfa.disable);

  const admin = Router();
  admin.use(requireAuth, requireRole('admin'));
  admin.get('/audit-events', audit.list);
  admin.get('/audit-events/verify', audit.verify);
  admin.post('/users/:id/lock', users.lock);
  admin.post('/users/:id/unlock', users.unlock);
  v1.use('/admin', admin);

  app.use('/v1', v1);
  app.use(notFoundHandler());
  app.use(errorHandler(d.logger));
  return app;
}
