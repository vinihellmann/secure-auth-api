import { apiReference } from '@scalar/express-api-reference';
import type { RequestHandler } from 'express';
import { loadConfig } from './config/env';
import { createContainer } from './container';
import { createLogger } from './infra/logger';

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ level: config.logLevel });

  const container = await createContainer(config, logger, {
    configurePublicRoutes: (app) => {
      // The handler is typed with `never` route params; it does not read any.
      const docs = apiReference({
        url: '/openapi.yaml',
        pageTitle: 'Secure Auth API',
      }) as unknown as RequestHandler;
      app.use('/docs', docs);
    },
  });

  const server = container.app.listen(config.port, () => {
    logger.info('api_listening', { port: config.port, activeKid: config.jwt.activeKid });
  });
  server.requestTimeout = config.requestTimeoutMs + 5_000;
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;

  let stopping = false;
  const shutdown = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    logger.info('shutdown_started', { signal });
    const force = setTimeout(() => process.exit(1), 15_000);
    force.unref();
    server.close(() => {
      container
        .close()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
    });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err: unknown) => {
  createLogger({ level: 'error' }).error('startup_failed', {
    error: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
