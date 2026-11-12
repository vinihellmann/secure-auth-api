import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import type { Logger } from '../../infra/logger';
import { AppError } from '../../shared/errors';

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** Correlation id + one access log line per request (never bodies, never tokens). */
export function requestLogging(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.requestId = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
    res.setHeader('X-Request-Id', req.requestId);

    const start = process.hrtime.bigint();
    res.on('finish', () => {
      logger.http('request', {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Number((process.hrtime.bigint() - start) / 1_000_000n),
        userId: req.auth?.userId,
      });
    });
    next();
  };
}

/**
 * Answers 503 if a handler has not responded within `ms`, so slow dependencies cannot pin
 * sockets indefinitely. The handler keeps running; its late response is discarded.
 */
export function requestTimeout(ms: number): RequestHandler {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        next(new AppError(503, 'request_timeout', 'The request took too long to complete'));
      }
    }, ms);
    timer.unref();
    const clear = (): void => clearTimeout(timer);
    res.on('finish', clear);
    res.on('close', clear);
    next();
  };
}
