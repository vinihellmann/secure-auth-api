import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import type { Logger } from '../../infra/logger';
import { AppError, notFound } from '../../shared/errors';

export interface ProblemDocument {
  type: string;
  title: string;
  status: number;
  code: string;
  detail?: string;
  errors?: unknown;
}

const problem = (
  status: number,
  code: string,
  title: string,
  errors?: unknown,
): ProblemDocument => ({
  type: `urn:secure-auth-api:problem:${code}`,
  title,
  status,
  code,
  ...(errors !== undefined ? { errors } : {}),
});

/** Maps anything thrown to RFC 9457 problem details plus response headers. */
export function toProblem(err: unknown): {
  body: ProblemDocument;
  headers: Record<string, string>;
} {
  if (err instanceof AppError) {
    return {
      body: problem(err.status, err.code, err.message, err.extra.errors),
      headers: err.extra.headers ?? {},
    };
  }
  if (err instanceof ZodError) {
    return {
      body: problem(
        400,
        'validation_error',
        'Request validation failed',
        err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      ),
      headers: {},
    };
  }
  const e = err as { type?: unknown; status?: unknown } | null;
  if (e?.type === 'entity.parse.failed') {
    return { body: problem(400, 'malformed_json', 'Malformed JSON body'), headers: {} };
  }
  if (e?.type === 'entity.too.large') {
    return { body: problem(413, 'payload_too_large', 'Request body exceeds 10kb'), headers: {} };
  }
  if (typeof e?.status === 'number' && e.status >= 400 && e.status < 500) {
    return { body: problem(e.status, 'bad_request', 'Bad request'), headers: {} };
  }
  return { body: problem(500, 'internal_error', 'Internal server error'), headers: {} };
}

export function notFoundHandler(): RequestHandler {
  return () => {
    throw notFound('Route not found', 'route_not_found');
  };
}

export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (err, req, res, next) => {
    const { body, headers } = toProblem(err);
    if (body.status >= 500) {
      logger.error('unhandled_error', {
        requestId: req.requestId,
        error:
          err instanceof Error
            ? { name: err.name, message: err.message, stack: err.stack }
            : String(err),
      });
    }
    if (res.headersSent) {
      next(err);
      return;
    }
    res
      .status(body.status)
      .set(headers)
      .type('application/problem+json')
      .json({ ...body, instance: req.originalUrl, requestId: req.requestId });
  };
}
