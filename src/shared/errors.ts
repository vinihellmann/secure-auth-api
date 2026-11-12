export interface AppErrorExtra {
  headers?: Record<string, string>;
  errors?: unknown;
}

/**
 * Operational error that maps 1:1 to an RFC 7807 problem response.
 */
export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly extra: AppErrorExtra = {},
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const badRequest = (code: string, message: string) => new AppError(400, code, message);

export const unauthorized = (message = 'Authentication required', code = 'unauthorized') =>
  new AppError(401, code, message, { headers: { 'WWW-Authenticate': 'Bearer' } });

export const forbidden = (message = 'Forbidden', code = 'forbidden') =>
  new AppError(403, code, message);

export const notFound = (message = 'Resource not found', code = 'not_found') =>
  new AppError(404, code, message);

export const conflict = (message: string, code = 'conflict') => new AppError(409, code, message);

export const tooManyRequests = (retryAfterSeconds: number, code: string, message: string) =>
  new AppError(429, code, message, {
    headers: { 'Retry-After': String(Math.max(1, Math.ceil(retryAfterSeconds))) },
  });
