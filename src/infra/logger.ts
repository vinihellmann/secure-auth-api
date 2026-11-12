import winston from 'winston';

export type Logger = winston.Logger;

export interface LoggerOptions {
  level: string;
  silent?: boolean;
}

/**
 * Structured JSON logger. Never log request bodies, passwords, tokens or secrets.
 */
export function createLogger(options: LoggerOptions): Logger {
  return winston.createLogger({
    level: options.level,
    silent: options.silent ?? false,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json(),
    ),
    transports: [new winston.transports.Console()],
  });
}
