import { Redis } from 'ioredis';
import type { Logger } from '../logger';

export function createRedis(url: string, logger: Logger): Redis {
  const redis = new Redis(url, { maxRetriesPerRequest: 2, enableReadyCheck: true });
  redis.on('error', (err: Error) => {
    logger.error('redis_error', { message: err.message });
  });
  return redis;
}
