import { randomInt, randomUUID } from 'node:crypto';
import request from 'supertest';
import { loadConfig, type AppConfig } from '../../src/config/env';
import { createContainer, type Container } from '../../src/container';
import { runMigrations } from '../../src/infra/db/migrator';
import { createLogger } from '../../src/infra/logger';

export interface TestContext {
  config: AppConfig;
  container: Container;
}

/** Builds the real application against the compose Postgres and Redis. */
export async function startApp(): Promise<TestContext> {
  const config = loadConfig();
  const container = await createContainer(config, createLogger({ level: 'error', silent: true }));
  // No-op when the migrate service already ran; the keyring signs the audit cut-over anchor
  // if 004 is still pending on a database that already has audit events.
  await runMigrations(container.sequelize, undefined, { mac: container.mac });
  return { config, container };
}

export const STRONG_PASSWORD = 'Correct-Horse-9-Battery';

/** Every test client gets its own source IP (TRUST_PROXY=true), so rate limits do not bleed. */
export const randomIp = (): string => `10.${randomInt(256)}.${randomInt(256)}.${randomInt(1, 255)}`;

export const uniqueEmail = (prefix = 'user'): string =>
  `${prefix}-${randomUUID().slice(0, 8)}@example.test`;

export function client(ctx: TestContext, ip = randomIp()) {
  const app = ctx.container.app;
  const withIp = (t: request.Test) => t.set('X-Forwarded-For', ip);
  return {
    ip,
    get: (path: string, token?: string) =>
      withIp(
        token
          ? request(app).get(path).set('Authorization', `Bearer ${token}`)
          : request(app).get(path),
      ),
    post: (path: string, body?: object, token?: string) => {
      const t = withIp(request(app).post(path));
      if (token) t.set('Authorization', `Bearer ${token}`);
      return body ? t.send(body) : t;
    },
    delete: (path: string, token: string) =>
      withIp(request(app).delete(path).set('Authorization', `Bearer ${token}`)),
  };
}

export interface LoggedInUser {
  id: string;
  email: string;
  password: string;
  accessToken: string;
  refreshToken: string;
}

export async function registerAndLogin(
  ctx: TestContext,
  email = uniqueEmail(),
): Promise<LoggedInUser> {
  const api = client(ctx);
  const reg = await api.post('/v1/auth/register', { email, password: STRONG_PASSWORD });
  if (reg.status !== 201)
    throw new Error(`register failed: ${reg.status} ${JSON.stringify(reg.body)}`);
  const login = await api.post('/v1/auth/login', { email, password: STRONG_PASSWORD });
  if (login.status !== 200)
    throw new Error(`login failed: ${login.status} ${JSON.stringify(login.body)}`);
  return {
    id: reg.body.id,
    email,
    password: STRONG_PASSWORD,
    accessToken: login.body.accessToken,
    refreshToken: login.body.refreshToken,
  };
}

export async function loginAdmin(ctx: TestContext): Promise<string> {
  if (!ctx.config.admin)
    throw new Error('ADMIN_EMAIL / ADMIN_PASSWORD must be set for integration tests');
  const res = await client(ctx).post('/v1/auth/login', ctx.config.admin);
  if (res.status !== 200)
    throw new Error(`admin login failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.accessToken as string;
}
