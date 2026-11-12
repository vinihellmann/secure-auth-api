import { ConfigError, loadConfig } from '../../src/config/env';

const base = {
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  REDIS_URL: 'redis://localhost:6379/0',
};

describe('configuration', () => {
  it('applies secure defaults', () => {
    const config = loadConfig(base);
    expect(config.scrypt).toEqual({ logN: 15, r: 8, p: 3 });
    expect(config.macActiveVersion).toBe('1');
    expect(config.rateLimitEnabled).toBe(true);
  });

  it('accepts test-friendly settings outside production', () => {
    const config = loadConfig({
      ...base,
      NODE_ENV: 'test',
      SECRETS_PROVIDER: 'env',
      RATE_LIMIT_ENABLED: 'false',
      SCRYPT_LOG_N: '10',
    });
    expect(config.secrets.provider).toBe('env');
    expect(config.scrypt.logN).toBe(10);
  });

  it.each([
    ['SECRETS_PROVIDER', 'env'],
    ['RATE_LIMIT_ENABLED', 'false'],
    ['SCRYPT_LOG_N', '12'],
  ])('refuses to boot in production with %s=%s', (key, value) => {
    expect(() => loadConfig({ ...base, NODE_ENV: 'production', [key]: value })).toThrow(
      new RegExp(key),
    );
  });

  it('reports every problem at once', () => {
    const load = () => loadConfig({ NODE_ENV: 'production', SECRETS_PROVIDER: 'env' });
    expect(load).toThrow(ConfigError);
    expect(load).toThrow(/DATABASE_URL[\s\S]*REDIS_URL/);
  });
});
