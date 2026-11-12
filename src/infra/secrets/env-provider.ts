import { SecretNotFoundError, type SecretsProvider } from './provider';

const ENV_PREFIX = 'SECRET_';

/**
 * Reads secrets from environment variables named SECRET_<NAME_UPPERCASED>.
 * Intended for tests and throwaway setups only: environment variables leak
 * through process listings, crash dumps and child processes.
 */
export class EnvSecretsProvider implements SecretsProvider {
  constructor(private readonly env: Record<string, string | undefined> = process.env) {}

  async get(name: string): Promise<string> {
    const value = this.env[`${ENV_PREFIX}${name.toUpperCase()}`];
    if (value === undefined || value === '') throw new SecretNotFoundError(name);
    return value.trim();
  }

  async list(prefix: string): Promise<string[]> {
    const wanted = `${ENV_PREFIX}${prefix.toUpperCase()}`;
    return Object.keys(this.env)
      .filter((k) => k.startsWith(wanted) && this.env[k])
      .map((k) => k.slice(ENV_PREFIX.length).toLowerCase())
      .sort();
  }
}
