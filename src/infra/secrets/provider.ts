export class SecretNotFoundError extends Error {
  constructor(name: string) {
    super(`Secret "${name}" not found`);
    this.name = 'SecretNotFoundError';
  }
}

/**
 * Abstraction over where secrets live.
 *
 * Implementations shipped here: FileSecretsProvider (Docker/Compose secrets under
 * /run/secrets) and EnvSecretsProvider (tests). To use a cloud secret manager
 * (AWS Secrets Manager, GCP Secret Manager, Vault, ...) implement this interface:
 *  - get(name): fetch one secret value by name;
 *  - list(prefix): return the names of all secrets starting with the prefix
 *    (the app discovers `jwt_key_<kid>` and `kek_<version>` that way, which is what
 *    makes key rotation a pure "add a secret, flip the active id" operation).
 * Then select it in src/infra/secrets/index.ts. No other code changes are needed.
 */
export interface SecretsProvider {
  get(name: string): Promise<string>;
  list(prefix: string): Promise<string[]>;
}
