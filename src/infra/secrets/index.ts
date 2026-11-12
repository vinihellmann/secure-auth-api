import type { AppConfig } from '../../config/env';
import { EnvSecretsProvider } from './env-provider';
import { FileSecretsProvider } from './file-provider';
import type { SecretsProvider } from './provider';

export * from './provider';
export { EnvSecretsProvider } from './env-provider';
export { FileSecretsProvider } from './file-provider';

/**
 * Single place that selects the provider. Add a cloud implementation here.
 */
export function createSecretsProvider(config: AppConfig): SecretsProvider {
  switch (config.secrets.provider) {
    case 'file':
      return new FileSecretsProvider(config.secrets.dir);
    case 'env':
      return new EnvSecretsProvider();
  }
}
