import { promises as fs } from 'node:fs';
import path from 'node:path';
import { SecretNotFoundError, type SecretsProvider } from './provider';

const SAFE_NAME = /^[A-Za-z0-9_.-]+$/;

/**
 * Reads secrets mounted as files, e.g. Docker Compose secrets at /run/secrets/<name>.
 */
export class FileSecretsProvider implements SecretsProvider {
  constructor(private readonly dir: string) {}

  async get(name: string): Promise<string> {
    if (!SAFE_NAME.test(name) || name.includes('..')) {
      throw new SecretNotFoundError(name);
    }
    try {
      const content = await fs.readFile(path.join(this.dir, name), 'utf8');
      return content.trim();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new SecretNotFoundError(name);
      throw err;
    }
  }

  async list(prefix: string): Promise<string[]> {
    let entries: string[];
    try {
      entries = await fs.readdir(this.dir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw err;
    }
    return entries.filter((n) => n.startsWith(prefix) && SAFE_NAME.test(n)).sort();
  }
}
