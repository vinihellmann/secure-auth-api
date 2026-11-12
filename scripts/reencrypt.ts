/**
 * KEK rotation: re-wraps every stored data key with the active KEK (KEK_ACTIVE_VERSION).
 *
 * Only the 60-byte wrapped DEK changes; IVs, tags and ciphertexts stay untouched, so the job
 * is cheap and each row is updated independently (safe to interrupt and re-run). After it
 * reports zero remaining rows on the old version, the old kek_<version> secret can be removed.
 *
 *   KEK_ACTIVE_VERSION=2 npm run reencrypt [-- --dry-run]
 */
import { parseArgs } from 'node:util';
import { loadConfig } from '../src/config/env';
import { createEnvelopeCrypto } from '../src/infra/crypto/envelope';
import { initModels } from '../src/infra/db/models';
import { createSequelize } from '../src/infra/db/sequelize';
import { createSecretsProvider } from '../src/infra/secrets';
import { SequelizeMfaRepository } from '../src/modules/mfa/mfa.repository';

const BATCH = 200;

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { 'dry-run': { type: 'boolean', default: false } } });
  const dryRun = values['dry-run'] ?? false;

  const config = loadConfig();
  const envelope = await createEnvelopeCrypto(
    createSecretsProvider(config),
    config.kekActiveVersion,
  );
  const sequelize = createSequelize(config.databaseUrl);
  initModels(sequelize);
  const repo = new SequelizeMfaRepository(sequelize);

  let scanned = 0;
  let rewrapped = 0;
  let after: string | null = null;
  try {
    for (;;) {
      const batch = await repo.listAfter(after, BATCH);
      if (batch.length === 0) break;
      for (const cred of batch) {
        scanned += 1;
        if (envelope.isCurrent(cred.secretEnc)) continue;
        const next = envelope.rewrap(cred.secretEnc);
        if (!dryRun) await repo.updateSecret(cred.userId, next);
        rewrapped += 1;
      }
      after = batch[batch.length - 1]?.userId ?? null;
    }
  } finally {
    await sequelize.close();
  }

  console.log(
    JSON.stringify({ activeKek: envelope.activeKekVersion, scanned, rewrapped, dryRun }, null, 2),
  );
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
