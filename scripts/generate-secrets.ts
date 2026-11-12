/**
 * Generates the key material the API needs, in Docker-secrets layout (one file per secret):
 *
 *   jwt_key_<kid>    RSA-2048 private key (PKCS#8 PEM) used for RS256; public part is in the JWKS
 *   kek_<version>    32 random bytes, base64: key-encryption key for envelope encryption
 *
 * Idempotent: existing files are never overwritten, so re-running is safe. Rotation is
 * "add a new kid / KEK version here, then flip JWT_ACTIVE_KID / KEK_ACTIVE_VERSION".
 *
 *   npm run keygen -- --out ./secrets --kid k1 --kid k2 --kek 1 [--owner 1000:1000]
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { chownSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    out: { type: 'string', default: './secrets' },
    kid: { type: 'string', multiple: true },
    kek: { type: 'string', multiple: true },
    owner: { type: 'string' },
  },
});

const outDir = path.resolve(values.out ?? './secrets');
const kids = values.kid?.length ? values.kid : ['k1', 'k2'];
const keks = values.kek?.length ? values.kek : ['1'];
const NAME = /^[A-Za-z0-9_-]+$/;

function parseOwner(raw: string | undefined): { uid: number; gid: number } | null {
  if (!raw) return null;
  const match = /^(\d+):(\d+)$/.exec(raw);
  if (!match) throw new Error('--owner must look like 1000:1000');
  return { uid: Number(match[1]), gid: Number(match[2]) };
}
const owner = parseOwner(values.owner);
const canChown = owner !== null && process.getuid?.() === 0;

function writeSecret(name: string, create: () => string): void {
  const file = path.join(outDir, name);
  if (existsSync(file)) {
    console.log(`kept      ${name}`);
    return;
  }
  writeFileSync(file, create(), { mode: 0o400, flag: 'wx' });
  if (canChown && owner) chownSync(file, owner.uid, owner.gid);
  console.log(`generated ${name}`);
}

mkdirSync(outDir, { recursive: true, mode: 0o700 });
if (canChown && owner) chownSync(outDir, owner.uid, owner.gid);

for (const kid of kids) {
  if (!NAME.test(kid)) throw new Error(`invalid kid "${kid}"`);
  writeSecret(`jwt_key_${kid}`, () =>
    generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string,
  );
}
for (const version of keks) {
  if (!NAME.test(version)) throw new Error(`invalid KEK version "${version}"`);
  writeSecret(`kek_${version}`, () => randomBytes(32).toString('base64'));
}

console.log(`secrets directory: ${outDir}`);
