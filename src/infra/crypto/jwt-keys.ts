import { createPrivateKey, createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import type { SecretsProvider } from '../secrets/provider';

export interface JwtKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export type PublicJwk = JsonWebKey & { kid: string; use: 'sig'; alg: 'RS256' };

export function keyFromPem(kid: string, privatePem: string): JwtKey {
  const privateKey = createPrivateKey(privatePem);
  if (privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error(`JWT key "${kid}" must be an RSA key`);
  }
  const bits = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
  if (bits < 2048) throw new Error(`JWT key "${kid}" must be at least 2048 bits`);
  return { kid, privateKey, publicKey: createPublicKey(privateKey) };
}

/**
 * Holds all verification keys plus the one active signing key.
 * Rotation: add a new key, switch the active kid, keep the old key published
 * until all tokens signed with it have expired, then remove it.
 */
export class KeyStore {
  private readonly byKid = new Map<string, JwtKey>();

  constructor(
    keys: JwtKey[],
    private readonly activeKid: string,
  ) {
    for (const k of keys) this.byKid.set(k.kid, k);
    if (!this.byKid.has(activeKid)) {
      throw new Error(`Active JWT key "${activeKid}" is not loaded`);
    }
  }

  get active(): JwtKey {
    return this.byKid.get(this.activeKid) as JwtKey;
  }

  get(kid: string): JwtKey | undefined {
    return this.byKid.get(kid);
  }

  /** JWKS document: public keys only, built from the RSA public key (n, e). */
  jwks(): { keys: PublicJwk[] } {
    const keys = [...this.byKid.values()].map((k) => ({
      ...k.publicKey.export({ format: 'jwk' }),
      kid: k.kid,
      use: 'sig' as const,
      alg: 'RS256' as const,
    }));
    return { keys };
  }
}

const JWT_SECRET_PREFIX = 'jwt_key_';

export async function loadKeyStore(
  secrets: SecretsProvider,
  activeKid: string,
): Promise<KeyStore> {
  const names = await secrets.list(JWT_SECRET_PREFIX);
  const keys: JwtKey[] = [];
  for (const name of names) {
    keys.push(keyFromPem(name.slice(JWT_SECRET_PREFIX.length), await secrets.get(name)));
  }
  if (keys.length === 0) throw new Error('No JWT key secrets found (expected jwt_key_<kid>)');
  return new KeyStore(keys, activeKid);
}
