import { createPrivateKey, createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import type { SecretsProvider } from '../secrets/provider';

export type JwtAlg = 'RS256' | 'ES256';

export interface JwtKey {
  kid: string;
  /**
   * Pinned to the key material at load time (RSA -> RS256, P-256 -> ES256). Tokens never get a
   * say: sign uses this value and verify rejects any token whose header disagrees with it.
   */
  alg: JwtAlg;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export type PublicJwk = JsonWebKey & { kid: string; use: 'sig'; alg: JwtAlg };

/**
 * Public JWK members we are willing to publish, per key type. An allowlist (rather than a
 * denylist of d/p/q/...) means a future export quirk can never leak private material.
 */
const PUBLIC_MEMBERS: Record<JwtAlg, readonly string[]> = {
  RS256: ['kty', 'n', 'e'],
  ES256: ['kty', 'crv', 'x', 'y'],
};

/** Derives the signing algorithm from the key itself; rejects anything we do not support. */
export function keyFromPem(kid: string, privatePem: string): JwtKey {
  const privateKey = createPrivateKey(privatePem);
  const type = privateKey.asymmetricKeyType;
  const details = privateKey.asymmetricKeyDetails;
  let alg: JwtAlg;
  if (type === 'rsa') {
    if ((details?.modulusLength ?? 0) < 2048) {
      throw new Error(`JWT key "${kid}" must be at least 2048 bits`);
    }
    alg = 'RS256';
  } else if (type === 'ec') {
    // ES256 is defined only for P-256 (RFC 7518 §3.4); other curves need other algs.
    if (details?.namedCurve !== 'prime256v1') {
      throw new Error(
        `JWT key "${kid}" uses unsupported EC curve "${details?.namedCurve ?? 'unknown'}" (only P-256 / ES256)`,
      );
    }
    alg = 'ES256';
  } else {
    throw new Error(
      `JWT key "${kid}" has unsupported type "${type ?? 'unknown'}" (expected RSA >= 2048 bits or EC P-256)`,
    );
  }
  return { kid, alg, privateKey, publicKey: createPublicKey(privateKey) };
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

  /** JWKS document: public keys only, restricted to the public members of each key type. */
  jwks(): { keys: PublicJwk[] } {
    const keys = [...this.byKid.values()].map((k) => {
      const exported = k.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const pub: Record<string, unknown> = {};
      for (const member of PUBLIC_MEMBERS[k.alg]) pub[member] = exported[member];
      return { ...pub, kid: k.kid, use: 'sig' as const, alg: k.alg } as PublicJwk;
    });
    return { keys };
  }
}

const JWT_SECRET_PREFIX = 'jwt_key_';

export async function loadKeyStore(secrets: SecretsProvider, activeKid: string): Promise<KeyStore> {
  const names = await secrets.list(JWT_SECRET_PREFIX);
  const keys: JwtKey[] = [];
  for (const name of names) {
    keys.push(keyFromPem(name.slice(JWT_SECRET_PREFIX.length), await secrets.get(name)));
  }
  if (keys.length === 0) throw new Error('No JWT key secrets found (expected jwt_key_<kid>)');
  return new KeyStore(keys, activeKid);
}
