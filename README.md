# secure-auth-api

[![CI](https://github.com/vinihellmann/secure-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/vinihellmann/secure-auth-api/actions/workflows/ci.yml)

An authentication service built the way a security review would expect: RS256 access tokens
with a rotating JWKS, opaque refresh tokens with rotation and reuse detection, TOTP two-factor
authentication with anti-replay and single-use recovery codes, envelope encryption for stored
secrets, a hand-written sliding-window rate limiter in Lua, account lockout with exponential
backoff, and an append-only audit log chained with HMAC-SHA256.

Runs entirely with `docker compose up`; key material is generated locally on first start.

**Stack:** Node 22, TypeScript (strict), Express 5, Sequelize 6 + PostgreSQL 16, Redis 7
(ioredis), jsonwebtoken, node:crypto scrypt (bcryptjs kept for legacy hashes), otplib + qrcode, zod, winston, helmet, umzug,
Jest + SWC + supertest, oxlint + prettier.

![scripts/demo.sh: JWT login, refresh reuse detection, TOTP with anti-replay, lockout and the audit chain](docs/demo.gif)

_Recorded with [`scripts/demo.sh`](scripts/demo.sh) against `docker compose up`._

## Contents

- [Architecture](#architecture)
- [Flows](#flows)
- [Design decisions](#design-decisions)
- [Quick start](#quick-start)
- [API overview](#api-overview)
- [Key management and rotation](#key-management-and-rotation)
- [Running the tests](#running-the-tests)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Trade-offs and next steps](#trade-offs-and-next-steps)

## Architecture

```mermaid
flowchart LR
    client([Client])
    rs([Resource servers])

    subgraph api [secure-auth-api]
        mw[helmet, CORS allowlist,<br/>10kb body, timeout,<br/>rate limit, authenticate]
        auth[Auth / Sessions / MFA / Users]
        audit[Audit chain]
    end

    pg[(PostgreSQL<br/>users, sessions,<br/>refresh_tokens, mfa,<br/>audit_events)]
    redis[(Redis<br/>rate limit ZSETs, lockout,<br/>TOTP last step, revoked sessions)]
    secrets[/"/run/secrets<br/>jwt_key_k1, jwt_key_k2, kek_1, mac_key_1"/]

    client --> mw --> auth
    auth --> pg
    auth --> redis
    auth --> audit --> pg
    secrets -. loaded at boot .-> auth
    rs -- "GET /.well-known/jwks.json" --> api
```

Resource servers validate access tokens offline with the JWKS; only this service holds private
keys.

## Flows

Login with two-factor authentication:

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as API
    participant R as Redis
    participant D as Postgres

    C->>A: POST /v1/auth/login {email, password}
    A->>R: lockout check (per email)
    A->>D: find user, scrypt compare (dummy hash if unknown)
    A-->>C: 200 {mfaRequired: true, mfaToken (5 min, RS256, aud=...:mfa)}
    C->>A: POST /v1/auth/login/mfa {mfaToken, code}
    A->>D: decrypt TOTP secret (envelope, AES-256-GCM)
    A->>R: claim time-step (Lua: only if newer than last)
    A->>R: SET NX challenge jti (single use)
    A->>D: create session + refresh token (SHA-256 stored)
    A-->>C: 200 {accessToken (15 min, kid), refreshToken}
```

Refresh rotation and reuse detection:

```mermaid
sequenceDiagram
    autonumber
    participant L as Legitimate client
    participant X as Attacker
    participant A as API
    participant D as Postgres

    L->>A: refresh(R1)
    A->>D: SELECT ... FOR UPDATE R1, insert R2, R1.replaced_by = R2
    A-->>L: R2
    X->>A: refresh(R1) (stolen copy)
    A->>D: R1 already replaced: revoke family and session
    A-->>X: 401 refresh_token_reused
    L->>A: refresh(R2)
    A-->>L: 401 (session revoked, user must log in again)
```

## Design decisions

- **RS256 or ES256 with `kid` and a JWKS.** Asymmetric signing lets other services verify
  tokens without sharing a secret. The algorithm is a property of the key (RSA >= 2048 bits ->
  RS256, EC P-256 -> ES256), derived at load time and never taken from the token: verification
  looks the key up by `kid` and requires `header.alg` to equal that key's algorithm, which rules
  out `alg: none`, HS256-with-public-key and RS256/ES256 swaps. Both kinds can coexist, so moving
  from RSA to EC is just another key rotation. The JWKS publishes an allowlist of public members
  per key type. Two keys are generated so the next key is already published before it becomes
  active.
- **Explicit token types.** Access tokens carry the JOSE header `typ: at+jwt` (RFC 9068) and MFA
  challenge tokens `typ: mfa-challenge+jwt`, in addition to distinct audiences and `token_use`
  claims (RFC 8725 section 3.11), so one kind can never be replayed as the other. Verification
  allows 5 s of clock skew.
- **Short access tokens, opaque refresh tokens.** Access tokens live 15 minutes and are not
  stored. Refresh tokens are 256-bit random strings; only their SHA-256 is stored (a fast hash
  is fine for high-entropy secrets, unlike passwords). Each session is one rotation family.
- **Reuse detection under concurrency.** Rotation runs in a transaction that locks the token
  row (`lock: true`, `SELECT ... FOR UPDATE`). Two simultaneous refreshes with the same token
  are serialized: one wins, the other is treated as reuse and the session is revoked.
- **Immediate revocation.** JWTs cannot be recalled, so revoked session ids are written to
  Redis with a TTL equal to the access token lifetime and checked on every request. Logout,
  password change, admin lock and reuse detection take effect instantly.
- **Algorithm-agile password hashing.** New hashes use scrypt from `node:crypto` (memory-hard,
  runs on the libuv thread pool, no native dependency) in PHC format
  `$scrypt$ln=15,r=8,p=3$<salt>$<hash>`: an OWASP-listed equivalent of N=2^17 that needs 32 MiB per
  hash instead of 128 MiB. Passwords are NFKC-normalized, and there is no 72-byte truncation as
  with bcrypt. Existing bcrypt hashes still verify and are re-hashed transparently on the next
  successful login (`password_rehashed` audit event); the same happens when the scrypt
  parameters are raised. Each algorithm is a strategy selected by hash prefix.
- **No user enumeration.** Unknown emails go through a comparison against a dummy hash of the
  primary algorithm, receive the same error body, and are locked out exactly like real accounts.
- **Re-authentication lockout.** Changing the password and disabling 2FA require the current
  password, and failures there have their own per-user lockout (`reauth:<userId>`), so a stolen
  access token cannot be used to brute-force the password behind it.
- **Lockout with exponential backoff.** 5 failures lock the account for 30 s, doubling per
  further failure up to 15 minutes. Separate from the per-IP rate limit: one stops credential
  stuffing across IPs, the other stops one IP spraying many accounts.
- **Sliding-window rate limiter in Lua.** A sorted set of timestamps per key, trimmed and
  counted atomically in one script (`defineCommand`), using Redis `TIME` so app server clock
  skew does not matter. No burst at window edges, unlike a fixed window. Policies per route;
  responses carry `RateLimit-*` headers and `Retry-After` on 429. IPv6 clients are bucketed by
  their /64 (a single host usually controls the whole prefix and could otherwise rotate
  addresses forever), and IPv4-mapped IPv6 shares the IPv4 bucket.
- **TOTP with anti-replay.** A code is valid for about 90 s (one step of drift each way). The
  last accepted time-step per user is stored in Redis and only strictly newer steps pass, so a
  code cannot be used twice, even within its window.
- **Recovery codes.** Ten codes, about 50 bits each. About 50 bits is too little for an unkeyed
  hash: after a database leak, a GPU could crack unsalted SHA-256 values offline for every user
  at once. So they are stored as `m1.<keyVersion>.HMAC-SHA256(key, userId | code)` with a
  server-side key. They are consumed with a single conditional
  `UPDATE ... WHERE code_hash IN (...) AND used_at IS NULL`, so two concurrent uses cannot both
  succeed. Codes issued before this scheme (plain SHA-256) are still accepted until used.
- **Envelope encryption for stored secrets.** Each value gets its own random data key (DEK);
  the DEK is wrapped by a versioned key-encryption key (KEK). Both layers are AES-256-GCM. The
  data layer's associated data binds the ciphertext to its owner (`mfa:<userId>`), so a value
  copied to another row does not decrypt. Rotating the KEK only re-wraps 60-byte DEKs.
- **Tamper-evident audit log, keyed.** Each event stores `prev_hash`, `mac_key_id` and
  `hash = HMAC-SHA256(key, canonical JSON of the event + prev_hash + mac_key_id)`. An unkeyed
  SHA-256 chain only stops accidents: anyone with owner rights can rewrite a row and recompute
  every later hash. With a key held only by the application, that rewrite is detectable.
  Appends take `pg_advisory_xact_lock` so the chain cannot fork under concurrency. A trigger
  rejects `UPDATE`, `DELETE` and `TRUNCATE`; if someone disables it, `/verify` pinpoints the
  first broken link.
- **Downgrade-proof cut-over.** Databases that predate keyed chaining keep their unkeyed rows.
  Migration 004 records the last legacy id in `audit_chain_anchor`, signed with the MAC key, and
  every later row must be keyed. An attacker therefore cannot relabel keyed rows as legacy and
  recompute them, and deleting or editing the anchor fails verification instead of hiding
  anything. The first keyed row's `prev_hash` commits to the whole legacy prefix.
- **One root key, many purposes.** `mac_key_<version>` is never used directly. HKDF-SHA256
  derives a subkey per purpose (`audit-chain`, `audit-anchor`, `recovery-code`), so a MAC made
  for one purpose is meaningless for another. It is kept separate from the KEK, so integrity
  keys and encryption keys rotate independently.
- **Secrets behind an interface.** `SecretsProvider` has a file implementation (Docker secrets
  layout under `/run/secrets`) and an env implementation for tests. A cloud secret manager is
  one new class; key discovery by prefix (`jwt_key_*`, `kek_*`, `mac_key_*`) makes rotation a
  data change.
- **Thin HTTP layer.** Each module owns a `*.routes.ts` that declares its routes with a shared
  `RouteKit` (authenticate, role check, rate limit). `authed()` handlers receive a typed
  `req.auth` and fail closed if a route is ever mounted without authentication. Controllers only
  parse, call a service and shape the response; audit events are recorded by services.
- **Fail-fast production config.** In `NODE_ENV=production` the boot refuses `env` secrets,
  disabled rate limiting and `SCRYPT_LOG_N < 14`. Logs go through a redaction format that masks
  passwords, tokens, secrets, cookies and OTP-looking codes even if a call site logs too much.
- **Hardening defaults.** helmet, CORS allowlist, 10kb JSON bodies, per-request timeout,
  `Cache-Control: no-store` on token responses, `trust proxy` explicit, problem+json errors
  that never leak internals, configuration validated by zod at boot.

## Quick start

Requirements: Docker with Compose v2, `curl`, `jq`.

```bash
docker compose up -d --build     # keygen -> migrate (+ admin seed) -> api on :3001
curl -s localhost:3001/ready | jq
curl -s localhost:3001/.well-known/jwks.json | jq '.keys[].kid'
```

Run the whole walkthrough at once (tokens, refresh reuse, 2FA, lockout, audit chain):

```bash
./scripts/demo.sh                # DEMO_PAUSE=0 to skip the pauses
```

Register, log in, use and rotate tokens:

```bash
API=http://localhost:3001
EMAIL="dev-$(date +%s)@example.com"
PASSWORD='Correct-Horse-9-Battery'

curl -s -X POST $API/v1/auth/register -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq

LOGIN=$(curl -s -X POST $API/v1/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
ACCESS=$(echo "$LOGIN" | jq -r .accessToken)
REFRESH=$(echo "$LOGIN" | jq -r .refreshToken)

curl -s $API/v1/me -H "Authorization: Bearer $ACCESS" | jq
curl -s $API/v1/sessions -H "Authorization: Bearer $ACCESS" | jq

# Rotate, then replay the old refresh token: the session is revoked.
curl -s -X POST $API/v1/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}" | jq '{accessToken, refreshToken}'
curl -s -X POST $API/v1/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}" | jq '{status, code}'
```

Enable 2FA (scan `qrCodeDataUrl` or type `secret` into any authenticator app):

```bash
LOGIN=$(curl -s -X POST $API/v1/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
ACCESS=$(echo "$LOGIN" | jq -r .accessToken)

curl -s -X POST $API/v1/mfa/totp/setup -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d "{\"password\":\"$PASSWORD\"}" | jq '{otpauthUri, secret}'
curl -s -X POST $API/v1/mfa/totp/enable -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}' | jq   # code from the app
```

Audit log (admin seeded from `ADMIN_EMAIL` / `ADMIN_PASSWORD`):

```bash
ADMIN=$(curl -s -X POST $API/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"ChangeMe-Admin-123!"}' | jq -r .accessToken)
curl -s "$API/v1/admin/audit-events?limit=5" -H "Authorization: Bearer $ADMIN" | jq
curl -s $API/v1/admin/audit-events/verify -H "Authorization: Bearer $ADMIN" | jq
```

Interactive reference: http://localhost:3001/docs (OpenAPI document at `/openapi.yaml`).

## API overview

| Method | Path                                 | Auth   | Notes                                               |
| ------ | ------------------------------------ | ------ | --------------------------------------------------- |
| POST   | `/v1/auth/register`                  | -      | 5/hour per IP                                       |
| POST   | `/v1/auth/login`                     | -      | 10/min per IP + per-account lockout                 |
| POST   | `/v1/auth/login/mfa`                 | -      | `mfaToken` + `code` or `recoveryCode`               |
| POST   | `/v1/auth/refresh`                   | -      | rotation, reuse detection                           |
| POST   | `/v1/auth/logout`                    | Bearer | revokes the current session                         |
| GET    | `/v1/me`                             | Bearer |                                                     |
| POST   | `/v1/me/password`                    | Bearer | revokes all other sessions                          |
| GET    | `/v1/sessions`                       | Bearer |                                                     |
| DELETE | `/v1/sessions/:id`                   | Bearer |                                                     |
| POST   | `/v1/mfa/totp/setup`                 | Bearer | password; otpauth URI + QR, secret stored encrypted |
| POST   | `/v1/mfa/totp/enable`                | Bearer | returns 10 recovery codes once                      |
| POST   | `/v1/mfa/totp/disable`               | Bearer | password + second factor                            |
| GET    | `/v1/admin/audit-events`             | admin  | filters, cursor pagination                          |
| GET    | `/v1/admin/audit-events/verify`      | admin  | walks the whole chain                               |
| POST   | `/v1/admin/users/:id/lock`, `unlock` | admin  | lock revokes all sessions                           |
| GET    | `/.well-known/jwks.json`             | -      | all loaded public keys                              |
| GET    | `/health`, `/ready`                  | -      |                                                     |

## Key management and rotation

`keygen` (one-shot Compose service, also `npm run keygen`) writes one file per secret into
`./secrets`, which is git-ignored and mounted read-only at `/run/secrets`:

| File         | Content                                                        |
| ------------ | -------------------------------------------------------------- |
| `jwt_key_k1` | RSA-2048 (or EC P-256 with `--alg ES256`) PKCS#8 PEM (active)  |
| `jwt_key_k2` | next signing key, already in the JWKS                          |
| `kek_1`      | 32 random bytes, base64 (active KEK)                           |
| `mac_key_1`  | 32 random bytes, base64 (HMAC root key: audit chain, recovery) |

Signing key rotation: set `JWT_ACTIVE_KID=k2` and restart. Tokens signed by `k1` stay valid
until they expire because `k1` is still loaded; remove `jwt_key_k1` after 15 minutes and add
`k3` as the next pre-published key (`npm run keygen -- --kid k3`, add `--alg ES256` for an
EC key).

MAC key rotation: generate `mac_key_2` (`--mac 2`), set `MAC_ACTIVE_VERSION=2` and restart.
Keep `mac_key_1` loaded for as long as audit rows or recovery codes made with it exist (audit
rows forever), because every row records the key version it was made with.

Upgrading an existing deployment: run `keygen` (it only adds the missing `mac_key_1`), then
`migrate` with the secrets mounted, so migration 004 can sign the audit cut-over anchor. Deploy
with `JWT_REQUIRE_TYP=false`; access tokens issued before the upgrade have no `at+jwt` type.
Switch it back to `true` after one access-token lifetime.

KEK rotation: generate `kek_2` (`--kek 2`), set `KEK_ACTIVE_VERSION=2`, restart, then run the
re-wrap job and remove `kek_1` once it reports nothing left on the old version:

```bash
docker compose run --rm api node dist/scripts/reencrypt.js --dry-run
docker compose run --rm api node dist/scripts/reencrypt.js
```

Envelope format (one ASCII string, safe in a `text` column):

```text
v1.<kekVersion>.<wrappedDek>.<iv>.<tag>.<ciphertext>
   wrappedDek = base64url(wrapIv[12] | wrapTag[16] | encryptedDek[32])
   iv, tag, ciphertext = base64url, AES-256-GCM over the plaintext with AAD "v1|ctx|<context>"
```

## Running the tests

```bash
npm install
npm run test:unit       # no services needed

npm run test:docker     # integration suite inside the compose network
# equivalent to:
docker compose -f docker-compose.yml -f docker-compose.test.yml run --build --rm test
```

Unit tests cover envelope encryption and tampering of every segment, the hash chain (edits,
deletions, forged links, recomputed unkeyed hashes, downgrade below the cut-over anchor), HMAC
subkey separation, scrypt hashing and legacy bcrypt upgrade, re-authentication lockout, token
signing and `kid` rotation (including alg confusion, ES256 and `typ`), IPv6 rate-limit keying,
log redaction, production config guards, lockout backoff, TOTP anti-replay and the RFC 6238 test
vector.

Integration tests run against real Postgres and Redis: refresh rotation and reuse detection,
concurrent refreshes, 429 with `Retry-After`, account lockout and enumeration resistance, the
full 2FA flow, single-use recovery codes, revoked sessions rejecting live access tokens,
password change revoking other sessions, RBAC, and audit chain verification catching a row
rewritten with the trigger disabled.

CI runs lint, typecheck, build, unit tests and a formatting check on Node 22, and the
integration suite through Docker Compose.

## Configuration

Validated with zod at boot; see [`.env.example`](.env.example). Highlights:

| Variable                       | Default  | Purpose                                    |
| ------------------------------ | -------- | ------------------------------------------ |
| `SECRETS_PROVIDER`             | `file`   | `file` (`SECRETS_DIR`) or `env` (tests)    |
| `JWT_ACTIVE_KID`               | `k1`     | signing key                                |
| `KEK_ACTIVE_VERSION`           | `1`      | KEK for new encryptions and re-wrapping    |
| `ACCESS_TOKEN_TTL_SECONDS`     | `900`    |                                            |
| `REFRESH_TOKEN_TTL_DAYS`       | `30`     |                                            |
| `MAC_ACTIVE_VERSION`           | `1`      | HMAC key for new audit rows/recovery codes |
| `SCRYPT_LOG_N` / `_R` / `_P`   | `15/8/3` | password hashing work factor               |
| `JWT_REQUIRE_TYP`              | `true`   | `false` only during the typ upgrade window |
| `TRUST_PROXY`                  | `false`  | set correctly behind a proxy (rate limits) |
| `CORS_ORIGINS`                 | empty    | comma-separated allowlist                  |
| `ADMIN_EMAIL`/`ADMIN_PASSWORD` | unset    | idempotent admin seed by `migrate`         |

## Project structure

```text
src/
  server.ts            entrypoint, graceful shutdown
  container.ts         composition root
  config/env.ts        zod-validated configuration
  http/                app, RouteKit, authed() handlers, client IP keying, middleware
  infra/
    crypto/            envelope encryption, JWT key store (RS256/ES256), HMAC keyring, hashing
    db/                Sequelize, models, umzug migrations (incl. audit trigger)
    rate-limit/        sliding-window limiter (Lua)
    redis/             client, stores (lockout, TOTP step, revoked sessions, MFA challenges)
    secrets/           SecretsProvider + file and env implementations
  modules/
    auth/              login, MFA step, refresh, logout, tokens, lockout (each module: *.routes.ts)
    sessions/          sessions and refresh token rotation
    mfa/               TOTP, recovery codes, enrollment
    users/             registration, profile, password change, admin lock, seed, password hashing
    audit/             HMAC chain, cut-over anchor, repository, verification
scripts/               generate-secrets (keygen), migrate (+ seed), reencrypt
test/unit, test/integration
```

## Trade-offs and next steps

- **Account lockout can be abused for denial of service** against a known email. Backoff caps
  the damage at 15 minutes; a CAPTCHA or proof-of-work after a few failures would avoid
  locking real users out.
- **Revocation depends on Redis.** If Redis loses data, revoked sessions regain access until
  their access tokens expire (at most 15 minutes). Persisting the revocation list or shortening
  token lifetime are the knobs.
- **The audit chain proves integrity, not completeness after the fact.** Someone with database
  owner rights could truncate the tail without forging anything; anchoring the head hash
  periodically (to object storage with object lock or a transparency log) closes that gap. The
  MAC key lives in the application, so a compromise of the app host (not just the database)
  can still forge rows; a KMS-held key would narrow that.
- **State change and audit event are separate transactions.** If the audit append fails after
  a committed change, the request errors but the change stays. A transactional outbox would
  make them atomic at the cost of holding the chain lock longer.
- **Strict reuse detection** revokes the session when a client legitimately retries a refresh
  after a network failure. A short grace period for the immediately previous token is a common
  relaxation.
- **Secrets in files.** Fine for Compose and Swarm; in production prefer a KMS so KEKs never
  leave the HSM (the `SecretsProvider` and envelope layers are already shaped for it).
- **Next:** WebAuthn/passkeys, email verification and password reset flows, OpenTelemetry
  traces, and per-tenant rate limit policies.

## License

[MIT](LICENSE)
