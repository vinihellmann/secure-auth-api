#!/usr/bin/env bash
# End-to-end walkthrough against the local stack: registration, RS256 tokens, refresh rotation with
# reuse detection, TOTP 2FA with anti-replay, recovery codes, account lockout and the audit chain.
#
#   docker compose up -d --build
#   ./scripts/demo.sh                 # DEMO_PAUSE=1 by default
#
# Requires bash, curl, jq and docker (TOTP codes are computed with otplib inside the api container,
# standing in for an authenticator app). Run from the repository root. Registration is limited to
# 5 per hour per IP, so the demo can run about five times an hour against the same stack.
set -euo pipefail

API=${API:-http://localhost:3001}
PAUSE=${DEMO_PAUSE:-1}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-ChangeMe-Admin-123!}

for bin in curl jq docker; do command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }; done

bold=$'\e[1m' dim=$'\e[2m' cyan=$'\e[36m' green=$'\e[32m' yellow=$'\e[33m' red=$'\e[31m' reset=$'\e[0m'
n=0
# jq on Windows prints CRLF; strip it so captured values stay clean.
jqr() { jq "$@" | tr -d '\r'; }
step() { n=$((n + 1)); printf '\n%s%s[%d] %s%s\n' "$bold" "$cyan" "$n" "$1" "$reset"; }
say() { printf '%s%s%s\n' "$dim" "$*" "$reset"; }
pause() { sleep "$PAUSE"; }
status() {
  local c=$1 color=$green
  ((c >= 400)) && color=$red
  ((c >= 300 && c < 400)) && color=$yellow
  printf '%s%s → %s%s%s\n' "$bold" "$2" "$color" "$c" "$reset"
}
# call METHOD PATH [JSON] [TOKEN]: prints the status line and leaves the body in $BODY.
call() {
  local method=$1 path=$2 data=${3:-} token=${4:-} out
  local args=(-sS -X "$method" "$API$path" -w '\n%{http_code}')
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  [[ -n $token ]] && args+=(-H "Authorization: Bearer $token")
  out=$(curl "${args[@]}")
  BODY=${out%$'\n'*}
  CODE=${out##*$'\n'}
  status "$CODE" "$method $path"
}
problem() { jqr -C '{status, code, title}' <<<"$BODY"; }
b64url() {
  local s=${1//-/+}
  s=${s//_//}
  while ((${#s} % 4)); do s+='='; done
  base64 -d <<<"$s" 2>/dev/null
}
totp() { docker compose exec -T api node -e 'console.log(require("otplib").authenticator.generate(process.argv[1]))' "$1" | tr -d '\r'; }
wait_next_step() {
  local left=$((30 - $(date +%s) % 30 + 1))
  say "(waiting ${left}s for the next 30 s TOTP window: each window's code is accepted once)"
  sleep "$left"
}

EMAIL="demo-$(date +%s)@example.com"
PASSWORD='Correct-Horse-9-Battery'
login() { call POST /v1/auth/login "{\"email\":\"$1\",\"password\":\"$2\"}"; }

step "Health and public keys"
call GET /ready
jqr -C -c . <<<"$BODY"
call GET /.well-known/jwks.json
say "Resource servers verify tokens offline with these public keys: k1 signs, k2 is pre-published."
jqr -C -c '.keys[] | {kid, kty, alg, use}' <<<"$BODY"
pause

step "Register"
call POST /v1/auth/register "{\"email\":\"$EMAIL\",\"password\":\"123\"}"
problem
call POST /v1/auth/register "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
say "The password is stored with scrypt; nothing sensitive is returned."
jqr -C . <<<"$BODY"
pause

step "Log in"
login "$EMAIL" "$PASSWORD"
ACCESS=$(jqr -r .accessToken <<<"$BODY")
R1=$(jqr -r .refreshToken <<<"$BODY")
say "Access token (15 min, signed with the key named by kid) + opaque refresh token (only its SHA-256 is stored):"
b64url "$(cut -d. -f1 <<<"$ACCESS")" | jqr -C -c .
b64url "$(cut -d. -f2 <<<"$ACCESS")" | jqr -C '{sub, sid, roles, aud, token_use, exp}'
call GET /v1/me "" "$ACCESS"
jqr -C -c . <<<"$BODY"
call GET /v1/me "" "${ACCESS%???}AAA"
say "One byte changed in the signature: rejected."
pause

step "Enable TOTP two-factor authentication"
call POST /v1/mfa/totp/setup "{\"password\":\"$PASSWORD\"}" "$ACCESS"
SECRET=$(jqr -r .secret <<<"$BODY")
say "The secret is stored encrypted (envelope encryption, AES-256-GCM); the QR code goes to the app."
jqr -C '{otpauthUri, secret, qrCodeDataUrl: (.qrCodeDataUrl[0:40] + "…")}' <<<"$BODY"
CODE1=$(totp "$SECRET")
call POST /v1/mfa/totp/enable "{\"code\":\"$CODE1\"}" "$ACCESS"
RECOVERY=$(jqr -r '.recoveryCodes[0]' <<<"$BODY")
say "Ten single-use recovery codes, shown once:"
jqr -C -c '.recoveryCodes[0:3] + ["…"]' <<<"$BODY"
pause

step "Refresh rotation and reuse detection"
call POST /v1/auth/refresh "{\"refreshToken\":\"$R1\"}"
R2=$(jqr -r .refreshToken <<<"$BODY")
say "R1 was exchanged for R2. Now an attacker replays the stolen R1:"
call POST /v1/auth/refresh "{\"refreshToken\":\"$R1\"}"
problem
say "Reuse revokes the whole session, so even the legitimate R2 stops working:"
call POST /v1/auth/refresh "{\"refreshToken\":\"$R2\"}"
problem
pause

step "Log in with the second factor"
wait_next_step
login "$EMAIL" "$PASSWORD"
say "The password alone is no longer enough:"
jqr -C '{mfaRequired, mfaToken: (.mfaToken[0:24] + "…"), mfaTokenExpiresIn}' <<<"$BODY"
MFA=$(jqr -r .mfaToken <<<"$BODY")
CODE2=$(totp "$SECRET")
call POST /v1/auth/login/mfa "{\"mfaToken\":\"$MFA\",\"code\":\"$CODE2\"}"
jqr -C '{tokenType, expiresIn, accessToken: (.accessToken[0:24] + "…")}' <<<"$BODY"
pause

step "Replayed TOTP code and recovery code"
login "$EMAIL" "$PASSWORD"
MFA=$(jqr -r .mfaToken <<<"$BODY")
say "Same code $CODE2 again, still inside its 30 s window: a Redis Lua script only accepts newer steps."
call POST /v1/auth/login/mfa "{\"mfaToken\":\"$MFA\",\"code\":\"$CODE2\"}"
problem
say "Lost phone? A recovery code works once:"
call POST /v1/auth/login/mfa "{\"mfaToken\":\"$MFA\",\"recoveryCode\":\"$RECOVERY\"}"
USER_ACCESS=$(jqr -r .accessToken <<<"$BODY")
jqr -C '{tokenType, expiresIn}' <<<"$BODY"
pause

login "$ADMIN_EMAIL" "$ADMIN_PASSWORD" >/dev/null
ADMIN=$(jqr -r .accessToken <<<"$BODY")

step "Brute force: account lockout"
say "Failures are counted per email (known or not, so lockout reveals nothing); the 5th locks for 30 s, doubling after."
for i in 1 2 3 4 5; do
  login "$EMAIL" "wrong-password-$i" >/dev/null
  printf '  attempt %d → %s %s\n' "$i" "$CODE" "$(jqr -r .code <<<"$BODY")"
done
login "$EMAIL" "$PASSWORD"
say "Even the correct password is refused while locked:"
problem
pause

step "Audit log (admin)"
call GET '/v1/admin/audit-events?limit=6' "" "$ADMIN"
jqr -C -c '.items | reverse[] | {id, eventType, prevHash: (.prevHash[0:12] + "…"), hash: (.hash[0:12] + "…")}' <<<"$BODY"
say "Every event is chained to the previous one with HMAC-SHA256; tampering with a row breaks it:"
call GET /v1/admin/audit-events/verify "" "$ADMIN"
jqr -C -c . <<<"$BODY"
call GET '/v1/admin/audit-events?limit=1' "" "$USER_ACCESS"
say "Regular users get 403."

step "Done"
say "Interactive API reference: $API/docs"
