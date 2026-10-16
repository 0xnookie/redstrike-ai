# Auth attack techniques (shared by auth-bypass / jwt / oauth)
# Use TEST accounts. No real brute-force / no locking out real users. Reset/MFA flows are approval-gated.

## Session management (feeder + auth-bypass)
- Cookie flags: missing `Secure`/`HttpOnly`/`SameSite` (pair with XSS/CSRF).
- **Fixation:** does the session id change on login? If not, a pre-set id survives auth.
- **Logout:** is the token invalidated server-side on logout? (replay after logout)
- Predictable/short tokens; token in URL; "remember me" token strength.

## auth-bypass
- Default/weak creds; username enumeration (timing / message diff).
- Forced browsing: reach an authed page/endpoint without a session (direct URL/API).
- Response tampering: flip `{"success":false}` / `2faRequired:true` client-side gates.
- **2FA/MFA bypass:** skip the 2FA step (go straight to the post-2FA endpoint), reuse/brute the OTP
  (rate-limit permitting — few attempts only), backup-code abuse.
- Password-reset: token predictability, host-header poisoning (→ host-header agent), reuse, no expiry.

## jwt
- `alg:none` (strip signature); accept `{"alg":"none"}`.
- Weak HMAC secret → crack offline (`hashcat`/`jwt_tool`), re-sign tampered claims.
- **Key confusion** RS256→HS256: sign with the public key as the HMAC secret.
- `kid` injection (path/SQL), `jku`/`x5u` pointing to attacker JWKS.
- Claim tampering: `sub`/`role`/`admin`/`exp` — accepted without verification?
- `jwt_tool -t <url> -rc <cookie>` for playbook; confirm the forged token is ACCEPTED.

## oauth / oidc
- `redirect_uri` manipulation (open-redirect in the allowlist → steal `code`/token); `redirect_uri`
  suffix/subdomain/path bypass.
- Missing/replayable `state` → login CSRF / account linking.
- Authorization-code reuse / no PKCE (downgrade) / implicit-flow token in URL fragment leak.
- `id_token` signature / audience (`aud`) / issuer (`iss`) not validated.
- Account takeover via email-unverified OAuth linking.
