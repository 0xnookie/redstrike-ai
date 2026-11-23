# SAML as an authentication bypass — signing oracles, ACS testing, RelayState
# Authorized, in-scope SSO only. TEST accounts; benign proof (reach a TEST-only authenticated state, then
# stop). Approval-gated. SAML XML-signature-wrapping / XXE on the parser are their own deep topics — this ref
# covers SAML used to BYPASS authentication: forging or replaying an assertion the SP will trust.

## The signing-oracle idea
SAML trust rests on a signature: the SP accepts an assertion because the IdP signed it. The bypass is to find
an endpoint that will **sign an assertion for you without authenticating you first** — a "signing oracle".
If an unauthenticated SP-initiated or IdP endpoint hands back a *signed* SAML Response, you can craft an
assertion naming any `NameID`/subject, get it signed, and POST it to the Assertion Consumer Service (ACS) to
log in as that subject — no password, no real IdP session.

## 1. Probe for an unauthenticated signing endpoint
Look for endpoints whose path contains `SSO`, `SAML`, `SingleSignOn`, `GenerateSAMLResponse`, `saml/sso`.
Hit the SP-initiated SSO endpoint with no session and see if it returns a signed assertion:

```bash
# Does the SSO endpoint sign without an authenticated session?
curl -s -X POST 'https://TARGET/saml/sso' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'status={"primaryCode":"urn:oasis:names:tc:SAML:2.0:status:Success"}'
# A SIGNED <saml:Response>/<saml:Assertion> in the body => signing oracle.

# Empty / malformed body to surface the framework + handler (detection clue harvesting):
curl -s -X POST 'https://TARGET/saml/sso' \
  -H 'Content-Type: application/x-www-form-urlencoded' -d ''
```

### Detection clues (you have a signing-oracle candidate when you see)
- An **ASP.NET stack trace naming `GenerateSAMLResponse`** (or `SPSingleSignOn`) — the signer ran and threw
  before auth, so the signing routine is reachable unauthenticated.
- The returned assertion has **no `InResponseTo` attribute** → it is **IdP-initiated** / unsolicited, so the
  SP has **no session binding** to a request it issued — it will accept a free-standing signed assertion.
- `Status: Success` reflected from attacker-supplied input into the signed document.
- A `SAMLResponse` returned on a GET/POST that required no login.

## 2. Forge → submit to ACS
With a signed assertion in hand (or a reflected signer you control the subject of), set the subject to a
TEST identity you own and POST it to the ACS endpoint:

```bash
# Locate the ACS (consumes the assertion and establishes the SP session):
#   paths like /saml/acs , /_hcms/mem/saml/acs , /sso/acs , /Shibboleth.sso/SAML2/POST
curl -s -i -X POST 'https://TARGET/saml/acs' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=<base64 of the signed assertion, subject = TEST identity>" \
  --data-urlencode "RelayState=/"
# A session cookie / 302 to an authenticated area => the ACS accepted the forged assertion.
```

ACS acceptance tests (what makes the oracle exploitable):
- **No `InResponseTo` validation** → unsolicited assertions accepted (IdP-initiated allowed).
- **Assertion replay** → the same signed assertion accepted twice (no one-time `ID`/`NotOnOrAfter` tracking).
- **Audience/recipient not checked** → an assertion minted for another SP/endpoint is accepted here.
- **Subject-confirmation / `NotOnOrAfter` not enforced** → stale or mis-addressed assertions pass.

Benign proof: log into a **TEST** account's state via a self-minted assertion naming that TEST subject, read a
TEST-only resource to confirm the session is real, then stop and log out. Never forge a real user's `NameID`.

## 3. RelayState as an open-redirect carrier
`RelayState` is the SP's "return to this URL after SSO" field and is frequently echoed into a redirect without
allowlisting. After (or independent of) a SAML login, it can bounce the browser to an attacker URL:

```bash
curl -s -i -X POST 'https://TARGET/saml/acs' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=<valid TEST assertion>" \
  --data-urlencode "RelayState=https://ATTACKER.example/"
# A 302 Location: https://ATTACKER.example/ => RelayState is an unvalidated redirect.
```

- Impact-chain: an open redirect on the post-login hop can be used to relay/steal the just-established session
  context, or to phish within the trusted SSO domain. Confirm the external bounce, then **hand the
  open-redirect leg to the `open-redirect` skill** and de-dupe.

## Hand-back
A signing-oracle / forged-assertion acceptance that reaches a TEST authenticated state is an **auth-bypass**
finding (server-granted access without valid auth) — rate it, capture the request/response pair, and route the
RelayState redirect to `open-redirect`. XML-signature-wrapping and XXE-on-the-SAML-parser are distinct classes;
note the surface and defer. All proofs use accounts/subjects you own, benign, approval-gated, cleaned up.
