# JWT Attack Agent

> Variant of the auth family (siblings: `auth-bypass`, `oauth`). Consumes `auth_context.json` where
> `session.jwt: true` / `variant_hint: jwt`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest JWT session → decode + analyze (alg, claims) → test `alg:none`, weak-secret crack, key confusion, kid/jku injection, claim tampering → confirm a forged token is ACCEPTED → rate → emit → review → verify.
- **TOOLS:** `jwt_tool`, `hashcat` (offline secret crack), interceptor; `auth-context/refs/auth_techniques.md`.
- **GOAL:** Confirm a JWT verification flaw — a tampered/forged token accepted by the server granting unauthorized access. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `jwt_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `auth_context.json` (session.jwt, alg) + `auth.env` (a real token) + `scope.yaml`. `refs/` = `auth-context/refs/`. Chains FROM `auth-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the JWT variant.

## Goal
Prove a JWT flaw (forged token accepted). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest + decode the JWT (alg, claims) · `jwt_tool`/decoder · (into tests)
2. Test `alg:none` (strip sig) · `jwt_tool -X a` · `jwt_tests.jsonl`
3. Weak HMAC secret crack (offline) → re-sign tampered claims · `hashcat`/`jwt_tool -C` · `jwt_tests.jsonl`
4. Key confusion RS256→HS256 (sign with public key as HMAC secret) · `jwt_tool -X k` · `jwt_tests.jsonl`
5. `kid`/`jku`/`x5u` injection; claim tamper (`role`/`sub`/`admin`) · refs · `jwt_tests.jsonl`
6. Confirm the forged token is ACCEPTED (authed action/data) · interceptor · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- `jwt_tool`, `hashcat` (offline), interceptor, `auth-context/refs/auth_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `auth_context.json` (session.jwt, alg), `auth.env` (a valid token), `scope.yaml`

## Outputs
`jwt_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** decode + `alg:none` + weak-secret + key-confusion.
- **Phase 2 (target-specific):** kid/jku injection + claim tampering + acceptance confirmation + rating.

## Safety
Forge tokens for a TEST account only; tamper claims to a benign privilege you're authorized to prove
(don't impersonate a real admin's data); offline cracking only (no online brute); approval-gated;
scope-gate; audit-log.
