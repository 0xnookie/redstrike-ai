# Credential Access Agent

> ATOMIC agent (post-ex / MITRE TA0006) — authorized credential testing: online guessing, offline hash
> cracking, and credential-store review on a landed host. Confirms weak/recoverable credentials.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** scope the credential surface → online guessing (rate-limited, lockout-aware) → collect hashes from an authorized host/store → crack OFFLINE → confirm a recovered/weak credential BENIGNLY → redact → rate → emit → review → verify.
- **TOOLS:** `hydra`/`medusa` (online), `hashcat`/`john` (offline), `name-that-hash`, host credential-store tooling; `refs/credential_access.md`.
- **GOAL:** Confirm that a credential is weak or recoverable — a guessable account, a crackable hash, or a readable secret store — demonstrated on a TEST credential, with all real secrets REDACTED. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `cred_enum.json`, `cred_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = an authorized host/service + any collected hashes + `scope.yaml`. `refs/` = `credential_access.md`. Chains FROM `linux-privesc`/`windows-privesc`/`ad-*`; chains TO `ad-lateral-movement` + `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a weak/recoverable credential benignly, secrets redacted. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The credential surface (a login service, a recovered hash set, a credential store on a landed host)
- The weakness: a guessable/sprayable account, a crackable hash, or an over-readable secret store
- A BENIGN proof: ONE weak/test credential recovered (cracked offline / guessed within policy) — with the secret stored only as a redacted fingerprint

## Steps  (action · tool · output)
1. Scope the surface (service, hash set, store) + confirm lockout/rate policy · recon · `cred_enum.json`
2. Online guessing — rate-limited, lockout-aware, few attempts, policy-first · `hydra`/`medusa` · `cred_tests.jsonl`
3. Collect hashes from the authorized host/store (redact as collected) · host tooling · `cred_tests.jsonl`
4. Crack OFFLINE (wordlist → rules → mask) · `hashcat`/`john` · `cred_tests.jsonl`
5. Confirm ONE recovered/weak credential benignly (auth with it once, or match a test account) · synth · `poc/<id>/`
6. Record + remove any collected hash files; REDACT secrets to fingerprints · synth · `cleanup.md`
7. Rate (CVSS) + write finding (redacted) · synth · `findings.json`
8. Emit report · synth · `report.md` · 9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- `hydra`/`medusa`, `hashcat`/`john`, `name-that-hash`, host credential-store tooling; `refs/credential_access.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- authorized host/service, collected hashes, `scope.yaml`

## Outputs
`cred_enum.json` · `cred_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** surface + online guessing (policy-aware).
- **Phase 2 (target-specific):** offline cracking + benign confirmation + redaction + rating (approval-gated).

## Safety
Post-ex, **approval-gated**. Crack **offline** only; online guessing is rate-limited + lockout-aware (never
lock out real users). Benign proof = ONE weak/test credential; **REDACT** every real secret to a fingerprint
(never store a plaintext password/hash/key in artifacts). Collected hash files are deleted (`cleanup.md`).
No reuse of recovered real credentials beyond the single proof without further approval. In-scope only; audit-log.
