# AD Initial Access Agent

> ATOMIC agent — go from NO credentials to a FIRST valid domain credential on an internal network.
> Precedes `ad-context` (which needs a foothold). ACTIVE, HIGH-RISK, findings-producing → imports
> `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** map the broadcast/auth surface → passive name-resolution poisoning (capture a NetNTLMv2) → authentication coercion → policy-first password spraying → anonymous enumeration → crack/confirm ONE valid credential OFFLINE/benignly → cleanup → rate → emit → review → verify.
- **TOOLS:** responder-class name-resolution capture, `mitm6` (IPv6), coercion utilities, `nxc`/`kerbrute` (spray), `hashcat` (offline); `refs/ad_initial_access.md`.
- **GOAL:** Confirm a path from unauthenticated to a first valid domain credential — a captured+cracked NetNTLMv2, or a sprayed/guessed valid account found within policy. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `iaccess_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = an in-scope internal network position + `scope.yaml`. `refs/` = `ad_initial_access.md`. Chains TO `ad-context` (hands off the first credential) + `credential-access` (offline crack) + `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove unauth → first domain credential, benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The exposure that yields a credential (poisonable name resolution, coercible auth, sprayable weak password, anonymous enumeration)
- A BENIGN proof: a captured NetNTLMv2 cracked OFFLINE to a test/weak account, OR a spray that finds ONE valid credential without locking accounts

## Steps  (action · tool · output)
1. Map the surface (LLMNR/NBT-NS/mDNS on, IPv6 DHCPv6, SMB signing, lockout policy) · recon · `iaccess_tests.jsonl`
2. Passive name-resolution poisoning → capture a NetNTLMv2 hash (redact) · responder-class · `iaccess_tests.jsonl`
3. Authentication coercion toward a listener (where in scope) · coercion utils · `iaccess_tests.jsonl`
4. Policy-FIRST password spraying (read `--pass-pol`; one password across users, spaced) · `nxc`/`kerbrute` · `iaccess_tests.jsonl`
5. Anonymous enumeration (null/anonymous SMB/LDAP, user lists) · `nxc`/`rpcclient` · `iaccess_tests.jsonl`
6. Crack the captured hash OFFLINE or confirm the sprayed credential benignly · `hashcat` · `poc/<id>/`
7. Stop poisoning; record + remove anything created; redact secrets · synth · `cleanup.md`
8. Rate (CVSS) + write finding (redacted) · synth · `findings.json`
9. Emit report · synth · `report.md` · 10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- responder-class capture, `mitm6`, coercion utilities, `nxc`/`kerbrute`, `hashcat` (offline); `refs/ad_initial_access.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- in-scope internal network position, `scope.yaml`

## Outputs
`iaccess_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** surface mapping + passive capture.
- **Phase 2 (target-specific):** coercion / policy-first spray + offline crack + cleanup + rating (approval-gated).

## Safety
Post-ex / internal, **approval-gated**. Prefer PASSIVE capture; poisoning responds only to broadcast queries —
keep it time-boxed and stop promptly (`cleanup.md`). Spraying is policy-first + lockout-aware (one password,
spaced — never lock accounts). Crack **offline**; **redact** captured hashes/credentials to fingerprints.
Coercion only toward an in-scope listener, non-disruptive. In-scope network only; audit-log. Hand the first
credential to `ad-context`.
