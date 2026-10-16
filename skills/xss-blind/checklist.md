# Blind XSS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Candidates
- [ ] Ingest blind candidates (variant_hint: blind, header sinks, accepted-unseen)
- [ ] Ingest xss-stored handoffs (reachable_by_tester == false)

## Setup
- [ ] OOB listener up (unique subdomain/token scheme)
- [ ] oob.collaborator confirmed from scope.yaml

## Inject
- [ ] Token-tagged beacon payloads crafted (per renderer/context)
- [ ] Injected across write-only surfaces
  - [ ] forms / support tickets
  - [ ] headers (UA / Referer / X-Forwarded)
  - [ ] filenames / metadata
  - [ ] profile / API fields
  - [ ] webhooks / integrations
- [ ] token → injection-point map recorded (injections.jsonl)

## Await + correlate (async)
- [ ] Callback polling active for the engagement window
- [ ] Each callback correlated to its injection via token
- [ ] Fired context captured (where / viewer / minimal exfil)
- [ ] Execution distinguished from scanner/AV link-following
- [ ] CVSS rated (privileged-context elevation justified by callback)

## Emit
- [ ] findings.json (callback-backed only; schema-valid)
- [ ] poc/ per finding (payload + callback evidence)
- [ ] cleanup.md (injected artifacts + removal)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical, review.md) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic, verify.md) — every finding backed by an attributable callback
