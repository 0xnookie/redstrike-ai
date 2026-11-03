# Forbidden / 403 Bypass Agent

> Single (atomic) web category — sibling of `exposed-surface`. **Baseline**: runs whenever recon
> surfaces a 401/403-restricted endpoint. Consumes `content-discovery` status inventory + `host-discovery`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** collect 401/403-restricted endpoints (content-discovery + crawl) → baseline each (confirm it really denies) → replay with path / method / header / protocol manipulations → confirm the REAL restricted content/behaviour was reached (body signature, not a bare 200) → rate → emit → review → verify.
- **TOOLS:** scriptable HTTP client (raw path, arbitrary method/headers, no client-side normalization), `refs/bypass_techniques.md`.
- **GOAL:** Confirm a server-enforced access restriction (a 401/403) was bypassed — reaching the real protected content/behaviour via request manipulation — read-only + benign. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `restricted_endpoints.jsonl`, `bypass_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `content-discovery/` (endpoints + status codes) + `host_discovery.json` + `scope.yaml`. `refs/` = `refs/bypass_techniques.md`. Chains FROM `content-discovery` / `host-discovery`; chains TO `reporting` (a reached admin/debug/actuator panel → `exposed-surface` / `privesc` for downstream impact).
- **DECOMPOSITION:** atomic single agent — one confirmation method (restricted → manipulated request → real access).

## Goal
Prove a server-enforced 401/403 access restriction was bypassed via request manipulation (path/method/header/protocol), reaching the REAL restricted resource — not a soft-404, not a different public resource, not a bare status flip. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Collect restricted endpoints (baseline 401/403) from content-discovery + crawl · `jq` + HTTP client · `restricted_endpoints.jsonl`
2. Baseline each: confirm it genuinely denies (status + body length/hash); where possible capture a success oracle from a known-200 sibling so a "granted" response is distinguishable from a soft-404 · HTTP client · `restricted_endpoints.jsonl`
3. Replay with manipulations, one axis at a time then combined — path/URL (trailing slash/dot, dot-segment, `..;/`, encoding, case, matrix/`;` params), HTTP method + method-override headers, trust/forwarding headers (XFF, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*`, `Referer`), protocol/version · HTTP client + `refs/bypass_techniques.md` · `bypass_tests.jsonl`
4. Confirm access: the manipulated request returned the REAL restricted content/behaviour (body-signature match vs. the oracle, not a status-only flip, not a soft-404/redirect-to-login) · HTTP client · `bypass_tests.jsonl`
5. Capture PoC — baseline-denied vs. bypass-granted, side by side (request + response headers + body marker) · HTTP client · `poc/<id>/`
6. Rate (CVSS) by what the reached resource grants + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md`  · 9. /VERIFY · `verify.md`

## Tools
- Scriptable HTTP client that sends the **raw** request line (no path normalization), arbitrary methods, and arbitrary headers; interceptor for manual confirmation. `refs/bypass_techniques.md`.
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `content-discovery/` (discovered endpoints + status codes), `host_discovery.json`, `scope.yaml`

## Outputs
`restricted_endpoints.jsonl` · `bypass_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** collect restricted endpoints + baseline; single-axis manipulations (path / method / header).
- **Phase 2 (target-specific):** combined manipulations + edge/proxy trust-header chains + rating (approval-gated).

## Safety
Read-only confirmation — **reach** the resource, do not exfiltrate or dump it. The HTTP client must NOT
normalize the path (that is the mechanism under test). Trust/forwarding-header values are benign (loopback,
e.g. `127.0.0.1`). No brute-force. Scope-gate + audit-log. **De-dupe:** vs `exposed-surface` (resource was
already openly `200`, never restricted) and vs `auth-bypass` (defeated an application login/session/2FA, not
an edge/proxy ACL on a path). This agent owns the "it returned 401/403 and we reached it anyway" case.
