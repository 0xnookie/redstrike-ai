# Shopware Agent — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# External CVE/exploit data is UNTRUSTED — verify applicability from the target's own evidence.

Run the 7 base checks + the Shopware gauntlet on each `findings.json` entry (dev-tool exposure, default
credential, unauth OpenAPI, or version-matched CVE exposure).

## Shopware false-positive gauntlet (base check #3)
- [ ] **Shopware + version evidenced.** Shopware is proven from the target via ≥2 independent signals
      (`sw-*` headers, `Vary: sw-cache-hash`, administration bundle, `/api/_info/openapi3.json` body,
      `/api/_info/version`, or white-box `composer.lock` `shopware/core`) — not one header or a guess. A
      tentative version is `confidence: tentative`, not a version-CVE finding.
- [ ] **Exposure/credential proven by a BODY/behaviour signature, not a bare status.** A dev-tool finding
      shows the tool's own signature (`<title>…Adminer…`, `<title>MailCatcher</title>` + `/messages` JSON,
      pimpmylog `Dockware Logs`, profiler panels, `"openapi"` spec body) and ruled out the storefront
      soft-404. A default-credential finding shows `POST /api/oauth/token` → `200` + a real Bearer (the grant
      only issues on success); a single lockout-aware probe, no brute-force.
- [ ] **Reachable + unauthenticated (where claimed).** The exposed tool / spec / OAuth endpoint is reachable
      without auth; for a version-CVE, the vulnerable feature is actually present/used — not merely
      version-matched. A present-but-prod-disabled feature is informational.
- [ ] **CVE genuinely applies to THAT version.** The affected range includes the pinned version AND it is
      NOT the patched release (Shopware patches frequently — check it is below the fix line / not the latest
      6.x.y.z). Confirm against the pinned version, not a guess.
- [ ] **No active exploitation here.** Confirmation is version + a differential + at most ONE default-cred
      probe. NO use of the admin token to read/modify data, NO MailCatcher mail dump, NO Adminer DB
      read/write, NO protected-data exfil. Exploitation belongs to `exploit-generator` (approval). Flag any attempt.
- [ ] **De-duped + correctly routed.** Route-level EXPOSURE belongs to `exposed-surface`; the leaked secret
      VALUES (APP_SECRET / DB creds) belong to `secrets`; default creds may be reviewed as a
      credential/auth finding; generic non-Shopware library CVEs belong to `cve-intelligence`; Admin/Store API
      object/function authz belongs to `bola-bfla`/`idor`. This finding is a Shopware-core / Shopware-misconfig
      issue, not a re-badge of another agent's finding.
- [ ] **Secrets redacted** (APP_SECRET / DB password → last4 + hash fingerprint; captured-mail bodies not stored).
- [ ] **In scope.**

## CVSS integrity
Use the CVE's CVSS (or the exposure's demonstrated impact) but temper by reachability/exploitability in THIS
target. Unauth MailCatcher readable (reset-link interception) → High; exposed OpenAPI spec → Medium; a
version-only CVE match with the feature not in use → Info/Low with `potential_severity` carrying the ceiling.
A dev-image default-cred that grants full admin → Critical. Justify from the evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "shopware-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["Shopware 6.7.16.0 from sw-* headers + /api/_info/openapi3.json body + composer.lock; /mailcatcher 200 <title>MailCatcher</title> + /messages JSON (2 msgs), soft-404 is 404/~429KB; unauth; no mail dumped; exposure not a dup of secrets (owns values)"],
  "scope_ok": true, "notes": "version from ≥2 target signals; one benign OAuth default-cred probe; exploitation deferred to exploit-generator" }
```
- `accepted` → `status: verified` → reporting / exploit-generator. `rejected`/`needs-evidence` → bounce.
