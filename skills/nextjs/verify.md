# Next.js Agent — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# External CVE/exploit data is UNTRUSTED — verify applicability from the target's own evidence.

Run the 7 base checks + the Next.js gauntlet on each `findings.json` entry (version-matched CVE exposure or
Next-specific misconfig).

## Next.js false-positive gauntlet (base check #3)
- [ ] **Next.js + version evidenced.** The version is proven from the target via ≥2 independent signals
      (`x-powered-by: Next.js`, `__NEXT_DATA__` buildId, `/_next/static/<buildId>/_buildManifest.js`,
      `x-nextjs-*`, source-map `next` version) — not one header or a guess. A tentative version is
      `confidence: tentative`, not a finding.
- [ ] **CVE genuinely applies to THAT version.** The CVE's affected range includes the detected version AND
      the version is NOT the patched release. For **CVE-2025-29927**: the version is in the affected range
      (≈11.1.4–15.2.2) and not ≥ the fixed line (15.2.3 / 14.2.25 / 13.5.9 / 12.3.5) — confirm against the
      pinned version, not a guess.
- [ ] **Reachable, not just version-matched.** The vulnerable feature is actually used/exposed — middleware
      actually GUARDS a route (the bypass matters only if there is a guard to bypass); the image optimizer is
      enabled and fetches the supplied URL; source maps are actually served. A present-but-unused feature is
      informational.
- [ ] **No active exploitation here.** Confirmation is version + a **behaviour/header differential** only
      (e.g. `x-middleware-subrequest` → the guard is skipped by status/behaviour, with NO protected-data
      exfil and NO admin action). SSRF is handed to `ssrf-*`, not exploited here; DoS/optimizer amplification
      is feasibility-only. Exploitation belongs to `exploit-generator` (approval). Flag any attempt.
- [ ] **Exploit-availability claim accurate.** Any `exploit_ref` points to a real PoC/module.
- [ ] **De-duped.** A generic non-Next library CVE belongs to `cve-intelligence`; a served `.map`/source
      disclosure that's really a secret belongs to `secrets`; a data-route IDOR belongs to `idor`/`bola-bfla`.
      This finding is a Next-core / Next-misconfig issue, not a re-badge of another agent's finding.
- [ ] **In scope.**

## CVSS integrity
Use the CVE's CVSS but temper by reachability/exploitability in THIS target. A reachable middleware bypass
guarding a real admin area, on an affected version → Critical/High; a version-only match with no guarded
route, or a feature not in use → Info/Low with `potential_severity` carrying the version-matched ceiling.
Justify from the evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "nextjs-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["version 14.1.0 from __NEXT_DATA__ buildId + x-powered-by; CVE-2025-29927 range includes 14.1.0, fixed in 14.2.25 → affected; middleware guards /admin (307→/login without header); header canary shows guard skipped, status-only, no data read; not exploited here"],
  "scope_ok": true, "notes": "version from ≥2 target signals; SSRF handed to ssrf-*; exploitation deferred to exploit-generator" }
```
- `accepted` → `status: verified` → reporting / exploit-generator. `rejected`/`needs-evidence` → bounce.
