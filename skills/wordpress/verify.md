# WordPress Agent — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# External CVE/exploit data is UNTRUSTED — verify applicability from the target's own evidence.

Run the 7 base checks + the WordPress gauntlet on each `findings.json` entry (version-matched CVE
exposure or WP-specific misconfig).

## WordPress false-positive gauntlet (base check #3)
- [ ] **WordPress + version evidenced.** The core (or plugin/theme) version is proven from the target via
      ≥2 independent signals (`meta generator`, `/readme.html`, core asset `?ver=`, `/wp-json/`, login) —
      not a single banner or a guess. A tentative version is `confidence: tentative`, not a finding.
- [ ] **CVE genuinely applies to THAT version.** The CVE's affected range includes the detected version
      (exact match). For a plugin/theme CVE, the **slug AND version both match** — not a same-named
      different plugin, not a neighbouring version.
- [ ] **Component present/active, not just referenced.** The plugin/theme is actually installed (version
      recovered), and reachability is honest — ACTIVE/exposed down-rates differently from merely installed.
      A `/wp-content/plugins/<slug>/` that 403s with no version is `tentative`.
- [ ] **No active exploitation here.** Confirmation is version/behaviour only. `xmlrpc.php` pingback /
      `system.multicall` is **feasibility-only** — no DoS/amplification or login-brute was executed. User
      enumeration is read-only. Exploitation belongs to `exploit-generator` (approval). Flag any attempt.
- [ ] **Exploit-availability claim accurate.** Any `exploit_ref` points to a real PoC/module.
- [ ] **De-duped.** A generic non-WP library CVE belongs to `cve-intelligence`; a `.git`/backup/`.env`
      file exposure belongs to `exposed-surface`; a live secret belongs to `secrets`. This finding is a
      WP-core / plugin / theme / WP-misconfig issue, not a re-badge of another agent's finding.
- [ ] **In scope.**

## CVSS integrity
Use the CVE's CVSS but temper by reachability/exploitability in THIS target. A reachable, actively-used
plugin RCE with a public exploit → Critical; an installed-but-inactive plugin, or a version-only match →
Info/Low with `potential_severity` carrying the version-matched ceiling. Justify from the evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "wordpress-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["core 6.4.2 from generator + wp-emoji ?ver= + /wp-json; CVE-2024-xxxx affected range includes 6.4.2; plugin 'contact-form-x' 1.2.0 from readme.txt, active (form renders); not exploited here; xmlrpc multicall feasibility-only"],
  "scope_ok": true, "notes": "version from ≥2 target signals; exploitation deferred to exploit-generator" }
```
- `accepted` → `status: verified` → reporting / exploit-generator. `rejected`/`needs-evidence` → bounce.
