# Supply-Chain Attack — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the supply-chain gauntlet. Confirmed = a real resolution/execution exposure proven
benignly (resolver preference in a lab, or an attributable OOB callback from a TEST package's install hook).
Re-run the benign proof.

## Supply-chain false-positive gauntlet (base check #3)
- [ ] **The exposure is real, not theoretical.** Either the resolver demonstrably pulled/preferred the
      attacker-named/higher-version TEST package (show the install/resolve log) OR a TEST package's install
      hook fired an attributable OOB callback — not merely "this internal name looks unclaimed".
- [ ] **The path is concrete.** The ecosystem, the precedence rule (public-vs-private index, version
      preference), or the hook/pipeline trust that executes attacker code is evidenced, not assumed.
- [ ] **Not a known-good control.** A private `index-url` that already wins, a scoped/namespaced registry, or
      pinned hashes that block the swap mean NO finding — show the control was actually bypassable.
- [ ] **Benign + reversible.** A tester-owned TEST package with a harmless marker hook only — no real
      payload, no usable internal name left published on a public index, no production pipeline touched;
      everything staged was unpublished/reverted.
- [ ] **Severity matches reach.** Code-exec on build/CI or on every installer of an internal name →
      High/Critical; a typosquat needing a user typo → Medium. In scope.

## CVSS integrity
Rate from where the attacker code would run (developer/CI build box, every consumer of the package) and how
many installs it reaches — not merely that a name was registrable. Flag inflation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "supply-chain-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["internal pkg 'acme-internal' absent from private-index precedence; lab resolver pulled tester v9.9.9 from the public index; postinstall fired a DNS callback to the oob id; benign marker only; unpublished after"],
  "scope_ok": true, "notes": "test package only; no usable name left public; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
