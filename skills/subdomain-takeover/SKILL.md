# Subdomain Takeover Agent

> ATOMIC single agent (no feeder) — one confirmation: a dangling DNS record points to a deprovisioned
> third-party resource an attacker can claim.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` (claiming a resource needs explicit
> authorization). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate subdomains + DNS records → identify dangling pointers → fingerprint the service + check claimability → confirm (benign) → rate → emit → review → verify.
- **TOOLS:** `subfinder`/`amass` (subs), `dnsx` (resolve CNAME/A/NS), `httpx` (fingerprint), `nuclei -t http/takeovers`, `subjack`/`nuclei`; `jq`.
- **GOAL:** Confirm a subdomain takeover — a dangling CNAME/A/NS to an unclaimed third-party service that could be registered by an attacker — with benign proof, not a hostile claim (unless explicitly authorized). Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `dns_records.json`, `takeover_candidates.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = host-discovery / `js-analysis` subdomains, `scope.yaml`. `refs/` = `takeover_fingerprints.md`; also consult `cve-intelligence/refs/vendor_status.md` (§Part-1 patched-class kill-list — platforms that closed the claimable window by default; §Part-3 claim-cooldown/reserved-name windows) before rating a takeover claimable. Chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Find dangling DNS records to claimable third-party services and confirm takeover is possible, with a
benign proof. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Subdomains + their CNAME/A/NS targets
- Dangling pointers (target service returns an "unclaimed" fingerprint)
- Whether the resource is actually registrable (claimability), proven benignly

## Steps  (action · tool · output)
1. Enumerate subdomains + resolve records · `subfinder`+`dnsx` · `dns_records.json`
2. Identify dangling pointers (CNAME/A/NS to third-party with no live resource) · `dnsx`+`httpx` · `takeover_candidates.jsonl`
3. Fingerprint the service + match an unclaimed-state signature · `refs/takeover_fingerprints.md` + `nuclei -t http/takeovers` · `takeover_candidates.jsonl`
4. Confirm claimability benignly (service shows claim page / API allows registration) — first screen the match against `cve-intelligence/refs/vendor_status.md` §Part-1 (is this a patched class whose claimable window the platform closed by default?) + §Part-3 (is the released name in a provider reserve/cooldown window, i.e. not registrable yet?); a kill-list/cooldown match you can't rule out → `open-proof-gap`, not a claimable HIGH. Do NOT hostilely claim unless authorized · synth · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- **Enumerate/resolve:** `subfinder`, `amass`, `dnsx`
- **Fingerprint/confirm:** `httpx`, `nuclei -t http/takeovers`, `subjack`; `refs/takeover_fingerprints.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- subdomain list (host-discovery / `js-analysis`), `scope.yaml`, `refs/takeover_fingerprints.md`

## Outputs
`dns_records.json` · `takeover_candidates.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate subdomains + resolve + flag dangling pointers.
- **Phase 2 (target-specific):** service fingerprint + claimability confirmation + rating.

## Safety
Detecting dangling records is read-only. **Actually claiming** the resource is an active takeover —
do it ONLY with explicit written authorization (and then with a benign marker page); otherwise
document claimability with evidence and stop. Scope-gate; audit-log. If authorized to claim,
record it in the report for hand-back/remediation.
