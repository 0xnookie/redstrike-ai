# Source Audit (white-box feeder)

> RECON / white-box feeder. Given AUTHORIZED source access, greps the codebase for dangerous-sink patterns
> across languages + runs `semgrep`, and emits a ROUTED candidate map (file:line → likely vuln class →
> executor) that feeds the vuln executors; also surfaces secret + dependency candidates. STATIC + read-only
> (never executes the code) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `source_context.json` (schema `_contract/source_context.schema.json`). The orchestrator runs this
> ONLY when `scope.yaml` grants authorized source access; a pure black-box run skips it.

## Interview
- **STEPS:** ingest source (provided repo / fetched / `js-analysis` beautified) → detect languages + LOC → per-language dangerous-pattern grep → **taint-reachability pass** (`semgrep mode:taint`, `refs/taint/` — marks each sink source→sink reachable vs present-but-unproven) → `semgrep --config auto` net → secret + dependency surface → map each candidate to a vuln class + carry its reachability → **structural extract** (`refs/chains/structural.yaml` — routes/auth-guards/id-reads/mass-assign/writable paths) → **chain + logic reasoning** (compose taint candidates + structural facts into candidate chains per `refs/chains/patterns.yaml`, confirm the absences semgrep can't, route as an executor SEQUENCE) → route to the executor(s) that can PROVE it → **calibrate lead confidence** (`sink-severity × victim_boundary`, discounted by guard-visibility; tag `guard_class` from `_contract/guard-catalog.md`) + **seed non-sink surface leads** (`source-lead`/`state-op`/`authz-route`) → emit → review.
- **TOOLS:** `rg`/grep (language patterns), `semgrep` (rulesets), `trufflehog` (secret candidates), dependency-manifest parse (`jq`); Solidity source → `web3-context`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Turn source access into a routed candidate map — WHERE the dangerous sinks are and WHICH executor should confirm each — so white-box leads get PROVEN by the executors, never asserted from a grep. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `source_findings.jsonl`, `source_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = an authorized source repo (`scope.yaml` source ref) + `js-analysis/` beautified JS + `web3-context` source. `refs/` = `source_audit.md` · `taint/` (reachability packs) · `chains/` (`structural.yaml` extractor + `patterns.yaml` catalog). Chains FROM `scope`/`js-analysis`/`web3-context`; chains TO the per-class context feeders that fan out to the executors — `injection-context` (→ ssti/command-injection/deserialization) · `sqli-context` (→ sqli-*) · `xss-context` (→ xss-*) · `file-context` (→ path-traversal-lfi/upload-rce) — plus `prototype-pollution` (direct) · `secrets` (secret candidates) · `cve-intelligence` (deps) · `web3-context` (Solidity). `chain_candidates[]` route as an executor SEQUENCE and seed `attack-chain-discovery` (pre-proof → it composes the accepted legs post-proof). Each consumer reads `source_context.json` as optional higher-confidence leads.
- **DECOMPOSITION:** n/a (white-box feeder). Black-box sink mapping → `injection-context`/`file-context`/etc.; Solidity source review → `web3-context` + the `sc-*` executors.

## Goal
Produce the routed source candidate map (dangerous sinks + secret/dep candidates → executors). DONE =
`checklist.md` `- [x]` · `review.md` PASS (`source_context.json` validates against the schema).

## What do we want
- **Languages + LOC** — what the codebase is written in (routes the pattern set)
- **Dangerous-sink candidates** — `file:line` + the matched pattern + the vuln class it implies + the executor to route it to (a grep hit is a LEAD, not a finding)
- **Reachability** — for each sink, whether attacker input provably REACHES it unsanitized (taint source→sink) in `taint.reachable`: a taint-reachable sink is high-confidence; a sink grep found but taint did NOT reach is present-but-unproven (low) — keep it as a lead and say so
- **Structural facts** — routes (read vs state-changing), auth-guards, object-id reads, mass-assignment, writable/exec paths → `structural[]` (the chain reasoner's raw material; a fact is context, not a finding)
- **Chain candidates** — composed attack chains (technical taint chains + logic/authz chains) routed as an executor SEQUENCE → `chain_candidates[]`; this is the "chain vulns or logics for real impact" output — a LEAD the hunt proves leg-by-leg, never a finding here
- **Secret candidates** — hardcoded keys/tokens (value redacted) → `secrets`
- **Dependencies** — manifest libs + versions; **prefer the LOCKFILE** (`composer.lock`/`package-lock.json`/`yarn.lock`/`Gemfile.lock`/`poetry.lock`) for EXACT pins (a banner/`Server` version is distro-backport-unreliable — the lockfile is ground truth) → `cve-intelligence` / `supply-chain`
- **Web-server & deploy config** — parse `Alias`/`ProxyPass`/`<Location>` (Apache) and `location`/`proxy_pass` (nginx), plus `.env`/framework config (`APP_ENV`, debug/profiler flags): exposed dev tools + debug mode are **route-level EXPOSURES absent from application code** (→ `exposed-surface`; secret values → `secrets`). A `dockware/*` or `*-dev` image ships them by default — enumerate them here, since no black-box brute-force reliably finds a server alias.
- **Calibrated leads** — each candidate carries `confidence` = `sink-severity × victim_boundary`, discounted by guard-visibility, with `guard_class` tagged when a framework guard dominates the class (see calibration below)
- **Non-sink surface leads** — `source-lead`/`state-op`/`authz-route` seeded so the logic/authz passes have an enumerated surface, not just the sink list (see surface seeding below)
- **Routing** — executor hints so the right agents fan out

## Confidence calibration (leads, not findings — rate them so the hunt spends effort where impact is)

Confidence here is lead QUALITY for routing, never a severity claim; the routed executor still proves or refutes each lead against the running target.
Rate it as `sink-severity × victim_boundary`, then DISCOUNT by guard-visibility.
Set `victim_boundary` on every candidate (`same-principal` / `cross-principal` / `lower-to-higher-priv` / `higher-to-lower-priv`) — it is the severity multiplier, not a footnote.
Where the dominant guard is INVISIBLE to grep/taint — a library secure-default, an ORM column allowlist, a deny-by-default field ACL, a server-side recompute, an explicit SameSite — DOWN-WEIGHT the lead by default and tag `guard_class` with the guard-catalog id (`_contract/guard-catalog.md`), so the executor confirms the guard's ESCAPE-HATCH instead of trusting a taint verdict.
Under such a guard a `taint.sanitized=false` is a FALSE-NEGATIVE (the guard is unseen by the taint engine) and must NOT raise confidence.

Caps (apply after the base rating):
- SQLi via an ORM identifier/value concat → cap `low`, tag `G-01` (the column allowlist dominates; only a raw-SQL path around the ORM re-opens it).
- XXE with no `NOENT`/`DTDLOAD` flag on a modern libxml floor → cap `low`, tag `G-02`, and do NOT trust `sanitized=false` to raise it (G-02 is invisible to taint).
- Deserialization with `taint.reachable=false` → cap `low`, note `needs-write-primitive`, severity ceiling `medium` (a gadget with no attacker-reachable source needs a separate write primitive to feed it).
- SSTI → SPLIT the lead: template-expression injection `medium`; SSTI→RCE `low` until G-13 (the template sandbox) is shown absent or defeated.
- SSRF → `medium` ONLY on the plain-vs-hardened-client asymmetry (a sibling fetch path on the plain client, tag `G-12`); a path on the hardened client is `low`/ruled-out.

Fix the XSS inversion:
Recon has historically rated XSS by sink metacharacters and so inverted confidence vs severity (self-XSS over-flagged, cross-principal under-flagged).
RAISE confidence when a lower or different principal's input renders into a LOWER-TRUST victim's context, and set `victim_boundary` to name the crossing — `higher-to-lower-priv` (staff→customer storefront), `lower-to-higher-priv` (customer→staff/admin), or `cross-principal` (tenant→tenant).
A `same-principal` self-XSS is down-weighted.
The real HIGH is the list/JSON-serialized field that SKIPS the shared sanitizer (the G-03 escape-hatch) and meets a raw sink — tag `guard_class: G-03` and rate it by its boundary, not by the sink string alone.

## Surface seeding (the sink candidate list is NOT the coverage universe)

A dangerous-sink map only covers injection-class surface; the business-logic and authorization passes need their OWN enumerated surface, or they run against nothing and read falsely clean.
So, alongside the candidates, the feeder SEEDS non-sink surface leads whose kinds match `_contract/surface_ledger.schema.json` exactly:
- `source-lead` — one per candidate (`sa-*`), so every routed sink is a tracked surface element an executor must close.
- `state-op` — derived from `structural[]` state-change routes (`state-change-route`): a state-changing operation + the invariant it must hold (single-use / limit / quota / stock / price-integrity / ownership / idempotency), for the business-logic & concurrency (TOCTOU / double-spend) pass.
- `authz-route` — derived from `structural[]` routes × their auth-guards (`auth-guard` / `unauth-route`): one route × its required-privilege cell, for the authorization-matrix pass (a state-changing/sensitive route with NO guard is the flag).
These are emitted from `structural[]` so the logic/authz passes have an enumerated surface EVEN WHEN `code-audit`'s `app_model.json` is absent — source-audit's structural map is the fallback universe.

## Steps  (action · tool · output)
1. Ingest + detect languages + LOC · `rg --files` + ext map · (seed)
2. Per-language dangerous-pattern grep (sinks per `refs`) · `rg` + `refs/source_audit.md` · `source_findings.jsonl`
3a. Taint-reachability pass — mark each sink source→sink reachable · `semgrep --config refs/taint/` · `logs/semgrep-taint.json`
3b. Supplementary net (language + security) · `semgrep --config auto` · `source_findings.jsonl`
4. Secret candidates (redact values) + dependency manifests · `trufflehog` + `jq` · `source_findings.jsonl`
5. Map each candidate → vuln class → executor; carry `taint.reachable`; set `victim_boundary` + `guard_class`; dedupe · synth · (into context)
6. Structural extract (routes/guards/id-reads/mass-assign/writable paths) · `semgrep --config refs/chains/structural.yaml` · `structural[]`
7. Chain + logic reasoning — compose candidates+facts into candidate chains per `refs/chains/patterns.yaml`; confirm authz absences; route as executor SEQUENCE · synth · `chain_candidates[]`
7b. Calibrate confidence (`sink-severity × victim_boundary`, discount by guard-visibility, apply caps) + seed non-sink surface leads (`source-lead`/`state-op`/`authz-route` from `structural[]`) · synth · (into context + surface ledger)
8. Consolidate + validate vs schema · synth · `source_context.json`
9. Emit summary · synth · `summary.md`
10. /REVIEW SKILL · `review.md`

## Tools
- `rg`/grep (language dangerous-pattern sets), `semgrep` (`refs/taint/` taint packs + `refs/chains/structural.yaml` + `--config auto`), `trufflehog` (secret candidates), `jq`
- Chain reasoning over `refs/chains/patterns.yaml` (the catalog) — synthesis, not a tool
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- authorized source repo (`scope.yaml` source ref), `js-analysis/` beautified JS, `web3-context` source
- `refs/source_audit.md` (sink grep) · `refs/taint/` (reachability packs) · `refs/chains/structural.yaml` + `refs/chains/patterns.yaml` (chain reasoner)
- `_contract/guard-catalog.md` (framework guards + escape-hatches → `guard_class` tags + guard-visibility discount) · `_contract/counterevidence.md` (don't dismiss a real candidate) · `_contract/severity-calibration.md`

## Outputs
`source_findings.jsonl` · `source_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** language detection + dangerous-pattern grep + taint-reachability pass (`refs/taint/`) + `--config auto` net.
- **Phase 2 (target-specific):** secret/dependency surface + class mapping + reachability-weighted routing + structural extract + chain/logic reasoning (candidate chains routed as executor sequences).

## Safety
**Read-only static review — NEVER execute the source.** White-box: requires authorized source access (scope).
A grep/semgrep hit — **taint-reachable included** — is a **CANDIDATE** to be confirmed by the routed executor against
the running target, not a finding on its own (no runtime proof here). Taint reachability raises lead *quality* (a
source→sink flow is far likelier real than a bare sink) but is still static: it can't see runtime guards, WAFs, or
framework auto-escaping, so `taint.reachable` is never promoted to a finding here. Redact secret **values** to fingerprints (hand the live-check to
`secrets`); hand dependency versions to `cve-intelligence`. Scope-gate; audit-log.
