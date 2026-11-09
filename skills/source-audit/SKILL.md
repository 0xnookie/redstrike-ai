# Source Audit (white-box feeder)

> RECON / white-box feeder. Given AUTHORIZED source access, greps the codebase for dangerous-sink patterns
> across languages + runs `semgrep`, and emits a ROUTED candidate map (file:line → likely vuln class →
> executor) that feeds the vuln executors; also surfaces secret + dependency candidates. STATIC + read-only
> (never executes the code) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `source_context.json` (schema `_contract/source_context.schema.json`). The orchestrator runs this
> ONLY when `scope.yaml` grants authorized source access; a pure black-box run skips it.

## Interview
- **STEPS:** ingest source (provided repo / fetched / `js-analysis` beautified) → detect languages + LOC → per-language dangerous-pattern grep → **taint-reachability pass** (`semgrep mode:taint`, `refs/taint/` — marks each sink source→sink reachable vs present-but-unproven) → `semgrep --config auto` net → secret + dependency surface → map each candidate to a vuln class + carry its reachability → **structural extract** (`refs/chains/structural.yaml` — routes/auth-guards/id-reads/mass-assign/writable paths) → **chain + logic reasoning** (compose taint candidates + structural facts into candidate chains per `refs/chains/patterns.yaml`, confirm the absences semgrep can't, route as an executor SEQUENCE) → route to the executor(s) that can PROVE it → emit → review.
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
- **Routing** — executor hints so the right agents fan out

## Steps  (action · tool · output)
1. Ingest + detect languages + LOC · `rg --files` + ext map · (seed)
2. Per-language dangerous-pattern grep (sinks per `refs`) · `rg` + `refs/source_audit.md` · `source_findings.jsonl`
3a. Taint-reachability pass — mark each sink source→sink reachable · `semgrep --config refs/taint/` · `logs/semgrep-taint.json`
3b. Supplementary net (language + security) · `semgrep --config auto` · `source_findings.jsonl`
4. Secret candidates (redact values) + dependency manifests · `trufflehog` + `jq` · `source_findings.jsonl`
5. Map each candidate → vuln class → executor; carry `taint.reachable`; dedupe · synth · (into context)
6. Structural extract (routes/guards/id-reads/mass-assign/writable paths) · `semgrep --config refs/chains/structural.yaml` · `structural[]`
7. Chain + logic reasoning — compose candidates+facts into candidate chains per `refs/chains/patterns.yaml`; confirm authz absences; route as executor SEQUENCE · synth · `chain_candidates[]`
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
