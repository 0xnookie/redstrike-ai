# Supply-Chain Attack Agent  (OWASP A06)

> ATOMIC agent — software supply-chain compromise (dependency confusion, typosquatting, malicious install hooks, CI/CD pipeline + artifact poisoning, lockfile/integrity-hash bypass).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (stages packages / install hooks). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** map the dependency surface (manifests, lockfiles, internal package names, registry config, CI pipeline) → classify the reachable sink (confusion / typosquat / install hook / pipeline poisoning / lockfile-hash bypass) → stage a TEST package/namespace you control → confirm benignly (resolver prefers the attacker name/version in a lab, OR a DNS/HTTP callback from a test install hook) → cleanup → rate → emit → review → verify.
- **TOOLS:** `pip`/`npm`/`gem` + registry query APIs, SBOM/dep scanners (`syft`/`grype`, OWASP Dependency-Check), an OOB collaborator, `refs/supply_chain_attacks.md`.
- **GOAL:** Confirm a supply-chain exposure — an internal package name resolvable from a public index, a typosquat, an install-hook/pipeline code-exec sink, or a lockfile/hash bypass — with a BENIGN proof (resolver preference in a lab, or a harmless OOB callback from a TEST package's hook). Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `supply_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = dependency manifests/lockfiles + registry/CI config (from recon / given) + `scope.yaml` (`oob.collaborator`, in-scope namespaces/registries). `refs/` = `supply_chain_attacks.md`. Chains FROM `js-analysis` / `content-discovery` (exposed manifests); chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic; multi-ecosystem in refs).

## Goal
Prove a software supply-chain exposure benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The ecosystem + the reachable sink (resolvable internal name, typosquat, install hook, poisonable CI step, lockfile/hash gap)
- The resolution/execution path an attacker package would take (public-vs-private index precedence, hook trigger, pipeline trust)
- A BENIGN proof: the resolver prefers the attacker-named/higher-version TEST package in a lab, OR a harmless DNS/HTTP OOB callback fires from a TEST package's install hook — NO real payload, NO usable internal name published to a public index

## Steps  (action · tool · output)
1. Map the dependency surface (manifests, lockfiles, internal names, `.npmrc`/`pip.conf`, CI config) · recon + refs · (into tests)
2. Classify the sink (dependency confusion / typosquat / install hook / pipeline poisoning / lockfile-hash bypass) · refs · `supply_tests.jsonl`
3. Stage a TEST package/namespace YOU control (benign marker hook; private lab index where needed) · `pip`/`npm`/`gem` · `supply_tests.jsonl`
4. Confirm benignly (resolver prefers the attacker name/version in a lab, OR OOB callback from the test hook) + record cleanup · OOB + CLI · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md` · 7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `pip`/`npm`/`gem` + registry query APIs, `syft`/`grype`, OWASP Dependency-Check, an OOB collaborator (DNS/HTTP), `refs/supply_chain_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- dependency manifests/lockfiles + registry/CI config, in-scope namespaces/registries, `scope.yaml` (`oob.collaborator`)

## Outputs
`supply_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** map the dependency surface + classify the sink.
- **Phase 2 (target-specific):** stage a TEST package + benign proof + cleanup + rating (approval-gated).

## Safety
Approval-gated. BENIGN proof only — a resolver-preference demo in a LAB/private index, or a harmless OOB
callback from a TEST package's install hook. **Never** publish a usable attacker package under a real internal
name on a public index, ship a real payload, or poison a production pipeline/artifact. Use tester-owned
names; **unpublish/revert** anything staged (cleanup). In-scope namespaces/registries only; audit-log.
