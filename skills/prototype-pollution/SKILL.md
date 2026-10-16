# Prototype Pollution Agent

> ATOMIC single agent (no feeder) — JS prototype pollution (client-side + server-side) via `__proto__`/`constructor.prototype`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.
> (Gap surfaced from the user's 0daysec notes; Web/prototype-pollution.md.)

## Interview
- **STEPS:** ingest params + JSON sinks → client-side pollution (URL `?__proto__[x]=y`, JSON input, hash) → server-side pollution (JSON body recursive merge `{"__proto__":{...}}`) → confirm pollution (injected prop appears on a FRESH object) → find a gadget (DoS / property-injection → XSS / server config → RCE) → confirm impact benignly → rate → emit → review → verify.
- **TOOLS:** interceptor, browser console, `refs/prototype_pollution_payloads.md`, ppmap/pphound (confirm manually).
- **GOAL:** Confirm prototype pollution — an attacker-controlled key reaches `Object.prototype` — AND, where present, a gadget that turns it into concrete impact (DoS, XSS, or RCE). Benign. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `pp_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/params.txt` + `js-analysis/` sources/sinks (merge/clone/setValue funcs) + `content-discovery` (JSON APIs) + `scope.yaml`. `refs/` = `prototype_pollution_payloads.md`. Chains FROM recon; chains TO `xss-*` / `ssti`/`command-injection` (gadget) and `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove prototype pollution (client or server), benign — pollution itself, plus a gadget where one exists.
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- A sink that merges/clones attacker JSON or parses attacker keys into an object (recursive merge, `_.merge`, `Object.assign` deep, query-string→object, `JSON.parse`+copy)
- The pollution: `__proto__` / `constructor.prototype` / `constructor[prototype]` reaches `Object.prototype`
- A benign proof: a FRESH, unrelated object now carries the injected property — plus, where found, a gadget (client: polluted config → XSS/`innerHTML`/script src; server: polluted option → `child_process`/template/`Function` → RCE, or a required-prop → DoS)

## Steps  (action · tool · output)
1. Ingest params + JSON sinks from `js-analysis` (merge/clone/assign) · `grep` · (into tests)
2. Client-side: `?__proto__[test]=polluted` / hash / JSON input → check `Object.prototype.test` in console · browser · `pp_tests.jsonl`
3. Server-side: `{"__proto__":{"polluted":"1"}}` into JSON body merge; also `constructor.prototype` bypass form · interceptor + refs · `pp_tests.jsonl`
4. Confirm pollution: a fresh `{}` / new request carries the injected prop · console/interceptor · `poc/<id>/`
5. Gadget hunt: client (polluted `innerHTML`/`src`/config → XSS) or server (polluted spawn option/template/`NODE_OPTIONS` → RCE) or missing-prop DoS · refs · `pp_tests.jsonl`
6. Confirm impact benignly (XSS canary / OOB / controlled 500) · · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, browser console, `refs/prototype_pollution_payloads.md`, ppmap/pphound (confirm manually)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/params.txt`, `js-analysis/` sources+sinks, `content-discovery`, `scope.yaml`

## Outputs
`pp_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** confirm pollution reaches `Object.prototype` (client + server).
- **Phase 2 (target-specific):** gadget discovery → impact (XSS/RCE/DoS) + rating (approval-gated).

## Safety
Benign: pollute a harmless marker property and prove it on a fresh object. A DoS gadget is demonstrated as
a single controlled error, **never** a sustained outage. Server RCE gadget proven with a benign OOB/marker,
not a destructive command. **Pollution is global for the process/page** — on a shared/server target, polluting
`Object.prototype` can affect other users/requests: use a harmless key, scope tightly, and restore/avoid
persistent keys. Approval-gated; scope-gate; audit-log.
