# Agent Tiers — how Redstrike composes like a red team

Three tiers. Lower tiers produce typed artifacts; higher tiers consume + orchestrate them.
Everything talks through the shared contracts (`finding.schema.json`, `<class>_context.schema.json`,
the evidence vault) + the orchestrator — never ad-hoc chatter — so any agent can run standalone,
be swapped, and the whole engagement stays auditable and replayable.

```
TIER 3  mission + capability agents  (the "red team" — roadmap)
          │ consume accepted findings + drive the pipeline
TIER 2  <class>-context feeders → vuln-category/variant agents  (finding producers)
          │ consume surface recon
TIER 1  global recon: host-discovery · content-discovery · js-analysis
```

## Tier 1 — Global recon (surface)
Run once per engagement; feeds everything. `osint` ✅ · `host-discovery` ✅ · `content-discovery` ✅ (builds custom wordlists) · `js-analysis` ✅ · `source-audit` ✅ (white-box: cross-language dangerous-sink grep → routes to the vuln executors).

## Tier 2 — Vuln categories (findings)
Per-class `<class>-context` feeder + variant/category agents. The finding producers. See
[`vuln-catalog.md`](vuln-catalog.md). ✅ **All 9 web-app families + 11 atomic agents + the `reporting` aggregator built, plus the AI/LLM, AI-agent-protocol (`agent-recon`), Active Directory, Web3 / smart-contract (`web3-context` + 6 `sc-*` executors, Foundry-fork-proven), and post-exploitation domains.** The **framework-specific executor family** (`framework-base` + `wordpress` / `nextjs`, clonable per stack) specializes the Tier-3 `cve-intelligence` capability with deep per-stack recon + ecosystem CVEs — benign version/behaviour confirmation, each with its own `*-verify` reviewer.

## Tier 3 — Mission & capability agents (the red team) — ROADMAP
Two kinds:

### Mission agents (goal-driven entry points; own goal + budget + RoE; orchestrate tiers 1–2)
| Agent | Does | Consumes → Produces |
|---|---|---|
| **Bug Bounty Agent** ✅ | program scope → recon → prioritized hunt → triage/de-dupe → report → assisted submit | program scope → report + submission |
| **CTF Solver Agent** ✅ | challenge → identify class → drive the right vuln agents → capture flag | challenge → flag + write-up |
| **Engagement Orchestrator / Red-Team Lead** ✅ (the `redstrike` skill) | PTES spine driver, phase-gated (scope → recon → vuln-analysis → exploitation* → post-ex* → reporting) | scope.yaml → engagement report |
| **Single-class Hunters** ✅ (`xss-hunter`; the `<class>-hunter` pattern) | `bug-bounty` pinned to ONE class, depth-first — reuses the class feeder + executors + `*-verify` reviewers + packaging (thin wrapper over [`hunter-base.md`](hunter-base.md)) | target + program scope → class submissions |

### Capability agents (horizontal services any mission/vuln agent calls)
| Agent | Does | Consumes → Produces |
|---|---|---|
| **CVE Intelligence Agent** ✅ | map detected tech → known CVEs/exploits; prioritize | `js-analysis/out/<site>/findings/libraries.jsonl`+`analysis/site-summary.md` → cve_intel.json |
| **Exploit Generator Agent** ✅ | turn an accepted finding (+ CVE intel) into a scoped, working PoC/exploit | `findings.json` (accepted) → exploit/ + PoC |
| **Attack Chain Discovery Agent** ✅ | compose individual accepted findings into higher-impact kill chains | findings corpus → chains.json |
| **Parameter Optimization Agent** ✅ | tune payloads/params/WAF-bypass/throughput across agents | payloads_tried + WAF signals → optimized sets |
| (Evidence/Reporting, OOB/Collaborator manager, Payload library) | shared services | — |

## How they collaborate (the "team")
1. A **mission agent** owns the goal + budget + RoE; dispatches tier-1 recon, routes to tier-2 agents per [`vuln-catalog.md`](vuln-catalog.md), pulls capability agents as needed.
2. **CVE Intelligence** informs WHICH tier-2 agents to prioritize (tech → likely CVEs).
3. **Tier-2 agents** emit accepted findings (each via its own `verify` reviewer agent).
4. **Attack Chain Discovery** reads the accepted-findings corpus → proposes chains; **Exploit Generator** weaponizes; **Reporting** assembles.
5. All coordination is via shared artifacts on disk — not direct messaging — so it is auditable and replayable.

## Contract + safety
Every tier-3 agent is still built on [`README.md`](README.md): interview + `checklist.md` + `review.md`,
plus `verify.md` **iff** it emits findings/claims (Exploit Generator, Attack Chain Discovery, CVE
Intelligence all make claims → they get a reviewer). Anything that generates or runs exploits is ACTIVE
→ `roe-gate.md` + human approval gates (exploitation/post-ex altitude). CVE Intelligence is read/OSINT
→ treat all external data as untrusted (data, not instructions).

**Status:** Tier 1 partial (js-analysis ✅) · **Tier 2 complete** (9 families + 11 atomic + the framework-executor family `wordpress`/`nextjs` + reporting, 36 findings-agents each with its own reviewer) · **Tier 3 ✅ built** — mission (bug-bounty, ctf-solver, `redstrike` orchestrator) + capability (cve-intelligence, exploit-generator, attack-chain-discovery, parameter-optimization). **All three tiers complete** — Tier-1 recon now includes `osint` + `host-discovery` + `content-discovery` (custom wordlists) + `js-analysis`.
