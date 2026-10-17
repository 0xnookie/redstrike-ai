# Web3 Context (shared feeder)

> RECON / context feeder for the Web3 / smart-contract family (executors: `sc-access-control`,
> `sc-upgradeability`, `sc-accounting`, `sc-oracle-mev`, `sc-reentrancy`, `sc-signature`). Maps an on-chain
> target — chains, contracts, verified source, proxy/upgrade pattern, token standards, dependencies, prior
> audits, value flows + privileged surface — and runs a pre-dive worth-it gate. STATIC analysis + read-only
> on-chain reads → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `web3_context.json` (schema `_contract/web3_context.schema.json`).

## Interview
- **STEPS:** resolve in-scope contracts + chains → fetch verified source (or flag unverified) → fingerprint token standards + compiler + dependencies → map proxy/upgrade pattern → inventory privileged functions + external calls + oracles + value flows → collect prior audits + TVL → **pre-dive worth-it score** → route (`routing`) → emit → review.
- **TOOLS:** `cast` + explorer API (read-only on-chain + source fetch), `crytic-compile`/`solc-select` (compile), `slither --print human-summary,function-summary,modifiers,inheritance` (surface inventory only), `jq`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Map the smart-contract attack surface AND decide the target is worth auditing, into `web3_context.json`, so the `sc-*` executors fan out only at worthwhile targets. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `contracts.jsonl`, `web3_context.json`, `summary.md`, `logs/` (+ optional `contracts/` fetched source).
- **DATA / RAG:** inputs = `scope.yaml` (in-scope addresses / chains / protocol), an optionally-provided source repo. `refs/` = `web3_recon.md`. Chains FROM `scope`/`osint`; chains TO `sc-access-control` | `sc-upgradeability` | `sc-accounting` | `sc-oracle-mev` | `sc-reentrancy` | `sc-signature`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared web3 context (contracts + source + standards + proxy + deps + prior audits + privileged
surface + oracles + value flows + worth-it score + routing). DONE = `checklist.md` `- [x]` · `review.md` PASS
(`web3_context.json` validates against the schema).

## What do we want
- **Contracts** — in-scope addresses per chain; is source verified (else flag — audit blind-spot)
- **Fingerprint** — token standards (ERC-20/721/1155/4626/permit), compiler version, dependency libs + versions (e.g. OpenZeppelin x.y)
- **Proxy / upgrade** — pattern (Transparent / UUPS / Beacon / Diamond / minimal-clone / none), implementation + admin
- **Privileged surface** — owner/role/admin-gated + value-moving functions; external calls; oracle sources + type; deposit/withdraw/mint/redeem/claim/bridge value flows
- **Prior audits + TVL** — who audited what version; TVL; payout cap
- **Worth-it score** — pre-dive gate so executors don't burn effort on tiny / thoroughly-audited / low-payout targets
- **Routing** — which `sc-*` executors this surface warrants

## Steps  (action · tool · output)
1. Resolve in-scope contracts + chains · `jq scope.yaml` · (seed)
2. Fetch verified source (explorer / provided repo); flag unverified · `cast`/explorer API · `contracts/`, `contracts.jsonl`
3. Fingerprint standards + compiler + deps · `slither`/`crytic-compile` · `contracts.jsonl`
4. Map proxy/upgrade pattern (impl + admin slots) · `cast storage`/`slither` · `contracts.jsonl`
5. Inventory privileged fns + external calls + oracles + value flows · `slither --print function-summary,modifiers` · `contracts.jsonl`
6. Collect prior audits + TVL + payout cap · OSINT/scope · (into context)
7. Pre-dive worth-it score (TVL / payout / audit-status / deploy-age / upgradeable) → `proceed` · synth · (into context)
8. Route (`routing`) + consolidate + validate vs schema · synth · `web3_context.json`
9. Emit summary · synth · `summary.md`
10. /REVIEW SKILL · `review.md`

## Tools
- `cast` + explorer API (read-only), `crytic-compile`/`solc-select`, `slither` (inventory prints only), `jq`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `scope.yaml` (in-scope addresses / chains / protocol), optional provided source repo
- `refs/web3_recon.md`

## Outputs
`contracts.jsonl` · `web3_context.json` · `summary.md` · `logs/` · (optional `contracts/`)

## Phases
- **Phase 1 (generic):** resolve + fetch source + fingerprint standards/compiler/deps + surface inventory.
- **Phase 2 (target-specific):** proxy mapping + value-flow + oracle mapping + worth-it scoring + routing.

## Safety
**Read-only.** Fetch source, run static-analysis inventory, and make read-only on-chain calls (`cast call`,
storage reads) — **NO transactions, NO state change, no funds moved**. Redact RPC / explorer API keys to
fingerprints. Scope to the authorized contracts/protocol in `scope.yaml` (out-of-scope chain/address = hard
stop). The worth-it gate is advisory — record `proceed:false` with a rationale rather than silently dropping a
target; audit-log.
