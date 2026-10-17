---
name: redstrike-web3-context
description: Run the Redstrike web3-context feeder — map an on-chain target (contracts, verified source, proxy/upgrade pattern, token standards, deps, prior audits, privileged + value-moving surface, oracles) and a pre-dive worth-it score into web3_context.json for the smart-contract executors. Recon feeder (review.md only). Read-only, no transactions.
---

Run the Redstrike **web3-context** feeder (canonical spec: `skills/web3-context/`). TIER-2 (Web3).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Authorized contracts/chains ONLY (hard stop on out-of-scope). **Read-only** — fetch source, static-analysis inventory, read-only on-chain calls (`cast call`, storage reads); **no transactions, no state change**. Redact RPC/explorer API keys.
2. **Execute:** follow `skills/web3-context/SKILL.md`; consume `scope.yaml` (addresses/chains/protocol) + any provided source repo; work `skills/web3-context/checklist.md`; use `skills/web3-context/refs/web3_recon.md`. Write outputs to `<engagement>/web3-context/` — key artifact `web3_context.json` (validate against `skills/_contract/web3_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/web3-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/web3-context --out <engagement>/web3-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `web3_context.json` feeds `redstrike-sc-access-control | sc-upgradeability | sc-accounting | sc-oracle-mev | sc-reentrancy | sc-signature`. Dependency versions → `cve-intelligence`.
