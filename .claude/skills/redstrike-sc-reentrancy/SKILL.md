---
name: redstrike-sc-reentrancy
description: Run the Redstrike sc-reentrancy hunt (executor) — smart-contract reentrancy (classic single-function CEI violation, cross-function, cross-contract, read-only stale-view, and ERC-777/721/1155 hook-based) where an external call returns control to the attacker before a state update, letting an attacker contract re-enter and drain funds or corrupt shared state, proven on a local fork — then gate and hand off to the sc-reentrancy-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-reentrancy** methodology (canonical spec: `skills/sc-reentrancy/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK ONLY** (`forge test --fork-url` / `anvil --fork-url`) with an attacker contract — **never a live mainnet transaction, never move real funds**; high-impact → approval-gated; redact RPC/explorer keys.
2. **Execute:** follow `skills/sc-reentrancy/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`attack_surface.external_calls`, `value_flows`, `contracts`, source) + `scope.yaml`; work `skills/sc-reentrancy/checklist.md`; use `skills/sc-reentrancy/refs/reentrancy.md`. Write outputs to `<engagement>/sc-reentrancy/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-reentrancy/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-reentrancy --out <engagement>/sc-reentrancy` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-reentrancy-verify` subagent on `<engagement>/sc-reentrancy`. Only `accepted` findings go to reporting.
