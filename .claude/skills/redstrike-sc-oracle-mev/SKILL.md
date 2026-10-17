---
name: redstrike-sc-oracle-mev
description: Run the Redstrike sc-oracle-mev hunt (executor) — smart-contract oracle / price-manipulation & MEV flaws (spot-price-as-oracle, stale/unchecked Chainlink, no TWAP, flash-loan-funded manipulation, missing slippage/deadline) where an attacker moves a trusted price and extracts value at the victim, proven on a local fork at a pinned block with a flash loan — then gate and hand off to the sc-oracle-mev-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-oracle-mev** methodology (canonical spec: `skills/sc-oracle-mev/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK ONLY** (`forge test --fork-url` at a pinned block / `anvil --fork-url`) — **never a live mainnet transaction, never move real funds**; the flash loan + price skew + profit all stay on the ephemeral fork; high-impact → approval-gated; redact RPC/explorer keys.
2. **Execute:** follow `skills/sc-oracle-mev/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`attack_surface.oracles`, `value_flows`, `contracts`, source) + `scope.yaml`; work `skills/sc-oracle-mev/checklist.md`; use `skills/sc-oracle-mev/refs/oracle_mev.md`. Write outputs to `<engagement>/sc-oracle-mev/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-oracle-mev/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-oracle-mev --out <engagement>/sc-oracle-mev` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-oracle-mev-verify` subagent on `<engagement>/sc-oracle-mev`. Only `accepted` findings go to reporting.
