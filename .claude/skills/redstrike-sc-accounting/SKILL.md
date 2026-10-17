---
name: redstrike-sc-accounting
description: Run the Redstrike sc-accounting hunt (executor) — smart-contract accounting / economic-invariant flaws (accounting desync on an early-return, incomplete reverse paths, off-by-one boundaries, ERC-4626 share math) where a real intended invariant breaks so value can be stolen/minted or the protocol drifts, proven on a local fork — then gate and hand off to the sc-accounting-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-accounting** methodology (canonical spec: `skills/sc-accounting/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK ONLY** (`forge test --fork-url` / `anvil --fork-url`) — **never a live mainnet transaction, never move real funds**; high-impact → approval-gated; redact RPC/explorer keys.
2. **Execute:** follow `skills/sc-accounting/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`attack_surface.value_flows`, `contracts[].standards` incl. erc4626, `contracts`, source) + `scope.yaml`; work `skills/sc-accounting/checklist.md`; use `skills/sc-accounting/refs/accounting.md`. Write outputs to `<engagement>/sc-accounting/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-accounting/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-accounting --out <engagement>/sc-accounting` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-accounting-verify` subagent on `<engagement>/sc-accounting`. Only `accepted` findings go to reporting.
