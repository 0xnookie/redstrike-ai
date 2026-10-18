---
name: redstrike-sc-upgradeability
description: Run the Redstrike sc-upgradeability hunt (executor) — smart-contract proxy/upgrade flaws (uninitialized/re-initializable init, unprotected upgradeTo/_authorizeUpgrade, uninitialized-impl selfdestruct/brick, storage-layout collision, diamond selector clash, delegatecall) where an unauthorized caller initializes/upgrades/bricks a proxy, proven on a local fork — then gate and hand off to the sc-upgradeability-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-upgradeability** methodology (canonical spec: `skills/sc-upgradeability/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK ONLY** (`forge test --fork-url` / `anvil --fork-url`) — **never a live mainnet transaction, never move real funds**; high-impact → approval-gated; redact RPC/explorer keys.
2. **Execute:** follow `skills/sc-upgradeability/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`attack_surface.upgrade_mechanism`, `contracts[].proxy`, source) + `scope.yaml`; work `skills/sc-upgradeability/checklist.md`; use `skills/sc-upgradeability/refs/upgradeability.md`. Write outputs to `<engagement>/sc-upgradeability/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-upgradeability/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-upgradeability --out <engagement>/sc-upgradeability` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-upgradeability-verify` subagent on `<engagement>/sc-upgradeability`. Only `accepted` findings go to reporting.
