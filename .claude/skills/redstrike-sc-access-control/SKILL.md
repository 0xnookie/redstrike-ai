---
name: redstrike-sc-access-control
description: Run the Redstrike sc-access-control hunt (executor) — smart-contract authorization flaws (missing/incorrect modifiers, sibling-function omission, tx.origin, role/visibility) where an unauthorized caller performs a privileged/value-moving action, proven on a local fork — then gate and hand off to the sc-access-control-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-access-control** methodology (canonical spec: `skills/sc-access-control/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK ONLY** (`forge test --fork-url` / `anvil --fork-url`) — **never a live mainnet transaction, never move real funds**; high-impact → approval-gated; redact RPC/explorer keys.
2. **Execute:** follow `skills/sc-access-control/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`privileged_functions`, `contracts`, source) + `scope.yaml`; work `skills/sc-access-control/checklist.md`; use `skills/sc-access-control/refs/access_control.md`. Write outputs to `<engagement>/sc-access-control/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-access-control/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-access-control --out <engagement>/sc-access-control` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-access-control-verify` subagent on `<engagement>/sc-access-control`. Only `accepted` findings go to reporting.
