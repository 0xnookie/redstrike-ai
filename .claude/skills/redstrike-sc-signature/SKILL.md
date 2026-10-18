---
name: redstrike-sc-signature
description: Run the Redstrike sc-signature hunt (executor) — smart-contract signature-verification flaws (unchecked ecrecover, malleability, replay, cross-domain, EIP-2612 permit) where a forged or replayed signature authorizes an action, proven on a local fork with vm.sign — then gate and hand off to the sc-signature-verify reviewer agent. Web3 family. Approval-gated.
---

Run the Redstrike **sc-signature** methodology (canonical spec: `skills/sc-signature/`). TIER-2 (Web3).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Authorized contracts/chains ONLY. Prove on a **LOCAL FORK / local test ONLY** (`forge test --fork-url` / `anvil --fork-url`, `vm.sign` with TEST keys) — **never a live mainnet transaction, never move real funds**; high-impact → approval-gated; redact RPC/explorer keys + any real private key.
2. **Execute:** follow `skills/sc-signature/SKILL.md`; consume `<engagement>/web3-context/web3_context.json` (`contracts[].standards` incl. erc2612-permit, `attack_surface`, source) + `scope.yaml`; work `skills/sc-signature/checklist.md`; use `skills/sc-signature/refs/signature.md`. Write outputs to `<engagement>/sc-signature/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sc-signature/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sc-signature --out <engagement>/sc-signature` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sc-signature-verify` subagent on `<engagement>/sc-signature`. Only `accepted` findings go to reporting.
