---
name: redstrike-attack-chain-discovery
description: Run the Redstrike attack-chain-discovery capability — compose ACCEPTED findings into higher-impact kill chains, optionally demonstrate one benignly — then gate and hand off to the attack-chain-discovery-verify reviewer agent.
---

Run the Redstrike **attack-chain-discovery** capability (canonical spec: `skills/attack-chain-discovery/`). TIER-3.

1. **Scope + approval:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Composition is reasoning over existing ACCEPTED findings (passive). Demonstrating a chain end-to-end chains real exploits → **approval-gated**, benign, via the Tier-2 agents' own safety rules.
2. **Execute:** follow `skills/attack-chain-discovery/SKILL.md`; ingest every `<engagement>/*/findings.json` where `review.verdict == accepted`; work `skills/attack-chain-discovery/checklist.md`. Write outputs to `<engagement>/attack-chain-discovery/` — `chains.json` (validate against `skills/_contract/attack_chain.schema.json`) + `findings.json` (composite chain findings). Every step MUST reference an accepted finding.
3. **Coverage:** copy your filled checklist into `<engagement>/attack-chain-discovery/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/attack-chain-discovery --out <engagement>/attack-chain-discovery` → fix + re-run until exit 0.
5. **Reviewer:** launch the `attack-chain-discovery-verify` subagent on `<engagement>/attack-chain-discovery`. Only `accepted` chains flow to reporting.
