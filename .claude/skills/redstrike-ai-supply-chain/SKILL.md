---
name: redstrike-ai-supply-chain
description: Run the Redstrike AI/ML supply-chain hunt (executor, OWASP LLM03) — malicious model-file RCE (pickle __reduce__ / Keras Lambda), unsafe deserialization, and model-hub confusion/typosquatting, confirmed with a benign OOB callback on load in a sandbox or a scanner-flagged opcode — then gate and hand off to the ai-supply-chain-verify reviewer agent. Approval-gated.
---

Run the Redstrike **ai-supply-chain** methodology (canonical spec: `skills/ai-supply-chain/`). OWASP LLM03.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (loading/scanning model artifacts); in-scope model sources only; BENIGN proof only — a TEST artifact's hook fires a harmless OOB marker loaded ONLY in an egress-restricted sandbox, or a static scanner flag. Never run a real payload or load an untrusted real model outside isolation.
2. **Execute:** follow `skills/ai-supply-chain/SKILL.md`; consume model artifacts + load/serving code + hub config (from `<engagement>/llm-context/llm_context.json` / recon); work `skills/ai-supply-chain/checklist.md`; use `skills/ai-supply-chain/refs/`. Write outputs to `<engagement>/ai-supply-chain/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ai-supply-chain/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ai-supply-chain --out <engagement>/ai-supply-chain` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ai-supply-chain-verify` subagent on `<engagement>/ai-supply-chain`. Only `accepted` findings go to reporting.
