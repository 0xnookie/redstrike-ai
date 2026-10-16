---
name: redstrike-supply-chain
description: Run the Redstrike software supply-chain hunt (executor, OWASP A06) — dependency confusion, typosquatting, malicious install hooks, CI/CD pipeline + artifact poisoning, and lockfile/integrity-hash bypass, confirmed benignly with a lab resolver preference or an OOB callback from a TEST package's install hook — then gate and hand off to the supply-chain-verify reviewer agent. Approval-gated.
---

Run the Redstrike **supply-chain** methodology (canonical spec: `skills/supply-chain/`). OWASP A06.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (staging packages / install hooks); in-scope namespaces/registries only; BENIGN proof only — a resolver-preference demo in a LAB/private index, or a harmless OOB callback from a TEST package's install hook. Never publish a usable internal name on a public index, ship a real payload, or poison a production pipeline; unpublish/revert everything staged.
2. **Execute:** follow `skills/supply-chain/SKILL.md`; consume dependency manifests/lockfiles + registry/CI config (from recon / given); work `skills/supply-chain/checklist.md`; use `skills/supply-chain/refs/`. Write outputs to `<engagement>/supply-chain/`.
3. **Coverage:** copy your filled checklist into `<engagement>/supply-chain/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/supply-chain --out <engagement>/supply-chain` → fix + re-run until exit 0.
5. **Reviewer:** launch the `supply-chain-verify` subagent on `<engagement>/supply-chain`. Only `accepted` findings go to reporting.
